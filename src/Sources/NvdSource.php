<?php

declare(strict_types=1);

namespace Gumslone\Vulns\Sources;

use Gumslone\Vulns\Data\PackageData;
use Gumslone\Vulns\Data\VulnerabilityData;
use Gumslone\Vulns\Severity as SeverityLevel;
use Gumslone\Vulns\Contracts\CpeLookup;
use Gumslone\Vulns\Support\CpeResolver;
use Gumslone\Vulns\Support\ResolvesLookupCpe;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;

/**
 * NIST National Vulnerability Database adapter.
 * API documentation: https://nvd.nist.gov/developers/vulnerabilities
 *
 * Rate limits: 5 req/30s without key, 50 req/30s with a (free) API key.
 */
class NvdSource extends AbstractSource
{
    use ResolvesLookupCpe;


    private ?string $apiKey;

    public function __construct(private readonly CpeResolver $cpeResolver, private readonly ?CpeLookup $cpeLookup = null, ?\GuzzleHttp\Client $http = null, array $options = [], ?\Psr\Log\LoggerInterface $logger = null, ?\Psr\SimpleCache\CacheInterface $cache = null)
    {
        $this->boot($options, $logger, $cache);
        $this->apiKey = $this->config('api_key');
        // The retrying handler backs off on 429/5xx (honouring Retry-After) so
        // a slipped rate limit becomes a delay, not a silent empty result.
        $this->http = $http ?? $this->makeClient(
            rtrim((string) $this->config('base_url', 'https://services.nvd.nist.gov/rest/json'), '/').'/',
            array_filter(['apiKey' => $this->apiKey]),
            defaultRetry: 3,
        );
    }

    public function name(): string
    {
        return 'nvd';
    }

    public function queryPackage(PackageData $package): array
    {
        $cpe = $this->resolveLookupCpe($package);
        if (! $cpe) {
            return [];
        }

        $vulns = [];
        $startIndex = 0;
        // Hard safety cap: 10 pages × 2000 default page size covers any real
        // package; beyond that we log the truncation rather than loop forever.
        $maxPages = (int) $this->config('max_pages', 10);

        try {
            for ($page = 0; $page < $maxPages; $page++) {
                $this->throttle();

                // virtualMatchString matches the CPE with wildcards against configurations
                $response = $this->http->get('cves/2.0', [
                    'query' => ['virtualMatchString' => $this->matchString($cpe), 'startIndex' => $startIndex],
                ]);
                $data = json_decode($response->getBody()->getContents(), true);

                $items = $data['vulnerabilities'] ?? [];
                foreach ($items as $item) {
                    $vuln = $this->parseCve($item['cve'] ?? []);
                    if ($vuln && $this->versionIsAffected($item['cve'] ?? [], $package)) {
                        $vulns[] = $vuln;
                    }
                }

                // NVD 2.0 pages via totalResults/startIndex; an empty page
                // also ends the walk in case the server miscounts totalResults.
                $startIndex += count($items);
                if ($items === [] || $startIndex >= (int) ($data['totalResults'] ?? 0)) {
                    return $vulns;
                }
            }
        } catch (GuzzleException $e) {
            $this->log('warning', '[vulns] NVD query failed', ['package' => $package->name, 'error' => $e->getMessage()]);

            // Fail safe: an unreachable NVD must surface as an error the
            // caller records, not read as "no known vulnerabilities".
            throw new \RuntimeException("NVD query failed for {$package->name}: {$e->getMessage()}", 0, $e);
        }

        $this->log('warning', '[vulns] NVD pagination cap reached — results truncated', [
            'package' => $package->name,
            'fetched' => $startIndex,
        ]);

        return $vulns;
    }

    public function queryBatch(array $packages): array
    {
        $results = [];
        foreach ($packages as $key => $package) {
            $results[$key] = $this->queryPackage($package);
        }

        return $results;
    }

    public function fetchById(string $vulnId): ?VulnerabilityData
    {
        try {
            $this->throttle();

            $response = $this->http->get('cves/2.0', ['query' => ['cveId' => $vulnId]]);
            $data = json_decode($response->getBody()->getContents(), true);
            $cve = $data['vulnerabilities'][0]['cve'] ?? null;

            return $cve ? $this->parseCve($cve) : null;
        } catch (GuzzleException) {
            return null;
        }
    }

    private function parseCve(array $cve): ?VulnerabilityData
    {
        if (empty($cve['id'])) {
            return null;
        }

        $description = collect($cve['descriptions'] ?? [])->firstWhere('lang', 'en')['value'] ?? null;

        [$v3Score, $v3Vector] = $this->extractCvssV3($cve['metrics'] ?? []);
        [$v2Score, $v2Vector] = $this->extractCvssV2($cve['metrics'] ?? []);
        [$v4Score, $v4Vector] = $this->extractCvssV4($cve['metrics'] ?? []);

        $bestScore = $v4Score ?? $v3Score ?? $v2Score;
        $severity = $bestScore !== null ? SeverityLevel::fromCvssScore($bestScore) : SeverityLevel::Unknown;

        $cwes = [];
        foreach ($cve['weaknesses'] ?? [] as $weakness) {
            foreach ($weakness['description'] ?? [] as $desc) {
                if (str_starts_with($desc['value'] ?? '', 'CWE-')) {
                    $cwes[] = $desc['value'];
                }
            }
        }

        $references = array_map(
            fn ($r) => ['type' => implode(',', $r['tags'] ?? []) ?: null, 'url' => $r['url'] ?? ''],
            $cve['references'] ?? [],
        );

        return new VulnerabilityData(
            vulnId: $cve['id'],
            source: 'nvd',
            summary: $description ? mb_substr($description, 0, 255) : null,
            details: $description,
            severity: $severity,
            cvssV3Score: $v3Score,
            cvssV3Vector: $v3Vector,
            cvssV2Score: $v2Score,
            cvssV2Vector: $v2Vector,
            cvssV4Score: $v4Score,
            cvssV4Vector: $v4Vector,
            isWithdrawn: ($cve['vulnStatus'] ?? '') === 'Rejected',
            // NVD marks contested records via cveTags since ~2023; older
            // records embedded a DISPUTED marker in the description text.
            isDisputed: $this->isDisputed($cve, $description),
            affectedRanges: $this->configurationRanges($cve['configurations'] ?? []),
            references: $references,
            cwes: array_values(array_unique($cwes)),
            sourcePublishedAt: isset($cve['published']) ? new \DateTime($cve['published']) : null,
            sourceModifiedAt: isset($cve['lastModified']) ? new \DateTime($cve['lastModified']) : null,
            sourceUrl: "https://nvd.nist.gov/vuln/detail/{$cve['id']}",
            rawDataChecksum: hash('sha256', json_encode($cve)),
            extra: ['vuln_status' => $cve['vulnStatus'] ?? null],
        );
    }

    /**
     * Check the CVE `configurations` node to determine whether the package
     * version falls inside any affected CPE match range.
     */
    private function versionIsAffected(array $cve, PackageData $package): bool
    {
        $configurations = $cve['configurations'] ?? [];
        if (! $configurations || ! $package->version) {
            return true; // no version data — keep and let assessment decide
        }

        $version = \Gumslone\Vulns\Support\Version::normalize($package->version);

        foreach ($configurations as $config) {
            foreach ($config['nodes'] ?? [] as $node) {
                foreach ($node['cpeMatch'] ?? [] as $match) {
                    if (! ($match['vulnerable'] ?? false)) {
                        continue;
                    }

                    $cpeVersion = $this->cpeResolver->parse23($match['criteria'] ?? '')['version'] ?? '*';

                    // Exact version in the CPE itself
                    if ($cpeVersion !== '*' && $cpeVersion !== '-') {
                        if ($this->looseVersionEquals($version, $cpeVersion)) {
                            return true;
                        }

                        continue;
                    }

                    // Range bounds
                    if (isset($match['versionStartIncluding']) && version_compare($version, $match['versionStartIncluding'], '<')) {
                        continue;
                    }
                    if (isset($match['versionStartExcluding']) && version_compare($version, $match['versionStartExcluding'], '<=')) {
                        continue;
                    }
                    if (isset($match['versionEndIncluding']) && version_compare($version, $match['versionEndIncluding'], '>')) {
                        continue;
                    }
                    if (isset($match['versionEndExcluding']) && version_compare($version, $match['versionEndExcluding'], '>=')) {
                        continue;
                    }

                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Version equality that treats trailing-zero differences as equal, so a
     * CPE pinned at "1.0" matches a package at "1.0.0" (version_compare alone
     * reports those as different and would miss the CVE).
     */
    private function looseVersionEquals(string $a, string $b): bool
    {
        $trim = function (string $v): array {
            $parts = explode('.', $v);
            while (count($parts) > 1 && end($parts) === '0') {
                array_pop($parts);
            }

            return $parts;
        };

        return $trim($a) === $trim($b);
    }

    private function extractCvssV3(array $metrics): array
    {
        foreach (['cvssMetricV31', 'cvssMetricV30'] as $key) {
            $data = $metrics[$key][0]['cvssData'] ?? null;
            if ($data) {
                return [(float) $data['baseScore'], $data['vectorString'] ?? null];
            }
        }

        return [null, null];
    }

    private function extractCvssV2(array $metrics): array
    {
        $data = $metrics['cvssMetricV2'][0]['cvssData'] ?? null;

        return $data ? [(float) $data['baseScore'], $data['vectorString'] ?? null] : [null, null];
    }

    private function extractCvssV4(array $metrics): array
    {
        $data = $metrics['cvssMetricV40'][0]['cvssData'] ?? null;

        return $data ? [(float) $data['baseScore'], $data['vectorString'] ?? null] : [null, null];
    }

    private function isDisputed(array $cve, ?string $description): bool
    {
        foreach ($cve['cveTags'] ?? [] as $tagGroup) {
            foreach ((array) ($tagGroup['tags'] ?? []) as $tag) {
                if (strcasecmp((string) $tag, 'disputed') === 0) {
                    return true;
                }
            }
        }

        return str_contains($description ?? '', 'DISPUTED');
    }

    /**
     * Convert a full CPE 2.3 string into a wildcard match string
     * (drop the exact version so ranges are matched server-side).
     */
    private function matchString(string $cpe): string
    {
        $parts = $this->cpeResolver->parse23($cpe);

        return implode(':', [
            'cpe', '2.3', $parts['part'], $parts['vendor'], $parts['product'],
            '*', '*', '*', '*', '*', '*', '*', '*',
        ]);
    }

    /**
     * Naive fixed-window throttle honouring NVD rate limits
     * (5/30s anonymous, 50/30s with key). Uses the cache as shared state.
     */
    /**
     * NVD `configurations` nodes → constraint strings VersionRange can parse
     * (['range' => '>= 1.0, <= 2.4.7']). Raw NVD nodes are useless to range
     * matching downstream; a cpeMatch with an exact version becomes '= x',
     * and a wildcard match without bounds is dropped (no evidence).
     *
     * @return array<int, array{range: string, source: string}>
     */
    private function configurationRanges(array $configurations): array
    {
        $ranges = [];
        foreach ($configurations as $config) {
            foreach ($config['nodes'] ?? [] as $node) {
                foreach ($node['cpeMatch'] ?? [] as $match) {
                    if (($match['vulnerable'] ?? true) === false) {
                        continue;
                    }

                    $clauses = [];
                    foreach ([
                        'versionStartIncluding' => '>=', 'versionStartExcluding' => '>',
                        'versionEndIncluding' => '<=', 'versionEndExcluding' => '<',
                    ] as $key => $op) {
                        if (isset($match[$key])) {
                            $clauses[] = "{$op} {$match[$key]}";
                        }
                    }

                    if ($clauses === []) {
                        // Exact version pinned in the CPE itself?
                        $cpeVersion = explode(':', (string) ($match['criteria'] ?? ''))[5] ?? '*';
                        if ($cpeVersion !== '*' && $cpeVersion !== '-' && $cpeVersion !== '') {
                            $clauses[] = "= {$cpeVersion}";
                        }
                    }

                    if ($clauses !== []) {
                        $ranges[] = ['range' => implode(', ', $clauses), 'source' => 'nvd'];
                    }
                }
            }
        }

        return $ranges;
    }

    private function throttle(): void
    {
        $window = (int) $this->config('rate_limit_window', 30);
        $max = (int) $this->config('rate_limit_max', $this->apiKey ? 50 : 5);
        // '.' separators, not ':' — PSR-16 reserves {}()/\@: and strict
        // implementations (e.g. Symfony's Psr16Cache) throw on them.
        $key = 'vulns.nvd.rate.'.intdiv(time(), $window);

        // PSR-16 has no atomic increment; a read-modify-write is fine for a
        // best-effort throttle. Falls back to a per-process counter uncached.
        static $local = [];
        if ($this->cache !== null) {
            $count = (int) $this->cache->get($key, 0) + 1;
            $this->cache->set($key, $count, $window * 2);
        } else {
            $count = $local[$key] = ($local[$key] ?? 0) + 1;
        }

        if ($count > $max) {
            // Sleep until the current window rolls over
            sleep($window - (time() % $window) + 1);
        }
    }
}
