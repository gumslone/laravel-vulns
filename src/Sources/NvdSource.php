<?php

declare(strict_types=1);

namespace Gumslone\Vulns\Sources;

use Gumslone\Vulns\Contracts\CpeLookup;
use Gumslone\Vulns\Data\PackageData;
use Gumslone\Vulns\Data\VulnerabilityData;
use Gumslone\Vulns\Severity as SeverityLevel;
use Gumslone\Vulns\Support\BuildsCpeRanges;
use Gumslone\Vulns\Support\CpeResolver;
use Gumslone\Vulns\Support\ResolvesLookupCpe;
use Gumslone\Vulns\Support\VersionRange;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use Psr\Log\LoggerInterface;
use Psr\SimpleCache\CacheInterface;

/**
 * NIST National Vulnerability Database adapter.
 * API documentation: https://nvd.nist.gov/developers/vulnerabilities
 *
 * Rate limits: 5 req/30s without key, 50 req/30s with a (free) API key.
 */
class NvdSource extends AbstractSource
{
    use BuildsCpeRanges;
    use ResolvesLookupCpe;

    private ?string $apiKey;

    public function __construct(private readonly CpeResolver $cpeResolver, private readonly ?CpeLookup $cpeLookup = null, ?Client $http = null, array $options = [], ?LoggerInterface $logger = null, ?CacheInterface $cache = null)
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
                $data = $this->decode($response, "NVD query for {$package->name}");

                $items = $data['vulnerabilities'] ?? [];
                foreach ($items as $item) {
                    $vuln = $this->parseCve($item['cve'] ?? []);
                    if ($vuln && $this->versionIsAffected($item['cve'] ?? [], $package, $cpe)) {
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
        } catch (GuzzleException|\RuntimeException $e) {
            $this->log('warning', '[vulns] NVD query failed', ['package' => $package->name, 'error' => $e->getMessage()]);

            // Fail safe: an unreachable NVD must surface as an error the
            // caller records, not read as "no known vulnerabilities".
            throw new \RuntimeException("NVD query failed for {$package->name}: {$e->getMessage()}", 0, $e);
        }

        $this->warn("results for {$package->name} truncated at {$startIndex} CVEs (max_pages={$maxPages})");

        return $vulns;
    }

    public function supports(PackageData $package): bool
    {
        return $this->resolveLookupCpe($package) !== null;
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
            $data = $this->decode($response, "NVD lookup of {$vulnId}");
            $cve = $data['vulnerabilities'][0]['cve'] ?? null;

            return $cve ? $this->parseCve($cve) : null;
        } catch (GuzzleException $e) {
            if (self::isNotFound($e)) {
                return null;
            }

            // Fail safe: a rate-limited or unreachable NVD is not "unknown CVE".
            throw new \RuntimeException("NVD lookup failed for {$vulnId}: {$e->getMessage()}", 0, $e);
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
    private function versionIsAffected(array $cve, PackageData $package, ?string $lookupCpe = null): bool
    {
        if (! $package->version) {
            return true; // no version to judge — keep and let assessment decide
        }

        $ranges = $this->configurationRanges($cve['configurations'] ?? []);

        // Judge by the queried product's own ranges: a sibling product's
        // "< 9.0.0" says nothing about this one. (When no vulnerable match
        // names it — a platform-only match — every range is considered.)
        $cpe = $lookupCpe !== null ? $this->cpeResolver->parse23($lookupCpe) : [];
        $product = strtolower(($cpe['vendor'] ?? '').':'.($cpe['product'] ?? ''));
        $own = array_values(array_filter($ranges, fn (array $r) => $r['product'] === $product));

        // VersionRange is fail-safe where raw version_compare is not: it
        // refuses to order "1.1.1k" or "5.3.0.RELEASE" rather than sort them
        // below the bound and clear a vulnerable package. Only a provable
        // "outside every range" drops the CVE.
        return VersionRange::isVulnerable($package->version, $own ?: $ranges) !== false;
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
