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
use GuzzleHttp\Pool;

/**
 * CVE-Search adapter — works against the public CIRCL instance
 * (cve.circl.lu) or a self-hosted https://github.com/cve-search/cve-search.
 * Endpoints: /api/cve/{id}, /api/search/{vendor}/{product}
 *
 * Self-hosted instances (CVE-Search-Docker) serve HTTPS with a self-signed
 * certificate — set CVE_SEARCH_VERIFY_TLS=false for those.
 */
class CveSearchSource extends AbstractSource
{
    use ResolvesLookupCpe;


    public function __construct(private readonly CpeResolver $cpeResolver, private readonly ?CpeLookup $cpeLookup = null, ?Client $http = null, array $options = [], ?\Psr\Log\LoggerInterface $logger = null, ?\Psr\SimpleCache\CacheInterface $cache = null)
    {
        $this->boot($options, $logger, $cache);
        $this->http = $http ?? $this->makeClient(
            rtrim((string) $this->config('base_url', 'https://cve.circl.lu/api'), '/').'/',
            options: ['verify' => (bool) $this->config('verify_tls', true)],
        );
    }

    public function name(): string
    {
        return 'cve_search';
    }

    public function queryBatch(array $packages): array
    {
        $results = array_fill_keys(array_keys($packages), []);

        // Lookup is by CPE vendor/product (no version), so packages that
        // resolve to the same pair share one request.
        $keysByPath = [];
        $productByPath = [];
        foreach ($packages as $key => $package) {
            $cpe = $this->resolveLookupCpe($package);
            if (! $cpe) {
                continue;
            }

            $parts = $this->cpeResolver->parse23($cpe);
            $perPage = (int) $this->config('page_size', 100);
            $path = "search/{$parts['vendor']}/{$parts['product']}?per_page={$perPage}";
            $keysByPath[$path][] = $key;
            $productByPath[$path] = $parts['product'];
        }

        $requests = function () use ($keysByPath) {
            foreach (array_keys($keysByPath) as $path) {
                yield $path => fn () => $this->http->getAsync($path);
            }
        };

        // Fail safe: a rejected request must not read as "no known
        // vulnerabilities" for its packages — collect rejections during the
        // pool run and throw once the pool has drained.
        $failed = 0;
        $firstReason = null;

        $pool = new Pool($this->http, $requests(), [
            'concurrency' => (int) $this->config('max_concurrency', 8),
            'fulfilled' => function ($response, $path) use (&$results, $keysByPath, $productByPath) {
                $data = json_decode($response->getBody()->getContents(), true);

                $items = $this->normaliseResults(is_array($data) ? $data : []);
                $product = $productByPath[$path] ?? null;
                $vulns = array_values(array_filter(array_map(
                    fn (array $item) => $this->parseCve($item, $product),
                    $items,
                )));

                foreach ($keysByPath[$path] as $key) {
                    $results[$key] = $vulns;
                }
            },
            'rejected' => function ($reason, $path) use (&$failed, &$firstReason) {
                $failed++;
                $message = $reason instanceof \Throwable ? $reason->getMessage() : (string) $reason;
                $firstReason ??= $message;
                $this->log('warning', '[vulns] CVE-Search query failed', [
                    'lookup' => $path,
                    'error' => $message,
                ]);
            },
        ]);

        $pool->promise()->wait();

        if ($failed > 0) {
            throw new \RuntimeException(sprintf(
                'CVE-Search: %d of %d requests failed: %s', $failed, count($keysByPath), $firstReason,
            ));
        }

        return $results;
    }

    public function fetchById(string $vulnId): ?VulnerabilityData
    {
        try {
            $response = $this->http->get('cve/'.rawurlencode($vulnId));
            $data = json_decode($response->getBody()->getContents(), true);

            return $data ? $this->parseCve($data) : null;
        } catch (GuzzleException) {
            return null;
        }
    }

    /**
     * Normalise the /api/search response into a flat list of records.
     *
     * Three shapes exist in the wild:
     *   - classic cve-search: a bare list of records
     *   - classic wrapped:    {"results": [record, ...]}
     *   - Vulnerability-Lookup (cve.circl.lu since 2025): {"results":
     *     {"nvd": [[id, record], ...], "github": [[id, record], ...], ...}}
     */
    private function normaliseResults(array $data): array
    {
        $results = $data['results'] ?? $data;
        if (! is_array($results)) {
            return [];
        }

        if (array_is_list($results)) {
            return $results;
        }

        $items = [];
        foreach ($results as $perSource) {
            if (! is_array($perSource)) {
                continue;
            }
            foreach ($perSource as $entry) {
                // Entries are [id, record] pairs; tolerate bare records too
                if (is_array($entry) && array_is_list($entry) && isset($entry[1]) && is_array($entry[1])) {
                    $items[] = $entry[1];
                } elseif (is_array($entry)) {
                    $items[] = $entry;
                }
            }
        }

        return $items;
    }

    private function parseCve(array $item, ?string $product = null): ?VulnerabilityData
    {
        $vulnId = $item['id'] ?? $item['cveMetadata']['cveId'] ?? null;
        if (! $vulnId) {
            return null;
        }

        // Both legacy (flat) and CVE 5.x (nested container) response shapes exist
        $cna = $item['containers']['cna'] ?? [];
        $summary = $item['summary']
            ?? collect($cna['descriptions'] ?? [])->firstWhere('lang', 'en')['value']
            ?? null;

        $cvssV3Score = null;
        $cvssV3Vector = null;
        if (isset($item['cvss3'])) {
            $cvssV3Score = (float) $item['cvss3'];
            $cvssV3Vector = $item['cvss3-vector'] ?? null;
        } else {
            // CNA-supplied metrics first, then ADP enrichment (NVD/CISA often
            // attach CVSS in containers.adp rather than containers.cna)
            $metricSets = collect($cna['metrics'] ?? [])
                ->concat(collect($item['containers']['adp'] ?? [])->flatMap(fn ($adp) => $adp['metrics'] ?? []));

            // Prefer a real CVSS v3.x score for the v3 columns. v4 is only a
            // score-based fallback (its 0-10 score maps to the same severity
            // bands) — but its vector is NOT a v3.1 vector, so don't store it in
            // the v3 vector field where downstream labels it CVSSv31.
            foreach ($metricSets as $metric) {
                foreach (['cvssV3_1', 'cvssV3_0'] as $key) {
                    if (isset($metric[$key]['baseScore'])) {
                        $cvssV3Score = (float) $metric[$key]['baseScore'];
                        $cvssV3Vector = $metric[$key]['vectorString'] ?? null;
                        break 2;
                    }
                }
            }

            if ($cvssV3Score === null) {
                foreach ($metricSets as $metric) {
                    if (isset($metric['cvssV4_0']['baseScore'])) {
                        $cvssV3Score = (float) $metric['cvssV4_0']['baseScore']; // score only; vector left null
                        break;
                    }
                }
            }
        }

        $cvssV2Score = isset($item['cvss']) ? (float) $item['cvss'] : null;

        $severity = $cvssV3Score !== null ? SeverityLevel::fromCvssScore($cvssV3Score)
            : ($cvssV2Score !== null ? SeverityLevel::fromCvssScore($cvssV2Score) : SeverityLevel::Unknown);

        $references = $item['references']
            ?? array_column($cna['references'] ?? [], 'url');

        $cwes = array_values(array_filter(array_map(
            fn ($pt) => collect($pt['descriptions'] ?? [])->first()['cweId'] ?? null,
            $cna['problemTypes'] ?? [],
        )));
        if (isset($item['cwe']) && str_starts_with($item['cwe'], 'CWE-')) {
            $cwes[] = $item['cwe'];
        }

        $published = $item['Published'] ?? $item['cveMetadata']['datePublished'] ?? null;
        $modified = $item['Modified'] ?? $item['cveMetadata']['dateUpdated'] ?? null;

        return new VulnerabilityData(
            vulnId: $vulnId,
            source: 'cve_search',
            summary: $summary ? mb_substr($summary, 0, 255) : null,
            details: $summary,
            severity: $severity,
            cvssV3Score: $cvssV3Score,
            cvssV3Vector: $cvssV3Vector,
            cvssV2Score: $cvssV2Score,
            cvssV2Vector: $item['cvss-vector'] ?? null,
            references: array_map(fn ($url) => ['type' => null, 'url' => is_array($url) ? ($url['url'] ?? '') : $url], $references),
            cwes: array_values(array_unique($cwes)),
            sourcePublishedAt: $published ? new \DateTime($published) : null,
            sourceModifiedAt: $modified ? new \DateTime($modified) : null,
            sourceUrl: "https://cve.circl.lu/cve/{$vulnId}",
            rawDataChecksum: hash('sha256', json_encode($item)),
            affectedRanges: $this->extractRanges($item, $product),
            extra: ['vulnerable_configuration' => $item['vulnerable_configuration'] ?? []],
        );
    }

    /**
     * Affected version ranges as constraint strings for VersionRange, so the
     * aggregator can prove an installed version outside every range and drop
     * the false positive (this source matches by name only).
     *
     * Handles both record shapes: CVE 5.x `containers.cna.affected[].versions[]`
     * and the NVD-API `configurations` node with cpeMatch
     * versionStartIncluding / versionEndIncluding bounds.
     *
     * Fail-safe: any entry that says "affected" but carries no expressible
     * bound makes the WHOLE record undeterminable ([]) — partial ranges would
     * let VersionRange wrongly prove "not affected".
     *
     * @return array<int, array{range: string, source: string}>
     */
    private function extractRanges(array $item, ?string $product): array
    {
        $entries = $item['containers']['cna']['affected'] ?? [];

        // A CVE can list several products; keep only the queried one when the
        // names line up. If none match, keep all — ORing a sibling product's
        // ranges can only over-flag, never clear a real hit.
        if ($product !== null && $entries !== []) {
            $matching = array_values(array_filter($entries, fn ($e) => strcasecmp(
                (string) ($e['product'] ?? $e['packageName'] ?? ''), $product) === 0));
            if ($matching !== []) {
                $entries = $matching;
            }
        }

        $ranges = [];
        foreach ($entries as $entry) {
            $versions = collect($entry['versions'] ?? [])
                ->filter(fn ($v) => is_array($v) && ($v['status'] ?? 'affected') === 'affected');

            // "This product is affected" with no affected version rows —
            // either no version data or inverted defaultStatus/unaffected
            // listing we can't express. Undeterminable.
            if ($versions->isEmpty()) {
                return [];
            }

            foreach ($versions as $v) {
                $range = $this->rangeFromVersionEntry($v);
                if ($range === null) {
                    return [];
                }
                $ranges[] = ['range' => $range, 'source' => $this->name()];
            }
        }

        foreach ($this->cpeMatchRanges($item) as $range) {
            if ($range === null) {
                return [];
            }
            $ranges[] = ['range' => $range, 'source' => $this->name()];
        }

        return $ranges;
    }

    /**
     * One CVE 5.x version entry → constraint string, or null when it affirms
     * "affected" without a usable bound.
     */
    private function rangeFromVersionEntry(array $v): ?string
    {
        $version = trim((string) ($v['version'] ?? ''));

        // GitHub-CNA style packs the whole constraint into `version`
        if (preg_match('/^[<>=]/', $version)) {
            return $version;
        }

        // Legacy CNA freetext: "through 0.18.0" = inclusive upper bound,
        // "before 1.2.3" = exclusive upper bound
        if (preg_match('/^(through|before)\s+(\S+)$/i', $version, $m)) {
            return (strtolower($m[1]) === 'through' ? '<= ' : '< ').$m[2];
        }

        $noLower = in_array(strtolower($version), ['', '0', '*', '-', 'unspecified', 'n/a'], true);

        foreach (['lessThan' => '<', 'lessThanOrEqual' => '<='] as $key => $op) {
            if (! isset($v[$key])) {
                continue;
            }
            if ($v[$key] === '*') {
                return $noLower ? null : ">= {$version}"; // open-ended upper
            }

            return $noLower ? "{$op} {$v[$key]}" : ">= {$version}, {$op} {$v[$key]}";
        }

        return $noLower ? null : "= {$version}";
    }

    /**
     * NVD-API-shape `configurations` (self-hosted / fkie records): vulnerable
     * cpeMatch entries → constraint strings. Yields null for a match without
     * expressible bounds so the caller can bail to undeterminable.
     *
     * @return iterable<int, ?string>
     */
    private function cpeMatchRanges(array $item): iterable
    {
        foreach ($item['configurations'] ?? [] as $config) {
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

                    if ($clauses !== []) {
                        yield implode(', ', $clauses);

                        continue;
                    }

                    // No range fields — the CPE itself may pin an exact version
                    // (cpe:2.3:part:vendor:product:VERSION:…)
                    $cpeVersion = explode(':', (string) ($match['criteria'] ?? ''))[5] ?? '';
                    yield in_array($cpeVersion, ['', '*', '-'], true) ? null : "= {$cpeVersion}";
                }
            }
        }
    }
}
