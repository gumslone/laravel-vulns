<?php

declare(strict_types=1);

namespace Gumslone\Vulns\Sources;

use Gumslone\Vulns\Contracts\CpeLookup;
use Gumslone\Vulns\Data\PackageData;
use Gumslone\Vulns\Data\VulnerabilityData;
use Gumslone\Vulns\Severity as SeverityLevel;
use Gumslone\Vulns\Support\CpeResolver;
use Gumslone\Vulns\Support\ResolvesLookupCpe;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Pool;
use Psr\Log\LoggerInterface;
use Psr\SimpleCache\CacheInterface;

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

    public function __construct(private readonly CpeResolver $cpeResolver, private readonly ?CpeLookup $cpeLookup = null, ?Client $http = null, array $options = [], ?LoggerInterface $logger = null, ?CacheInterface $cache = null)
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

    public function supports(PackageData $package): bool
    {
        return $this->resolveLookupCpe($package) !== null;
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
            // Encoded per segment: a crafted CPE must not be able to climb
            // out of search/ or append a query string.
            $path = 'search/'.rawurlencode((string) $parts['vendor']).'/'.rawurlencode((string) $parts['product']);
            $keysByPath[$path][] = $key;
            $productByPath[$path] = $parts['product'];
        }

        $perPage = max(1, (int) $this->config('page_size', 100));
        $maxPages = max(1, (int) $this->config('max_pages', 20));

        // Fail safe: a rejected or unreadable page must not read as "no known
        // vulnerabilities" for its packages — collect failures during the
        // pool rounds and throw once they have drained.
        $failed = 0;
        $requested = 0;
        $firstReason = null;
        $itemsByPath = array_fill_keys(array_keys($keysByPath), []);

        // Each round fetches one page per pending lookup concurrently; a
        // full page means there may be another (a popular product runs to
        // hundreds of rows — page 1 alone holds only the newest CVEs, and an
        // old installed version is affected by exactly the older ones).
        $pending = array_fill_keys(array_keys($keysByPath), 1);
        while ($pending !== []) {
            $next = [];
            $requests = function () use ($pending, $perPage) {
                foreach ($pending as $path => $page) {
                    yield $path => fn () => $this->http->getAsync("{$path}?per_page={$perPage}&page={$page}");
                }
            };

            $pool = new Pool($this->http, $requests(), [
                'concurrency' => (int) $this->config('max_concurrency', 8),
                'fulfilled' => function ($response, $path) use (&$itemsByPath, &$next, &$failed, &$firstReason, $pending, $perPage, $maxPages, $keysByPath) {
                    $data = json_decode($response->getBody()->getContents(), true);
                    if (! is_array($data)) {
                        $failed++;
                        $firstReason ??= 'the response was not valid JSON';

                        return;
                    }

                    $items = $this->normaliseResults($data);
                    $itemsByPath[$path] = array_merge($itemsByPath[$path], $items);

                    $total = is_numeric($data['total_count'] ?? null) ? (int) $data['total_count'] : null;
                    $more = $total !== null ? count($itemsByPath[$path]) < $total : count($items) >= $perPage;
                    if ($items === [] || ! $more) {
                        return;
                    }
                    if ($pending[$path] >= $maxPages) {
                        $this->warn(
                            sprintf('results for %s truncated at %d rows (max_pages=%d)', $path, count($itemsByPath[$path]), $maxPages),
                            [], $keysByPath[$path],
                        );

                        return;
                    }
                    $next[$path] = $pending[$path] + 1;
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

            $requested += count($pending);
            $pool->promise()->wait();
            $pending = $next;
        }

        if ($failed > 0) {
            throw new \RuntimeException(sprintf(
                'CVE-Search: %d of %d requests failed: %s', $failed, $requested, $firstReason,
            ));
        }

        foreach ($itemsByPath as $path => $items) {
            // The same CVE arrives once per upstream feed; keep the first.
            $vulns = [];
            foreach ($items as $item) {
                $vuln = $this->parseCve($item, $productByPath[$path] ?? null);
                if ($vuln !== null) {
                    $vulns[$vuln->vulnId] ??= $vuln;
                }
            }
            foreach ($keysByPath[$path] as $key) {
                $results[$key] = array_values($vulns);
            }
        }

        return $results;
    }

    public function fetchById(string $vulnId): ?VulnerabilityData
    {
        try {
            $response = $this->http->get('cve/'.rawurlencode($vulnId));
            // An unknown id answers 200 with a literal `null`.
            $data = $this->decode($response, "CVE-Search lookup of {$vulnId}", allowNull: true);

            return $data ? $this->parseCve($data) : null;
        } catch (GuzzleException $e) {
            if (self::isNotFound($e)) {
                return null;
            }

            // Fail safe: an unreachable instance is not "unknown CVE".
            throw new \RuntimeException("CVE-Search lookup failed for {$vulnId}: {$e->getMessage()}", 0, $e);
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
        $cvssV4Score = null;
        $cvssV4Vector = null;
        if (isset($item['cvss3'])) {
            $cvssV3Score = (float) $item['cvss3'];
            $cvssV3Vector = $item['cvss3-vector'] ?? null;
        } else {
            // CNA-supplied metrics first, then ADP enrichment (NVD/CISA often
            // attach CVSS in containers.adp rather than containers.cna)
            $metricSets = collect($cna['metrics'] ?? [])
                ->concat(collect($item['containers']['adp'] ?? [])->flatMap(fn ($adp) => $adp['metrics'] ?? []));

            // Each standard lands in its own column — a v4 vector is not a
            // v3.1 vector, so it must never sit where downstream labels it
            // CVSSv31.
            foreach ($metricSets as $metric) {
                foreach (['cvssV3_1', 'cvssV3_0'] as $key) {
                    if ($cvssV3Score === null && isset($metric[$key]['baseScore'])) {
                        $cvssV3Score = (float) $metric[$key]['baseScore'];
                        $cvssV3Vector = $metric[$key]['vectorString'] ?? null;
                    }
                }
                if ($cvssV4Score === null && isset($metric['cvssV4_0']['baseScore'])) {
                    $cvssV4Score = (float) $metric['cvssV4_0']['baseScore'];
                    $cvssV4Vector = $metric['cvssV4_0']['vectorString'] ?? null;
                }
            }
        }

        $cvssV2Score = isset($item['cvss']) ? (float) $item['cvss'] : null;

        $severity = SeverityLevel::fromCvssScore($cvssV4Score ?? $cvssV3Score ?? $cvssV2Score);

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
            cvssV4Score: $cvssV4Score,
            cvssV4Vector: $cvssV4Vector,
            // CVE 5 records keep REJECTED ids resolvable; they must not look live.
            isWithdrawn: strcasecmp((string) ($item['cveMetadata']['state'] ?? ''), 'REJECTED') === 0,
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
