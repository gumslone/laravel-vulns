<?php

declare(strict_types=1);

namespace Gumslone\Vulns\Sources;

use Gumslone\Vulns\Data\PackageData;
use Gumslone\Vulns\Data\VulnerabilityData;
use Gumslone\Vulns\Severity as SeverityLevel;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\BadResponseException;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Pool;
use Psr\Log\LoggerInterface;
use Psr\SimpleCache\CacheInterface;

/**
 * Shodan CVEDB adapter — https://cvedb.shodan.io. Free, no API key.
 *
 * Endpoints (mirroring GumVulns' ShodanSource):
 *   - GET cve/{CVE-id}                     single record
 *   - GET cves?product={name}&limit=50     product search
 *
 * Records carry flat numeric CVSS scores (cvss_v2 / cvss_v3 / cvss_v4, plus a
 * generic `cvss` + `cvss_version` pair on older rows) and threat signals CVEDB
 * is uniquely good for: EPSS score, EPSS percentile (`ranking_epss`) and the CISA
 * KEV flag. It does NOT expose per-version affects data — only a `cpes` list —
 * so affectedRanges stays empty and the cpes go into extra: emitting
 * pseudo-ranges here would let downstream version-evidence merging wrongly
 * clear real hits.
 */
class ShodanCvedbSource extends AbstractSource
{
    public function __construct(?Client $http = null, array $options = [], ?LoggerInterface $logger = null, ?CacheInterface $cache = null)
    {
        $this->boot($options, $logger, $cache);
        $this->http = $http ?? $this->makeClient(
            rtrim((string) $this->config('base_url', 'https://cvedb.shodan.io'), '/').'/',
        );
    }

    public function name(): string
    {
        return 'shodan_cvedb';
    }

    public function supports(PackageData $package): bool
    {
        return ($package->cpe23 !== null && $package->version !== null) || trim($package->name) !== '';
    }

    public function queryBatch(array $packages): array
    {
        $results = array_fill_keys(array_keys($packages), []);

        // An explicit CPE with a concrete version uses CVEDB's precise cpe23
        // filter (it needs part AND version); everything else falls back to
        // the broader product-name search. Packages sharing a lookup key —
        // e.g. the same dependency reachable through different manifests —
        // share one request.
        $keysByProduct = [];
        $queryByProduct = [];
        foreach ($packages as $key => $package) {
            if ($package->cpe23 !== null && $package->version !== null) {
                $lookup = $package->cpe23;
                $queryByProduct[$lookup] = ['cpe23' => $package->cpe23];
            } else {
                $lookup = $package->name;
                $queryByProduct[$lookup] = ['product' => $package->name];
            }
            $keysByProduct[$lookup][] = $key;
        }

        // CVEDB caps each list via `limit` and walks on with `skip`. Results
        // come newest first, so page 1 alone would miss exactly the older
        // CVEs an old installed version is affected by.
        $limit = max(1, (int) $this->config('page_size', 50));
        $maxPages = max(1, (int) $this->config('max_pages', 20));

        // Fail safe: a rejected or unreadable page must not read as "no known
        // vulnerabilities" for its product — collect failures during the
        // pool rounds and throw once they have drained.
        $failed = 0;
        $requested = 0;
        $firstReason = null;
        $itemsByProduct = array_fill_keys(array_keys($keysByProduct), []);

        $pending = array_fill_keys(array_keys($keysByProduct), 0);
        while ($pending !== []) {
            $next = [];
            $requests = function () use ($pending, $queryByProduct, $limit) {
                foreach ($pending as $product => $page) {
                    yield $product => fn () => $this->http->getAsync('cves', [
                        'query' => $queryByProduct[$product] + ['limit' => $limit] + ($page > 0 ? ['skip' => $page * $limit] : []),
                    ]);
                }
            };

            $pool = new Pool($this->http, $requests(), [
                'concurrency' => (int) $this->config('max_concurrency', 8),
                'fulfilled' => function ($response, $product) use (&$itemsByProduct, &$next, &$failed, &$firstReason, $pending, $keysByProduct, $limit, $maxPages) {
                    $data = json_decode($response->getBody()->getContents(), true);
                    if (! is_array($data)) {
                        $failed++;
                        $firstReason ??= 'the response was not valid JSON';

                        return;
                    }

                    $items = is_array($data['cves'] ?? null) ? $data['cves'] : [];
                    $itemsByProduct[$product] = array_merge($itemsByProduct[$product], $items);

                    if (count($items) < $limit) {
                        return; // a short page is the last one
                    }
                    if ($maxPages <= $pending[$product] + 1) {
                        $this->warn(
                            sprintf('results for "%s" truncated at %d CVEs (max_pages=%d)', $product, count($itemsByProduct[$product]), $maxPages),
                            [], $keysByProduct[$product],
                        );

                        return;
                    }
                    $next[$product] = $pending[$product] + 1;
                },
                'rejected' => function ($reason, $product) use (&$failed, &$firstReason) {
                    $failed++;
                    $message = $reason instanceof \Throwable ? $reason->getMessage() : (string) $reason;
                    $firstReason ??= $message;
                    $this->log('warning', '[vulns] Shodan CVEDB query failed', [
                        'product' => $product,
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
                'Shodan CVEDB: %d of %d requests failed: %s', $failed, $requested, $firstReason,
            ));
        }

        foreach ($itemsByProduct as $product => $items) {
            $vulns = [];
            foreach (array_filter($items, 'is_array') as $item) {
                $vuln = $this->parseItem($item);
                if ($vuln !== null) {
                    $vulns[$vuln->vulnId] ??= $vuln;
                }
            }
            foreach ($keysByProduct[$product] as $key) {
                $results[$key] = array_values($vulns);
            }
        }

        return $results;
    }

    public function knowsId(string $vulnId): bool
    {
        return VulnerabilityData::isCveId(trim($vulnId));
    }

    public function fetchById(string $vulnId): ?VulnerabilityData
    {
        if (! $this->knowsId($vulnId)) {
            return null;
        }

        try {
            $response = $this->http->get('cve/'.rawurlencode($vulnId));
        } catch (BadResponseException $e) {
            // An unknown id is a semantic miss, not an outage
            if ($e->getResponse()->getStatusCode() === 404) {
                return null;
            }

            $this->log('warning', '[vulns] Shodan CVEDB fetch failed', ['id' => $vulnId, 'error' => $e->getMessage()]);

            throw new \RuntimeException("Shodan CVEDB: fetch of {$vulnId} failed: {$e->getMessage()}", 0, $e);
        } catch (GuzzleException $e) {
            $this->log('warning', '[vulns] Shodan CVEDB fetch failed', ['id' => $vulnId, 'error' => $e->getMessage()]);

            throw new \RuntimeException("Shodan CVEDB: fetch of {$vulnId} failed: {$e->getMessage()}", 0, $e);
        }

        return $this->parseItem($this->decode($response, "Shodan CVEDB lookup of {$vulnId}"));
    }

    private function parseItem(array $item): ?VulnerabilityData
    {
        $id = (string) ($item['cve_id'] ?? '');
        if ($id === '') {
            return null;
        }

        $v4Score = isset($item['cvss_v4']) ? (float) $item['cvss_v4'] : null;
        $v3Score = isset($item['cvss_v3']) ? (float) $item['cvss_v3'] : null;
        $v2Score = isset($item['cvss_v2']) ? (float) $item['cvss_v2'] : null;

        // Older rows only carry a generic `cvss` + `cvss_version` pair; route
        // it into the matching versioned slot rather than dropping the score.
        if (isset($item['cvss'])) {
            match ((int) ($item['cvss_version'] ?? 3)) {
                2 => $v2Score ??= (float) $item['cvss'],
                4 => $v4Score ??= (float) $item['cvss'],
                default => $v3Score ??= (float) $item['cvss'],
            };
        }

        $bestScore = $v4Score ?? $v3Score ?? $v2Score;

        $references = array_values(array_filter(array_map(
            fn ($url) => is_string($url) ? trim($url) : '',
            $item['references'] ?? [],
        )));

        $summary = isset($item['summary']) ? (string) $item['summary'] : null;

        return new VulnerabilityData(
            vulnId: $id,
            source: 'shodan_cvedb',
            summary: $summary !== null ? mb_substr($summary, 0, 255) : null,
            details: $summary,
            severity: $bestScore !== null ? SeverityLevel::fromCvssScore($bestScore) : SeverityLevel::Unknown,
            cvssV3Score: $v3Score,
            cvssV3Vector: $item['cvss_v3_vector'] ?? null,
            cvssV2Score: $v2Score,
            cvssV4Score: $v4Score,
            epssScore: isset($item['epss']) ? (float) $item['epss'] : null,
            // The live API spells it `ranking_epss`; `ranked_epss` kept as a
            // fallback for older cached payloads.
            epssPercentile: isset($item['ranking_epss']) ? (float) $item['ranking_epss']
                : (isset($item['ranked_epss']) ? (float) $item['ranked_epss'] : null),
            isKnownExploited: ! empty($item['kev']),
            usedInRansomware: strcasecmp((string) ($item['ransomware_campaign'] ?? ''), 'Known') === 0,
            references: array_map(fn ($url) => ['type' => null, 'url' => $url], $references),
            sourcePublishedAt: isset($item['published_time']) ? new \DateTime($item['published_time']) : null,
            sourceUrl: "https://cvedb.shodan.io/cve/{$id}",
            rawDataChecksum: hash('sha256', json_encode($item)),
            extra: [
                // CPE list only — no version bounds, so it stays evidence,
                // not affectedRanges (see class docblock).
                'cpes' => $item['cpes'] ?? [],
                'propose_action' => $item['propose_action'] ?? null,
                'ransomware_campaign' => $item['ransomware_campaign'] ?? null,
            ],
        );
    }
}
