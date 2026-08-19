<?php

declare(strict_types=1);

namespace Gumslone\Vulns\Sources;

use Gumslone\Vulns\Data\VulnerabilityData;
use Gumslone\Vulns\Severity as SeverityLevel;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\BadResponseException;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Pool;

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
    public function __construct(?Client $http = null, array $options = [], ?\Psr\Log\LoggerInterface $logger = null, ?\Psr\SimpleCache\CacheInterface $cache = null)
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

        // CVEDB caps result lists via `limit`; 50 is what the reference
        // implementation requests. A full page may mean truncation — flag it
        // rather than guessing at undocumented paging parameters.
        $limit = (int) $this->config('page_size', 50);

        $requests = function () use ($keysByProduct, $queryByProduct, $limit) {
            foreach (array_keys($keysByProduct) as $product) {
                yield $product => fn () => $this->http->getAsync('cves', [
                    'query' => $queryByProduct[$product] + ['limit' => $limit],
                ]);
            }
        };

        // Fail safe: a rejected request must not read as "no known
        // vulnerabilities" for its product — collect rejections during the
        // pool run and throw once the pool has drained.
        $failed = 0;
        $firstReason = null;

        $pool = new Pool($this->http, $requests(), [
            'concurrency' => (int) $this->config('max_concurrency', 8),
            'fulfilled' => function ($response, $product) use (&$results, $keysByProduct, $limit) {
                $data = json_decode($response->getBody()->getContents(), true) ?? [];
                $items = $data['cves'] ?? [];

                if (count($items) >= $limit) {
                    $this->log('warning', '[vulns] Shodan CVEDB returned a full page — results may be truncated', [
                        'product' => $product,
                        'limit' => $limit,
                    ]);
                }

                $vulns = array_values(array_filter(array_map(
                    fn ($item) => is_array($item) ? $this->parseItem($item) : null,
                    $items,
                )));

                foreach ($keysByProduct[$product] as $key) {
                    $results[$key] = $vulns;
                }
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

        $pool->promise()->wait();

        if ($failed > 0) {
            throw new \RuntimeException(sprintf(
                'Shodan CVEDB: %d of %d requests failed: %s', $failed, count($keysByProduct), $firstReason,
            ));
        }

        return $results;
    }

    public function fetchById(string $vulnId): ?VulnerabilityData
    {
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

        $data = json_decode($response->getBody()->getContents(), true);

        return is_array($data) ? $this->parseItem($data) : null;
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
