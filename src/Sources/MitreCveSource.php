<?php

declare(strict_types=1);

namespace Gumslone\Vulns\Sources;

use Gumslone\Vulns\Data\VulnerabilityData;
use Gumslone\Vulns\Severity as SeverityLevel;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\BadResponseException;
use GuzzleHttp\Exception\GuzzleException;

/**
 * MITRE CVE Services adapter — the authoritative CVE List V5 record API
 * (https://cveawg.mitre.org/api). Free, no API key.
 *
 * This is a fetch-by-id-ONLY source: the CVE Program publishes records, it
 * has no package-coordinate search surface. The source exists because CNA
 * records land here the moment a CVE is published — often days before NVD
 * finishes analysis — so aggregators can hydrate an id seen elsewhere with
 * the authoritative description, CNA/ADP CVSS metrics and affected products.
 */
class MitreCveSource extends AbstractSource
{
    public function __construct(?Client $http = null, array $options = [], ?\Psr\Log\LoggerInterface $logger = null, ?\Psr\SimpleCache\CacheInterface $cache = null)
    {
        $this->boot($options, $logger, $cache);
        $this->http = $http ?? $this->makeClient(
            rtrim((string) $this->config('base_url', 'https://cveawg.mitre.org/api'), '/').'/',
        );
    }

    public function name(): string
    {
        return 'mitre';
    }

    /**
     * Always empty, without any HTTP traffic: there is no package search to
     * call (see class docblock). Every input key is still present in the
     * result so callers can attribute per-package outcomes uniformly.
     */
    public function queryBatch(array $packages): array
    {
        return array_fill_keys(array_keys($packages), []);
    }

    public function fetchById(string $vulnId): ?VulnerabilityData
    {
        try {
            $response = $this->http->get('cve/'.rawurlencode($vulnId));
        } catch (BadResponseException $e) {
            // An unknown/unpublished id is a semantic miss, not an outage
            if ($e->getResponse()->getStatusCode() === 404) {
                return null;
            }

            $this->log('warning', '[vulns] MITRE CVE fetch failed', ['id' => $vulnId, 'error' => $e->getMessage()]);

            throw new \RuntimeException("MITRE: fetch of {$vulnId} failed: {$e->getMessage()}", 0, $e);
        } catch (GuzzleException $e) {
            $this->log('warning', '[vulns] MITRE CVE fetch failed', ['id' => $vulnId, 'error' => $e->getMessage()]);

            throw new \RuntimeException("MITRE: fetch of {$vulnId} failed: {$e->getMessage()}", 0, $e);
        }

        $data = json_decode($response->getBody()->getContents(), true);

        return is_array($data) ? $this->parseRecord($data) : null;
    }

    /** Map a CVE Record v5 JSON document into the normalised DTO. */
    private function parseRecord(array $record): ?VulnerabilityData
    {
        $meta = $record['cveMetadata'] ?? [];
        $id = $meta['cveId'] ?? null;
        if (! $id) {
            return null;
        }

        $cna = $record['containers']['cna'] ?? [];

        // REJECTED records move the prose to rejectedReasons; return them
        // anyway (with state noted in extra) so a stored copy of a since-
        // rejected CVE can be recognised and retired downstream.
        $summary = collect($cna['descriptions'] ?? [])->firstWhere('lang', 'en')['value']
            ?? collect($cna['rejectedReasons'] ?? [])->firstWhere('lang', 'en')['value']
            ?? null;

        // CNA-supplied metrics first, then ADP enrichment (NVD/CISA attach
        // CVSS in containers.adp when the CNA supplied none) — concat order
        // makes the CNA value win per CVSS version, ADP fill the gaps.
        $metricSets = collect($cna['metrics'] ?? [])
            ->concat(collect($record['containers']['adp'] ?? [])->flatMap(fn ($adp) => $adp['metrics'] ?? []));

        [$v4Score, $v4Vector] = $this->firstMetric($metricSets, ['cvssV4_0']);
        [$v3Score, $v3Vector] = $this->firstMetric($metricSets, ['cvssV3_1', 'cvssV3_0']);
        [$v2Score, $v2Vector] = $this->firstMetric($metricSets, ['cvssV2_0']);

        $bestScore = $v4Score ?? $v3Score ?? $v2Score;

        $cwes = [];
        foreach ($cna['problemTypes'] ?? [] as $problemType) {
            foreach ($problemType['descriptions'] ?? [] as $desc) {
                if (! empty($desc['cweId'])) {
                    $cwes[] = $desc['cweId'];
                }
            }
        }

        $references = array_map(
            fn ($r) => ['type' => implode(',', $r['tags'] ?? []) ?: null, 'url' => $r['url'] ?? ''],
            $cna['references'] ?? [],
        );

        return new VulnerabilityData(
            vulnId: $id,
            source: 'mitre',
            summary: $summary !== null ? mb_substr($summary, 0, 255) : null,
            details: $summary,
            severity: $bestScore !== null ? SeverityLevel::fromCvssScore($bestScore) : SeverityLevel::Unknown,
            cvssV3Score: $v3Score,
            cvssV3Vector: $v3Vector,
            cvssV2Score: $v2Score,
            cvssV2Vector: $v2Vector,
            cvssV4Score: $v4Score,
            cvssV4Vector: $v4Vector,
            references: $references,
            cwes: array_values(array_unique($cwes)),
            sourcePublishedAt: isset($meta['datePublished']) ? new \DateTime($meta['datePublished']) : null,
            sourceModifiedAt: isset($meta['dateUpdated']) ? new \DateTime($meta['dateUpdated']) : null,
            sourceUrl: 'https://www.cve.org/CVERecord?id='.rawurlencode($id),
            rawDataChecksum: hash('sha256', json_encode($record)),
            extra: [
                'state' => $meta['state'] ?? null,
                // Raw CNA affects data — version entries here are freetext-ish
                // and CNA-specific, so they stay evidence in extra rather than
                // becoming affectedRanges the merger would treat as proof.
                'affected' => $cna['affected'] ?? [],
            ],
        );
    }

    /**
     * First metric set carrying any of the given CVSS keys → [score, vector].
     *
     * @param  \Illuminate\Support\Collection<int, array>  $metricSets
     * @param  string[]  $keys
     * @return array{0: ?float, 1: ?string}
     */
    private function firstMetric($metricSets, array $keys): array
    {
        foreach ($metricSets as $metric) {
            foreach ($keys as $key) {
                if (isset($metric[$key]['baseScore'])) {
                    return [(float) $metric[$key]['baseScore'], $metric[$key]['vectorString'] ?? null];
                }
            }
        }

        return [null, null];
    }
}
