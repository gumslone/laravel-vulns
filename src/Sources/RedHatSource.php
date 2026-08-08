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

/**
 * Red Hat Security Data API adapter (free, no key required).
 * https://access.redhat.com/documentation/en-us/red_hat_security_data_api
 *
 * Lookup is by package NAME only — the API filters CVEs by the affected
 * RPM/source package and knows nothing about the caller's installed version.
 * Only meaningful for OS/rpm-ish ecosystems, but unknown names simply return
 * an empty list, so no ecosystem filter is applied here.
 */
class RedHatSource extends AbstractSource
{

    public function __construct(?Client $http = null, array $options = [], ?\Psr\Log\LoggerInterface $logger = null, ?\Psr\SimpleCache\CacheInterface $cache = null)
    {
        $this->boot($options, $logger, $cache);
        $this->http = $http ?? $this->makeClient(
            rtrim((string) $this->config('base_url', 'https://access.redhat.com/hydra/rest/securitydata'), '/').'/',
        );
    }

    public function name(): string
    {
        return 'redhat';
    }

    public function queryBatch(array $packages): array
    {
        $results = array_fill_keys(array_keys($packages), []);

        // Lookup is a package-name search (no version), so packages sharing
        // a name — e.g. the same dependency at different versions — share
        // one request.
        $keysByName = [];
        foreach ($packages as $key => $package) {
            $keysByName[$package->name][] = $key;
        }

        // The API pages via per_page/page; request one large page and flag a
        // full page as possible truncation instead of chasing page numbers
        // for a source that is a secondary evidence stream.
        $pageSize = (int) $this->config('page_size', 1000);

        $requests = function () use ($keysByName, $pageSize) {
            foreach (array_keys($keysByName) as $name) {
                yield $name => fn () => $this->http->getAsync('cve.json', [
                    'query' => ['package' => $name, 'per_page' => $pageSize],
                ]);
            }
        };

        // Fail safe: a rejected request must not read as "no known
        // vulnerabilities" for its package — collect rejections during the
        // pool run and throw once the pool has drained.
        $failed = 0;
        $firstReason = null;

        $pool = new Pool($this->http, $requests(), [
            'concurrency' => (int) $this->config('max_concurrency', 8),
            'fulfilled' => function ($response, $name) use (&$results, $keysByName, $pageSize) {
                $entries = json_decode($response->getBody()->getContents(), true) ?? [];

                if (count($entries) >= $pageSize) {
                    $this->log('warning', '[vulns] Red Hat returned a full page — results may be truncated', [
                        'package' => $name,
                        'per_page' => $pageSize,
                    ]);
                }

                $vulns = array_values(array_filter(array_map(
                    [$this, 'parseEntry'],
                    array_filter($entries, 'is_array'),
                )));

                foreach ($keysByName[$name] as $key) {
                    $results[$key] = $vulns;
                }
            },
            'rejected' => function ($reason, $name) use (&$failed, &$firstReason) {
                $failed++;
                $message = $reason instanceof \Throwable ? $reason->getMessage() : (string) $reason;
                $firstReason ??= $message;
                $this->log('warning', '[vulns] Red Hat query failed', [
                    'package' => $name,
                    'error' => $message,
                ]);
            },
        ]);

        $pool->promise()->wait();

        if ($failed > 0) {
            throw new \RuntimeException(sprintf(
                'Red Hat: %d of %d requests failed: %s', $failed, count($keysByName), $firstReason,
            ));
        }

        return $results;
    }

    public function fetchById(string $vulnId): ?VulnerabilityData
    {
        try {
            // Red Hat serves CVE detail pages under the uppercase id only.
            $response = $this->http->get('cve/'.rawurlencode(strtoupper($vulnId)).'.json');
            $data = json_decode($response->getBody()->getContents(), true);

            return is_array($data) ? $this->parseEntry($data) : null;
        } catch (BadResponseException $e) {
            // 404 is a semantic answer — "no such CVE in Red Hat's data" —
            // not a transport failure, so it maps to null rather than a throw.
            if ($e->getResponse()->getStatusCode() === 404) {
                return null;
            }

            $this->log('warning', '[vulns] Red Hat fetchById failed', ['id' => $vulnId, 'error' => $e->getMessage()]);

            throw new \RuntimeException("Red Hat: fetchById failed for {$vulnId}: {$e->getMessage()}", 0, $e);
        } catch (GuzzleException $e) {
            $this->log('warning', '[vulns] Red Hat fetchById failed', ['id' => $vulnId, 'error' => $e->getMessage()]);

            // Fail safe: an unreachable API must surface as an error the
            // caller records, not read as "unknown id".
            throw new \RuntimeException("Red Hat: fetchById failed for {$vulnId}: {$e->getMessage()}", 0, $e);
        }
    }

    /**
     * Map one Red Hat record to the normalised DTO. Two shapes exist:
     * the cve.json search rows (flat: CVE, severity, cvss3_score,
     * cvss3_scoring_vector, bugzilla_description, affected_packages) and the
     * cve/<id>.json detail document (name, threat_severity, nested cvss3
     * object, bugzilla.description / details[]).
     */
    private function parseEntry(array $entry): ?VulnerabilityData
    {
        $vulnId = $entry['CVE'] ?? $entry['name'] ?? null;
        if (! $vulnId) {
            return null;
        }

        $score = $entry['cvss3_score'] ?? $entry['cvss3']['cvss3_base_score'] ?? null;
        $score = ($score !== null && $score !== '') ? (float) $score : null;
        $vector = $entry['cvss3_scoring_vector'] ?? $entry['cvss3']['cvss3_scoring_vector'] ?? null;

        $summary = $entry['bugzilla_description'] ?? $entry['bugzilla']['description'] ?? null;
        if (($summary === null || $summary === '') && is_array($entry['details'] ?? null)) {
            $summary = implode(' ', $entry['details']);
        }

        // Red Hat's own qualitative label ("important", "moderate", …) is
        // its curated judgement — prefer it, and only fall back to deriving
        // the band from the CVSS score when no label was published.
        $severity = SeverityLevel::fromLabel($entry['severity'] ?? $entry['threat_severity'] ?? null);
        if ($severity === SeverityLevel::Unknown && $score !== null) {
            $severity = SeverityLevel::fromCvssScore($score);
        }

        // The detail document's references arrive as strings, occasionally
        // newline-joined — flatten before mapping to the reference shape.
        $references = [];
        foreach ((array) ($entry['references'] ?? []) as $reference) {
            foreach (explode("\n", (string) $reference) as $url) {
                if (trim($url) !== '') {
                    $references[] = ['type' => null, 'url' => trim($url)];
                }
            }
        }

        $cwes = [];
        if (preg_match_all('/CWE-\d+/', (string) ($entry['CWE'] ?? $entry['cwe'] ?? ''), $matches)) {
            $cwes = array_values(array_unique($matches[0]));
        }

        return new VulnerabilityData(
            vulnId: $vulnId,
            source: 'redhat',
            summary: $summary ? mb_substr($summary, 0, 255) : null,
            details: $summary ?: null,
            severity: $severity,
            cvssV3Score: $score,
            cvssV3Vector: $vector,
            // affected_packages are NEVRA strings scoped to Red Hat product
            // streams, not semver ranges — expressing them as ranges would
            // fabricate evidence, so they ride along in extra and the range
            // stays undeterminable ([]) for the evidence merge.
            affectedRanges: [],
            references: $references,
            cwes: $cwes,
            sourcePublishedAt: isset($entry['public_date']) ? new \DateTime($entry['public_date']) : null,
            sourceUrl: $entry['resource_url'] ?? "https://access.redhat.com/security/cve/{$vulnId}",
            rawDataChecksum: $this->checksum($entry),
            extra: [
                'affected_packages' => $entry['affected_packages'] ?? [],
                'advisories' => $entry['advisories'] ?? [],
            ],
        );
    }
}
