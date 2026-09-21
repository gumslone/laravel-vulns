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
 * Red Hat Security Data API adapter (free, no key required).
 * https://access.redhat.com/documentation/en-us/red_hat_security_data_api
 *
 * Lookup is by package NAME only — the API filters CVEs by the affected
 * RPM/source package and knows nothing about the caller's installed version.
 * The search is by RPM NAME alone, so it is only asked about OS-level
 * packages (`ecosystems` option, default rpm/generic/unspecified): for a
 * language package the same name is a different piece of software — npm's
 * `tar`, `ws` or `http` would inherit the RPMs' CVEs, and with no version
 * ranges to judge by nothing could ever clear them. Pass `['*']` to ask
 * about everything regardless.
 */
class RedHatSource extends AbstractSource
{
    public function __construct(?Client $http = null, array $options = [], ?LoggerInterface $logger = null, ?CacheInterface $cache = null)
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

    public function supports(PackageData $package): bool
    {
        if ($this->rpmName($package) === '') {
            return false;
        }

        $ecosystems = array_map('strtolower', (array) $this->config('ecosystems', ['rpm', 'redhat', 'generic', '']));

        return in_array('*', $ecosystems, true) || in_array(strtolower($package->ecosystem), $ecosystems, true);
    }

    /** "redhat/openssl" (from pkg:rpm/redhat/openssl) → "openssl": the search knows bare RPM names. */
    private function rpmName(PackageData $package): string
    {
        $name = trim($package->name);

        return ($slash = strrpos($name, '/')) === false ? $name : substr($name, $slash + 1);
    }

    public function queryBatch(array $packages): array
    {
        $results = array_fill_keys(array_keys($packages), []);

        // Lookup is a package-name search (no version), so packages sharing
        // a name — e.g. the same dependency at different versions — share
        // one request.
        $keysByName = [];
        foreach ($packages as $key => $package) {
            if ($this->supports($package)) {
                $keysByName[$this->rpmName($package)][] = $key;
            }
        }

        $pageSize = max(1, (int) $this->config('page_size', 1000));
        $maxPages = max(1, (int) $this->config('max_pages', 10));

        // Fail safe: a rejected or unreadable page must not read as "no known
        // vulnerabilities" for its package — collect failures during the
        // pool rounds and throw once they have drained.
        $failed = 0;
        $requested = 0;
        $firstReason = null;
        $entriesByName = array_fill_keys(array_keys($keysByName), []);

        // The API pages via per_page/page (1-based); a full page means more.
        $pending = array_fill_keys(array_keys($keysByName), 1);
        while ($pending !== []) {
            $next = [];
            $requests = function () use ($pending, $pageSize) {
                foreach ($pending as $name => $page) {
                    yield $name => fn () => $this->http->getAsync('cve.json', [
                        'query' => ['package' => (string) $name, 'per_page' => $pageSize] + ($page > 1 ? ['page' => $page] : []),
                    ]);
                }
            };

            $pool = new Pool($this->http, $requests(), [
                'concurrency' => (int) $this->config('max_concurrency', 8),
                'fulfilled' => function ($response, $name) use (&$entriesByName, &$next, &$failed, &$firstReason, $pending, $keysByName, $pageSize, $maxPages) {
                    $entries = json_decode($response->getBody()->getContents(), true);
                    if (! is_array($entries)) {
                        $failed++;
                        $firstReason ??= 'the response was not valid JSON';

                        return;
                    }

                    $entriesByName[$name] = array_merge($entriesByName[$name], $entries);

                    if (count($entries) < $pageSize) {
                        return; // a short page is the last one
                    }
                    if ($pending[$name] >= $maxPages) {
                        $this->warn(
                            sprintf('results for "%s" truncated at %d CVEs (max_pages=%d)', $name, count($entriesByName[$name]), $maxPages),
                            [], $keysByName[$name],
                        );

                        return;
                    }
                    $next[$name] = $pending[$name] + 1;
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

            $requested += count($pending);
            $pool->promise()->wait();
            $pending = $next;
        }

        if ($failed > 0) {
            throw new \RuntimeException(sprintf(
                'Red Hat: %d of %d requests failed: %s', $failed, $requested, $firstReason,
            ));
        }

        foreach ($entriesByName as $name => $entries) {
            $vulns = array_values(array_filter(array_map(
                [$this, 'parseEntry'],
                array_filter($entries, 'is_array'),
            )));

            foreach ($keysByName[$name] as $key) {
                $results[$key] = $vulns;
            }
        }

        return $results;
    }

    public function fetchById(string $vulnId): ?VulnerabilityData
    {
        try {
            // Red Hat serves CVE detail pages under the uppercase id only.
            $response = $this->http->get('cve/'.rawurlencode(strtoupper($vulnId)).'.json');

            return $this->parseEntry($this->decode($response, "Red Hat lookup of {$vulnId}"));
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
