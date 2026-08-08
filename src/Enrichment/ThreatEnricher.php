<?php

declare(strict_types=1);

namespace Gumslone\Vulns\Enrichment;

use Gumslone\Vulns\Data\VulnerabilityData;
use GuzzleHttp\Client;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Psr\SimpleCache\CacheInterface;

/**
 * Stamps merged results with threat-intel signals that no advisory feed
 * carries: EPSS (FIRST.org's probability of exploitation in the wild within
 * 30 days — free, batched, no key) and CISA KEV (confirmed actively
 * exploited). Both key off CVE ids, so enrichment runs after the merge when
 * canonical ids are settled.
 *
 * A failing feed degrades gracefully: results come back un-enriched and the
 * failure is reported via errors() so VulnSearch can surface it — a missing
 * EPSS score must read as "unknown", never as "not exploited".
 */
class ThreatEnricher
{
    private const EPSS_BATCH = 100;

    private Client $http;

    /** @var array<string, string> feed => error message from the last apply */
    private array $errors = [];

    /** @param array<string, mixed> $options see config/vulns.php 'epss' and 'kev' */
    public function __construct(
        ?Client $http = null,
        private readonly array $options = [],
        private readonly LoggerInterface $logger = new NullLogger,
        private readonly ?CacheInterface $cache = null,
    ) {
        $this->http = $http ?? new Client(['timeout' => 30]);
    }

    public function epssEnabled(): bool
    {
        return (bool) ($this->options['epss']['enabled'] ?? true);
    }

    public function kevEnabled(): bool
    {
        return (bool) ($this->options['kev']['enabled'] ?? true);
    }

    /**
     * Enrich merged per-package results in place, one EPSS batch and one
     * cached KEV catalog for the whole set. Shape in = shape out.
     *
     * @param  array<array-key, VulnerabilityData[]>  $resultsByPackage
     * @return array<array-key, VulnerabilityData[]>
     */
    public function apply(array $resultsByPackage): array
    {
        $this->errors = [];
        if (! $this->epssEnabled() && ! $this->kevEnabled()) {
            return $resultsByPackage;
        }

        $cveIds = [];
        foreach ($resultsByPackage as $vulns) {
            foreach ($vulns as $vuln) {
                $canonical = $vuln->canonicalId();
                if (VulnerabilityData::isCveId($canonical)) {
                    $cveIds[strtoupper($canonical)] = true;
                }
            }
        }
        if ($cveIds === []) {
            return $resultsByPackage;
        }

        $epss = $this->epssEnabled() ? $this->epssScores(array_keys($cveIds)) : [];
        $kev = $this->kevEnabled() ? $this->kevIds() : [];

        return array_map(
            fn (array $vulns) => array_map(function (VulnerabilityData $vuln) use ($epss, $kev): VulnerabilityData {
                $cve = strtoupper($vuln->canonicalId());
                $scores = $epss[$cve] ?? null;
                $kevEntry = $kev[$cve] ?? null;
                if ($scores === null && $kevEntry === null) {
                    return $vuln;
                }

                return $vuln->withThreatSignals(
                    $scores['epss'] ?? null,
                    $scores['percentile'] ?? null,
                    $kevEntry !== null,
                    kevSince: isset($kevEntry['added']) ? new \DateTimeImmutable($kevEntry['added']) : null,
                    kevDueDate: isset($kevEntry['due']) ? new \DateTimeImmutable($kevEntry['due']) : null,
                    usedInRansomware: (bool) ($kevEntry['ransomware'] ?? false),
                );
            }, $vulns),
            $resultsByPackage,
        );
    }

    /**
     * Feed failures from the most recent apply(). Non-empty means results
     * are un- or partially enriched, not that the signals are absent.
     *
     * @return array<string, string> feed ('epss'|'kev') => error
     */
    public function errors(): array
    {
        return $this->errors;
    }

    /**
     * @param  string[]  $cveIds
     * @return array<string, array{epss: float, percentile: float}>
     */
    private function epssScores(array $cveIds): array
    {
        $ttl = (int) ($this->options['epss']['cache_ttl'] ?? 21600); // EPSS refreshes daily
        $baseUrl = rtrim((string) ($this->options['epss']['base_url'] ?? 'https://api.first.org/data/v1/epss'), '/');

        $scores = [];
        $misses = [];
        foreach ($cveIds as $cve) {
            $cached = $this->cache?->get('vulns.epss.'.$cve);
            if (is_array($cached)) {
                // Cached misses are [] so known-unscored CVEs aren't re-asked.
                if ($cached !== []) {
                    $scores[$cve] = $cached;
                }
            } else {
                $misses[] = $cve;
            }
        }

        foreach (array_chunk($misses, self::EPSS_BATCH) as $chunk) {
            try {
                $response = $this->http->get($baseUrl, [
                    'query' => ['cve' => implode(',', $chunk)],
                    'headers' => ['Accept' => 'application/json'],
                ]);
                $data = json_decode((string) $response->getBody(), true);
            } catch (\Throwable $e) {
                $this->logger->warning('[vulns] EPSS fetch failed', ['error' => $e->getMessage()]);
                $this->errors['epss'] = $e->getMessage();
                break;
            }

            // A 200 whose body isn't the expected JSON (an HTML outage page
            // behind a proxy) is a failed feed, NOT an authoritative "no
            // scores" — caching misses from it would poison the cache for a
            // whole TTL.
            if (! is_array($data) || ! array_key_exists('data', $data)) {
                $this->logger->warning('[vulns] EPSS returned a malformed body');
                $this->errors['epss'] = 'malformed response body';
                break;
            }

            $answered = [];
            foreach ($data['data'] ?? [] as $row) {
                $cve = strtoupper((string) ($row['cve'] ?? ''));
                if ($cve === '') {
                    continue;
                }
                $entry = ['epss' => (float) ($row['epss'] ?? 0), 'percentile' => (float) ($row['percentile'] ?? 0)];
                $scores[$cve] = $entry;
                $answered[$cve] = true;
                $this->cache?->set('vulns.epss.'.$cve, $entry, $ttl);
            }
            foreach ($chunk as $cve) {
                if (! isset($answered[$cve])) {
                    $this->cache?->set('vulns.epss.'.$cve, [], $ttl);
                }
            }
        }

        return $scores;
    }

    /**
     * The KEV catalog keyed by upper-case CVE id, with listing date, the US
     * federal remediation due date, and confirmed-ransomware use.
     *
     * @return array<string, array{added: ?string, due: ?string, ransomware: bool}>
     */
    private function kevIds(): array
    {
        $ttl = (int) ($this->options['kev']['cache_ttl'] ?? 21600);
        // New cache key ('catalog', not 'ids'): the cached shape changed from
        // booleans to detail arrays and stale booleans must not be trusted.
        $cached = $this->cache?->get('vulns.kev.catalog');
        if (is_array($cached)) {
            return $cached;
        }

        $url = (string) ($this->options['kev']['url']
            ?? 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json');

        try {
            $response = $this->http->get($url, ['headers' => ['Accept' => 'application/json']]);
            $data = json_decode((string) $response->getBody(), true);
        } catch (\Throwable $e) {
            $this->logger->warning('[vulns] KEV catalog fetch failed', ['error' => $e->getMessage()]);
            $this->errors['kev'] = $e->getMessage();

            return [];
        }

        // Same malformed-200 guard as EPSS: an HTML outage page must not be
        // cached as an empty catalog for a whole TTL.
        if (! is_array($data) || ! array_key_exists('vulnerabilities', $data)) {
            $this->logger->warning('[vulns] KEV catalog returned a malformed body');
            $this->errors['kev'] = 'malformed response body';

            return [];
        }

        $ids = [];
        foreach ($data['vulnerabilities'] as $entry) {
            if (! empty($entry['cveID'])) {
                $ids[strtoupper((string) $entry['cveID'])] = [
                    'added' => self::validDate($entry['dateAdded'] ?? null),
                    'due' => self::validDate($entry['dueDate'] ?? null),
                    'ransomware' => strcasecmp((string) ($entry['knownRansomwareCampaignUse'] ?? ''), 'Known') === 0,
                ];
            }
        }
        $this->cache?->set('vulns.kev.catalog', $ids, $ttl);

        return $ids;
    }

    /**
     * A parseable date string or null. One malformed date in one catalog row
     * must degrade that field, not blow up the entire enrichment.
     */
    private static function validDate(mixed $value): ?string
    {
        if (! is_string($value) || $value === '') {
            return null;
        }

        try {
            new \DateTimeImmutable($value);

            return $value;
        } catch (\Throwable) {
            return null;
        }
    }
}
