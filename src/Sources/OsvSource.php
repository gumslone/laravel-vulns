<?php

declare(strict_types=1);

namespace Gumslone\Vulns\Sources;

use Gumslone\Vulns\Data\PackageData;
use Gumslone\Vulns\Data\VulnerabilityData;
use Gumslone\Vulns\Severity as SeverityLevel;
use Gumslone\Vulns\Support\CvssCalculator;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Pool;

/**
 * Google OSV (Open Source Vulnerabilities) adapter.
 * API documentation: https://google.github.io/osv.dev/api/
 *
 * No API key required. Covers: npm, PyPI, Maven, Go, Rust, NuGet, Ruby, PHP, etc.
 */
class OsvSource extends AbstractSource
{
    /** OSV rejects querybatch requests with more than 1000 queries. */
    private const QUERYBATCH_MAX = 1000;


    private string $baseUrl;

    public function __construct(?Client $http = null, array $options = [], ?\Psr\Log\LoggerInterface $logger = null, ?\Psr\SimpleCache\CacheInterface $cache = null)
    {
        $this->boot($options, $logger, $cache);

        // Requests use relative paths ('v1/query') so a configured base_url
        // keeps its own path prefix — per RFC 3986 an absolute path like
        // '/v1/query' REPLACES the base_uri path entirely, which silently
        // broke every mirror/proxy base_url. Legacy configs baked '/v1' into
        // the base_url (the old absolute paths made it dead weight); strip it
        // so those configs keep working now that the paths carry 'v1/'.
        $base = rtrim((string) $this->config('base_url', 'https://api.osv.dev'), '/');
        if (str_ends_with($base, '/v1')) {
            $base = substr($base, 0, -3);
        }
        $this->baseUrl = rtrim($base, '/').'/';

        $this->http = $http ?? $this->makeClient($this->baseUrl, ['Content-Type' => 'application/json']);
    }

    public function name(): string
    {
        return 'osv';
    }

    public function queryPackage(PackageData $package): array
    {
        if (! $this->queryable($package)) {
            return [];
        }

        $payload = $this->queryPayload($package);
        $vulns = [];

        // The single-query endpoint pages exactly like querybatch: resend the
        // same query with the returned token until the last page.
        do {
            try {
                $response = $this->http->post('v1/query', ['json' => $payload]);
                $data = json_decode($response->getBody()->getContents(), true);
            } catch (GuzzleException $e) {
                $this->log('warning', '[vulns] OSV query failed', ['package' => $package->name, 'error' => $e->getMessage()]);

                // Fail safe: an unreachable feed must surface as an error the
                // caller records, not read as "no known vulnerabilities".
                throw new \RuntimeException("OSV query failed for {$package->name}: {$e->getMessage()}", 0, $e);
            }

            $vulns = array_merge($vulns, $this->parseVulns($data['vulns'] ?? []));
            $payload['page_token'] = $data['next_page_token'] ?? null;
        } while (! empty($payload['page_token']));

        return $vulns;
    }

    public function queryBatch(array $packages): array
    {
        $results = array_fill_keys(array_keys($packages), []);

        // querybatch returns minimal records ({id, modified}) per query, so
        // first collect the ids (and modified stamps) affecting each package…
        $idsByKey = array_fill_keys(array_keys($packages), []);
        $modifiedById = [];

        foreach (array_chunk($packages, self::QUERYBATCH_MAX, true) as $chunk) {
            // key => query payload; queries whose result reports another page
            // are resent with its page token until exhausted
            $pending = [];
            foreach ($chunk as $key => $package) {
                if ($this->queryable($package)) {
                    $pending[$key] = $this->queryPayload($package);
                }
            }

            while ($pending !== []) {
                $keys = array_keys($pending);

                try {
                    $response = $this->http->post('v1/querybatch', [
                        'json' => ['queries' => array_values($pending)],
                    ]);
                    $data = json_decode($response->getBody()->getContents(), true);
                } catch (GuzzleException $e) {
                    $this->log('warning', '[vulns] OSV batch query failed', ['error' => $e->getMessage()]);

                    // Fail safe: swallowing this would report every package in
                    // the batch as clean. Throw so VulnSearch records the
                    // source in errors() and results read as "under-reported".
                    throw new \RuntimeException("OSV batch query failed: {$e->getMessage()}", 0, $e);
                }

                // Results come back in query order
                $next = [];
                foreach (array_values($data['results'] ?? []) as $i => $result) {
                    if (! isset($keys[$i])) {
                        continue;
                    }
                    $key = $keys[$i];

                    foreach ($result['vulns'] ?? [] as $vuln) {
                        if (! empty($vuln['id'])) {
                            $idsByKey[$key][] = $vuln['id'];
                            $modifiedById[$vuln['id']] = (string) ($vuln['modified'] ?? '');
                        }
                    }

                    if (! empty($result['next_page_token'])) {
                        $next[$key] = $pending[$key];
                        $next[$key]['page_token'] = $result['next_page_token'];
                    }
                }

                $pending = $next;
            }
        }

        // …then hydrate each distinct id exactly once (a vulnerability shared
        // by many packages is fetched a single time) and fan back out.
        $vulnsById = $this->hydrateVulns($modifiedById);

        foreach ($idsByKey as $key => $ids) {
            foreach (array_unique($ids) as $id) {
                if (isset($vulnsById[$id])) {
                    $results[$key][] = $vulnsById[$id];
                }
            }
        }

        return $results;
    }

    /**
     * Turn minimal querybatch records into full vulnerability records.
     *
     * OSV bumps `modified` on every change, so id+modified identifies an
     * immutable payload: records seen before are served from cache and only
     * the rest are fetched, via a pooled set of concurrent requests.
     *
     * @param  array<string, string>  $modifiedById  vuln id => modified stamp
     * @return array<string, VulnerabilityData> id => vulnerability
     */
    private function hydrateVulns(array $modifiedById): array
    {
        if ($modifiedById === []) {
            return [];
        }

        $ttl = (int) $this->config('cache_ttl', 86400 * 7);
        $vulns = [];
        $misses = [];

        foreach ($modifiedById as $id => $modified) {
            $raw = $ttl > 0 ? $this->cache?->get($this->cacheKey($id, $modified)) : null;
            if (is_array($raw) && ($vuln = $this->parseVuln($raw))) {
                $vulns[$id] = $vuln;
            } else {
                $misses[] = $id;
            }
        }

        if ($misses === []) {
            return $vulns;
        }

        $requests = function () use ($misses) {
            foreach ($misses as $id) {
                yield $id => fn () => $this->http->getAsync('v1/vulns/'.rawurlencode($id));
            }
        };

        $pool = new Pool($this->http, $requests(), [
            'concurrency' => (int) $this->config('max_concurrency', 8),
            'fulfilled' => function ($response, string $id) use (&$vulns, $modifiedById, $ttl) {
                $data = json_decode($response->getBody()->getContents(), true) ?? [];
                if ($vuln = $this->parseVuln($data)) {
                    $vulns[$id] = $vuln;
                    if ($ttl > 0) {
                        $this->cache?->set($this->cacheKey($id, $modifiedById[$id]), $data, $ttl);
                    }
                }
            },
            'rejected' => function ($reason, string $id) {
                $this->log('warning', '[vulns] OSV vulnerability hydration failed', [
                    'vuln_id' => $id,
                    'error' => $reason instanceof \Throwable ? $reason->getMessage() : (string) $reason,
                ]);
            },
        ]);

        $pool->promise()->wait();

        return $vulns;
    }

    private function cacheKey(string $vulnId, string $modified): string
    {
        // '.' separators, not ':' — PSR-16 reserves {}()/\@: and strict
        // implementations (e.g. Symfony's Psr16Cache) throw on them.
        return 'vulns.osv.vuln.'.sha1($vulnId.'|'.$modified);
    }

    public function fetchById(string $vulnId): ?VulnerabilityData
    {
        try {
            $response = $this->http->get('v1/vulns/'.rawurlencode($vulnId));
            $data = json_decode($response->getBody()->getContents(), true);

            return $this->parseVuln($data);
        } catch (GuzzleException) {
            return null;
        }
    }

    private function parseVulns(array $vulns): array
    {
        return array_filter(array_map([$this, 'parseVuln'], $vulns));
    }

    /**
     * Map a raw OSV vulnerability record (the schema OSV serves and that
     * osv-scanner emits inline) into our DTO. Public so image scanning can
     * reuse the exact same parsing.
     */
    public function mapOsvRecord(array $record): ?VulnerabilityData
    {
        return $this->parseVuln($record);
    }

    private function parseVuln(array $v): ?VulnerabilityData
    {
        if (empty($v['id'])) {
            return null;
        }

        $cvssV4 = $this->extractCvss($v, '4');
        $cvssV3 = $this->extractCvss($v, '3');
        $cvssV2 = $this->extractCvss($v, '2');
        // Newest standard first — a v4-only advisory (increasingly common)
        // must still yield a severity.
        $bestScore = $cvssV4['score'] ?? $cvssV3['score'] ?? $cvssV2['score'];
        $severity = $bestScore !== null
            ? SeverityLevel::fromCvssScore((float) $bestScore)
            : SeverityLevel::Unknown;

        // OSV CVSS vectors carry no numeric score; GHSA records expose a
        // qualitative severity in database_specific — use it as a fallback.
        if ($severity === SeverityLevel::Unknown) {
            $severity = SeverityLevel::fromLabel($v['database_specific']['severity'] ?? null);
        }

        $ecosystems = [];
        $ranges = [];
        $fixedVers = [];
        $isFixed = false;

        foreach ($v['affected'] ?? [] as $affected) {
            $eco = $affected['package']['ecosystem'] ?? null;
            if ($eco) {
                $ecosystems[] = $eco;
            }

            foreach ($affected['ranges'] ?? [] as $range) {
                $ranges[] = $range;
                foreach ($range['events'] ?? [] as $event) {
                    if (isset($event['fixed'])) {
                        $isFixed = true;
                        $fixedVers[] = "{$eco}:{$event['fixed']}";
                    }
                }
            }
        }

        $rawChecksum = hash('sha256', json_encode($v));

        return new VulnerabilityData(
            vulnId: $v['id'],
            source: 'osv',
            summary: $v['summary'] ?? null,
            details: $v['details'] ?? null,
            severity: $severity,
            cvssV3Score: $cvssV3['score'] ? (float) $cvssV3['score'] : null,
            cvssV3Vector: $cvssV3['vector'] ?? null,
            cvssV2Score: $cvssV2['score'] ? (float) $cvssV2['score'] : null,
            cvssV2Vector: $cvssV2['vector'] ?? null,
            cvssV4Score: $cvssV4['score'] ? (float) $cvssV4['score'] : null,
            cvssV4Vector: $cvssV4['vector'] ?? null,
            aliases: $v['aliases'] ?? [],
            affectedEcosystems: array_unique($ecosystems),
            affectedRanges: $ranges,
            references: array_map(fn ($r) => ['type' => $r['type'] ?? null, 'url' => $r['url'] ?? ''], $v['references'] ?? []),
            cwes: array_column($v['database_specific']['cwe_ids'] ?? [], null),
            isFixed: $isFixed,
            fixedVersions: array_unique($fixedVers),
            sourcePublishedAt: isset($v['published']) ? new \DateTime($v['published']) : null,
            sourceModifiedAt: isset($v['modified']) ? new \DateTime($v['modified']) : null,
            sourceUrl: "https://osv.dev/vulnerability/{$v['id']}",
            rawDataChecksum: $rawChecksum,
            extra: ['database_specific' => $v['database_specific'] ?? []],
        );
    }

    private function extractCvss(array $v, string $majorVersion): array
    {
        foreach ($v['severity'] ?? [] as $sev) {
            if (str_starts_with($sev['type'] ?? '', "CVSS_V{$majorVersion}")) {
                // OSV's severity[].score is a CVSS *vector string* (e.g.
                // "CVSS:3.1/AV:N/AC:L/..."), never a bare number — compute the
                // base score from the vector rather than scraping digits.
                $vector = (string) ($sev['score'] ?? '');
                $score = $vector !== '' ? (new CvssCalculator)->baseScore($vector) : null;

                if ($score !== null) {
                    return ['score' => (string) $score, 'vector' => $vector];
                }
            }
        }

        return ['score' => null, 'vector' => null];
    }

    /**
     * Map internal ecosystem names to OSV ecosystem identifiers.
     */
    /**
     * Build the OSV query payload for a package. OS packages (deb/apk) are
     * queried by PURL — OSV resolves the distro release from the purl's
     * `distro=` qualifier, which name+ecosystem alone can't express — while
     * language ecosystems use the name+ecosystem+version form.
     *
     * @return array<string, mixed>
     */
    private function queryPayload(PackageData $package): array
    {
        if (in_array($package->ecosystem, ['deb', 'apk', 'rpm'], true) && $package->purl) {
            return ['package' => ['purl' => $package->purl]];
        }

        // A commit-pinned package outside OSV's registry ecosystems (a git
        // submodule, a repo-shaped app) has no registry coordinates — OSV
        // resolves the commit directly against advisory git ranges, which is
        // exactly how advisories for vendored apps are published.
        $noVersion = $package->version === null || $package->version === '';
        $hasCommit = $package->gitCommitHash !== null && $package->gitCommitHash !== '';
        if ($hasCommit && ($noVersion || $this->mapEcosystem($package->ecosystem) === null)) {
            return ['commit' => $package->gitCommitHash];
        }

        return [
            'version' => $package->version,
            'package' => [
                'name' => $package->name,
                'ecosystem' => $this->mapEcosystem($package->ecosystem),
            ],
        ];
    }

    private function mapEcosystem(string $ecosystem): ?string
    {
        return match ($ecosystem) {
            'composer' => 'Packagist',
            'npm' => 'npm',
            'pip' => 'PyPI',
            'pypi' => 'PyPI',
            'maven',
            'gradle' => 'Maven',
            'nuget' => 'NuGet',
            'go',
            'golang' => 'Go',
            'cargo' => 'crates.io',
            'gem' => 'RubyGems',
            'cocoapods' => 'CocoaPods',
            // Unknown ecosystems must NOT be guessed: one invalid ecosystem
            // 400s the entire querybatch, losing OSV for every package in it.
            default => null,
        };
    }

    /** Whether OSV can answer for this package at all. */
    private function queryable(\Gumslone\Vulns\Data\PackageData $package): bool
    {
        if (in_array($package->ecosystem, ['deb', 'apk', 'rpm'], true) && $package->purl) {
            return true;
        }
        if ($package->gitCommitHash) {
            return true;
        }

        return $this->mapEcosystem($package->ecosystem) !== null;
    }
}
