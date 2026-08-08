<?php

declare(strict_types=1);

namespace Gumslone\Vulns\Sources;

use Gumslone\Vulns\Data\PackageData;
use Gumslone\Vulns\Data\VulnerabilityData;
use Gumslone\Vulns\Severity as SeverityLevel;
use Gumslone\Vulns\Support\PurlBuilder;
use GuzzleHttp\Client;
use GuzzleHttp\Pool;

/**
 * Sonatype OSS Index adapter — the free component-report API.
 * https://ossindex.sonatype.org/rest
 *
 * Works anonymously; optional basic auth (username + API token) raises the
 * rate limits. Lookups are purl-coordinate based, so an exact version is
 * required — there is no name-only or by-CVE search surface.
 */
class OssIndexSource extends AbstractSource
{
    /**
     * The API rejects component-report requests with more than 128
     * coordinates, so larger batches are split into multiple POSTs.
     */
    private const MAX_COORDINATES = 128;

    public function __construct(private readonly PurlBuilder $purlBuilder, ?Client $http = null, array $options = [], ?\Psr\Log\LoggerInterface $logger = null, ?\Psr\SimpleCache\CacheInterface $cache = null)
    {
        $this->boot($options, $logger, $cache);

        // Auth is optional: anonymous requests work but are rate-limited
        // harder. Only send the header when BOTH halves are configured — a
        // lone username/token would just earn a 401 on every request.
        $username = (string) $this->config('username', '');
        $token = (string) $this->config('api_token', '');
        $headers = [];
        if ($username !== '' && $token !== '') {
            $headers['Authorization'] = 'Basic '.base64_encode("{$username}:{$token}");
        }

        $this->http = $http ?? $this->makeClient(
            rtrim((string) $this->config('base_url', 'https://ossindex.sonatype.org/api/v3'), '/').'/',
            $headers,
        );
    }

    public function name(): string
    {
        return 'oss_index';
    }

    public function queryBatch(array $packages): array
    {
        $results = array_fill_keys(array_keys($packages), []);

        // coordinate => input keys. Several inputs can share one coordinate
        // (same dependency reachable through different manifests) — they all
        // receive the same report. Versionless packages are skipped, not
        // failed: the API only answers exact coordinates, so there is
        // nothing to ask.
        $keysByCoordinate = [];
        foreach ($packages as $key => $package) {
            $purl = $package->purl ?? $this->purlBuilder->fromPackageArray($package->toArray());
            if ($purl && $package->version) {
                $keysByCoordinate[$purl][] = $key;
            }
        }

        if ($keysByCoordinate === []) {
            return $results;
        }

        // The response echoes each coordinate; index on a normalised form
        // (lowercase, percent-decoded, qualifiers/subpath stripped) because
        // the server canonicalises purl case AND encoding — an exact-string
        // match would silently drop those reports.
        $coordinateAliases = [];
        foreach (array_keys($keysByCoordinate) as $coordinate) {
            $coordinateAliases[self::normalizeCoordinate($coordinate)] = $coordinate;
        }

        $chunks = array_chunk(array_keys($keysByCoordinate), self::MAX_COORDINATES);

        $requests = function () use ($chunks) {
            foreach ($chunks as $index => $coordinates) {
                yield $index => fn () => $this->http->postAsync('component-report', [
                    'json' => ['coordinates' => $coordinates],
                ]);
            }
        };

        // Fail safe: a rejected request must not read as "no known
        // vulnerabilities" for its coordinates — collect rejections during
        // the pool run and throw once the pool has drained.
        $failed = 0;
        $firstReason = null;

        $pool = new Pool($this->http, $requests(), [
            'concurrency' => (int) $this->config('max_concurrency', 4),
            'fulfilled' => function ($response) use (&$results, $packages, $keysByCoordinate, $coordinateAliases) {
                $reports = json_decode($response->getBody()->getContents(), true) ?? [];

                foreach ($reports as $report) {
                    if (! is_array($report)) {
                        continue;
                    }

                    $coordinate = $coordinateAliases[self::normalizeCoordinate((string) ($report['coordinates'] ?? ''))] ?? null;
                    $keys = $coordinate !== null ? ($keysByCoordinate[$coordinate] ?? []) : [];
                    if ($keys === []) {
                        continue;
                    }

                    // All keys behind one coordinate carry the same purl type,
                    // hence the same ecosystem — safe to read off the first.
                    $ecosystem = $packages[$keys[0]]->ecosystem;

                    $vulns = array_values(array_filter(array_map(
                        fn (array $vuln) => $this->parseVulnerability($vuln, $ecosystem),
                        array_filter($report['vulnerabilities'] ?? [], 'is_array'),
                    )));

                    foreach ($keys as $key) {
                        $results[$key] = $vulns;
                    }
                }
            },
            'rejected' => function ($reason, $index) use (&$failed, &$firstReason) {
                $failed++;
                $message = $reason instanceof \Throwable ? $reason->getMessage() : (string) $reason;
                $firstReason ??= $message;
                $this->log('warning', '[vulns] OSS Index query failed', [
                    'chunk' => $index,
                    'error' => $message,
                ]);
            },
        ]);

        $pool->promise()->wait();

        if ($failed > 0) {
            throw new \RuntimeException(sprintf(
                'OSS Index: %d of %d requests failed: %s', $failed, count($chunks), $firstReason,
            ));
        }

        return $results;
    }

    public function fetchById(string $vulnId): ?VulnerabilityData
    {
        // OSS Index is coordinate-scoped only; no public by-CVE/by-ID lookup.
        return null;
    }

    private function parseVulnerability(array $vuln, string $ecosystem): ?VulnerabilityData
    {
        // Prefer the CVE as the canonical, cross-source identifier; the
        // displayName ("sonatype-2020-1214" for non-CVE findings) beats the
        // raw id, which is an opaque UUID nobody can look up elsewhere.
        $vulnId = $vuln['cve'] ?? $vuln['displayName'] ?? $vuln['id'] ?? null;
        if (! $vulnId) {
            return null;
        }

        $score = isset($vuln['cvssScore']) ? (float) $vuln['cvssScore'] : null;
        $vector = $vuln['cvssVector'] ?? null;

        // OSS Index publishes one bare score + vector pair without saying
        // which CVSS standard it is — the vector prefix decides. Unprefixed
        // vectors carrying the Authentication (Au:) metric are CVSS v2 (v3
        // replaced Au with PR); with no vector at all the score lands in the
        // v3 column, the API's dominant convention.
        [$v2Score, $v2Vector, $v3Score, $v3Vector, $v4Score, $v4Vector] = match (true) {
            $vector === null => [null, null, $score, null, null, null],
            str_starts_with($vector, 'CVSS:4.0') => [null, null, null, null, $score, $vector],
            str_starts_with($vector, 'CVSS:3') => [null, null, $score, $vector, null, null],
            str_contains($vector, 'Au:') => [$score, $vector, null, null, null, null],
            default => [null, null, $score, $vector, null, null],
        };

        $references = array_values(array_filter(array_merge(
            [$vuln['reference'] ?? null],
            $vuln['externalReferences'] ?? [],
        )));

        // Keep every other identifier as an alias so cross-source
        // deduplication can still connect the report to the same advisory.
        $aliases = array_values(array_unique(array_diff(
            array_filter([$vuln['cve'] ?? null, $vuln['displayName'] ?? null]),
            [$vulnId],
        )));

        $cwes = [];
        if (preg_match_all('/CWE-\d+/', (string) ($vuln['cwe'] ?? ''), $matches)) {
            $cwes = array_values(array_unique($matches[0]));
        }

        return new VulnerabilityData(
            vulnId: $vulnId,
            source: 'oss_index',
            summary: isset($vuln['title']) ? mb_substr($vuln['title'], 0, 255) : null,
            details: $vuln['description'] ?? null,
            severity: $score !== null ? SeverityLevel::fromCvssScore($score) : SeverityLevel::Unknown,
            cvssV3Score: $v3Score,
            cvssV3Vector: $v3Vector,
            cvssV2Score: $v2Score,
            cvssV2Vector: $v2Vector,
            cvssV4Score: $v4Score,
            cvssV4Vector: $v4Vector,
            aliases: $aliases,
            affectedEcosystems: [$ecosystem],
            references: array_map(fn ($url) => ['type' => null, 'url' => $url], $references),
            cwes: $cwes,
            sourceUrl: $vuln['reference'] ?? null,
            rawDataChecksum: $this->checksum($vuln),
            extra: ['oss_index_id' => $vuln['id'] ?? null],
        );
    }

    /**
     * Sonatype requires authentication since 2025 — anonymous requests 401.
     * Gate on credentials like Snyk so the default config doesn't record an
     * oss_index error on every single search.
     */
    public function isEnabled(): bool
    {
        return parent::isEnabled()
            && $this->config('username') !== null
            && $this->config('api_token') !== null;
    }

    /**
     * Coordinate comparison form: the server canonicalises case, percent-
     * encoding, and strips qualifiers — compare what survives all three.
     */
    private static function normalizeCoordinate(string $coordinate): string
    {
        $bare = preg_split('/[?#]/', $coordinate, 2)[0];

        return strtolower(rawurldecode($bare));
    }
}
