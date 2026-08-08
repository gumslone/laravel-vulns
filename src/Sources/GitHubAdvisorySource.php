<?php

declare(strict_types=1);

namespace Gumslone\Vulns\Sources;

use Gumslone\Vulns\Data\PackageData;
use Gumslone\Vulns\Data\VulnerabilityData;
use Gumslone\Vulns\Severity as SeverityLevel;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Pool;

/**
 * GitHub Security Advisory Database adapter (GraphQL API).
 * https://docs.github.com/en/graphql/reference/objects#securityvulnerability
 *
 * Requires GITHUB_TOKEN (a classic PAT with no scopes is sufficient).
 */
class GitHubAdvisorySource extends AbstractSource
{
    private const ECOSYSTEM_MAP = [
        'composer' => 'COMPOSER',
        'npm' => 'NPM',
        'pip' => 'PIP',
        'pypi' => 'PIP',
        'maven' => 'MAVEN',
        'gradle' => 'MAVEN',
        'nuget' => 'NUGET',
        'go' => 'GO',
        'golang' => 'GO',
        'cargo' => 'RUST',
        'gem' => 'RUBYGEMS',
        'cocoapods' => 'SWIFT', // closest supported; CocoaPods itself is unsupported
    ];

    private const VULNERABILITIES_QUERY = <<<'GRAPHQL'
    query($ecosystem: SecurityAdvisoryEcosystem!, $package: String!, $cursor: String) {
      securityVulnerabilities(ecosystem: $ecosystem, package: $package, first: 100, after: $cursor) {
        pageInfo { hasNextPage endCursor }
        nodes {
          vulnerableVersionRange
          firstPatchedVersion { identifier }
          advisory {
            ghsaId
            summary
            description
            severity
            publishedAt
            updatedAt
            permalink
            identifiers { type value }
            references { url }
            cwes(first: 10) { nodes { cweId } }
            cvss { score vectorString }
          }
        }
      }
    }
    GRAPHQL;


    public function __construct(?Client $http = null, array $options = [], ?\Psr\Log\LoggerInterface $logger = null, ?\Psr\SimpleCache\CacheInterface $cache = null)
    {
        $this->boot($options, $logger, $cache);
        // A malformed "Bearer " header 401s even on public endpoints — only
        // send auth when a token is actually configured.
        $token = (string) $this->config('token');
        $this->http = $http ?? $this->makeClient(
            'https://api.github.com',
            $token !== '' ? ['Authorization' => 'Bearer '.$token] : [],
        );
    }

    public function name(): string
    {
        return 'github';
    }

    /**
     * Enabled even without a token: REPOSITORY advisories are public REST
     * (rate-limited but sufficient). The registry GraphQL feed still needs a
     * token — queryBatch skips it when none is configured.
     */
    public function isEnabled(): bool
    {
        return (bool) $this->config('enabled', true);
    }

    public function queryBatch(array $packages): array
    {
        $results = array_fill_keys(array_keys($packages), []);

        // key => cursor of the next page to fetch (null = first page)
        $hasToken = (bool) $this->config('token');
        $pending = [];
        foreach ($packages as $key => $package) {
            if (isset(self::ECOSYSTEM_MAP[$package->ecosystem])) {
                // The registry GraphQL feed requires authentication.
                if ($hasToken) {
                    $pending[$key] = null;
                }
            } elseif ($package->ecosystem === 'github' && str_contains($package->name, '/')) {
                // Repo-shaped packages (git submodules, apps declared by their
                // repository) aren't on any registry — but their repos can
                // publish REPOSITORY security advisories, which never appear
                // in the registry-scoped GraphQL feed (or OSV).
                $results[$key] = $this->repoAdvisories($package);
            }
        }

        // GitHub's GraphQL API returns HTTP 200 with a top-level `errors` array
        // (e.g. RATE_LIMITED) rather than a 4xx — those never reach the pool's
        // `rejected` handler, so track them and fail loudly at the end.
        $graphqlErrors = [];

        // Fail safe: a transport-level rejection must not read as "no known
        // vulnerabilities" for its package — collect rejections during the
        // pool rounds and throw once pagination has drained.
        $failed = 0;
        $requested = 0;
        $firstReason = null;

        // Each round fetches one page per pending package concurrently;
        // packages with further pages carry their cursor into the next round.
        while ($pending !== []) {
            $next = [];

            $requests = function () use ($pending, $packages) {
                foreach ($pending as $key => $cursor) {
                    $package = $packages[$key];
                    yield $key => fn () => $this->http->postAsync('/graphql', [
                        'json' => [
                            'query' => self::VULNERABILITIES_QUERY,
                            'variables' => [
                                'ecosystem' => self::ECOSYSTEM_MAP[$package->ecosystem],
                                'package' => $package->name,
                                'cursor' => $cursor,
                            ],
                        ],
                    ]);
                }
            };

            $pool = new Pool($this->http, $requests(), [
                'concurrency' => (int) $this->config('max_concurrency', 8),
                'fulfilled' => function ($response, $key) use (&$results, &$next, &$graphqlErrors, $packages) {
                    $data = json_decode($response->getBody()->getContents(), true) ?? [];

                    if (! empty($data['errors'])) {
                        $graphqlErrors[] = $data['errors'][0]['type'] ?? ($data['errors'][0]['message'] ?? 'unknown GraphQL error');

                        return;
                    }

                    $result = $data['data']['securityVulnerabilities'] ?? [];

                    foreach ($result['nodes'] ?? [] as $node) {
                        if ($vuln = $this->parseNode($node, $packages[$key]->ecosystem)) {
                            $results[$key][] = $vuln;
                        }
                    }

                    if ($result['pageInfo']['hasNextPage'] ?? false) {
                        $next[$key] = $result['pageInfo']['endCursor'];
                    }
                },
                'rejected' => function ($reason, $key) use ($packages, &$failed, &$firstReason) {
                    $failed++;
                    $message = $reason instanceof \Throwable ? $reason->getMessage() : (string) $reason;
                    $firstReason ??= $message;
                    $this->log('warning', '[vulns] GitHub Advisory query failed', [
                        'package' => $packages[$key]->name,
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
                'GitHub Advisory: %d of %d requests failed: %s', $failed, $requested, $firstReason,
            ));
        }

        // Surface a GraphQL-level failure (rate limit, bad query) so the
        // aggregator records it against the scan — but only throw when NOTHING
        // succeeded, so a transient error on one page doesn't discard the valid
        // advisories already collected for the rest of the batch.
        if ($graphqlErrors !== []) {
            $anyResults = array_sum(array_map('count', $results)) > 0;
            if (! $anyResults) {
                throw new \RuntimeException('GitHub GraphQL error: '.implode(', ', array_unique($graphqlErrors)));
            }
            $this->log('warning', '[vulns] GitHub Advisory partial failure', ['errors' => array_unique($graphqlErrors)]);
        }

        return $results;
    }

    public function fetchById(string $vulnId): ?VulnerabilityData
    {
        if (! str_starts_with($vulnId, 'GHSA-')) {
            return null;
        }

        try {
            $data = $this->graphql(
                <<<'GRAPHQL'
                query($ghsaId: String!) {
                  securityAdvisory(ghsaId: $ghsaId) {
                    ghsaId
                    summary
                    description
                    severity
                    publishedAt
                    updatedAt
                    permalink
                    identifiers { type value }
                    references { url }
                    cwes(first: 10) { nodes { cweId } }
                    cvss { score vectorString }
                  }
                }
                GRAPHQL,
                ['ghsaId' => $vulnId],
            );

            $advisory = $data['data']['securityAdvisory'] ?? null;

            return $advisory ? $this->parseAdvisory($advisory, [], null) : null;
        } catch (GuzzleException) {
            return null;
        }
    }

    /**
     * Advisories published ON a repository (REST; the GraphQL securityAdvisories
     * feed only covers registry packages). Example: GumCP's GHSA-c2wp-qw9x-94g7,
     * a critical RCE with no CVE and no registry ecosystem — invisible to every
     * other source.
     *
     * @return VulnerabilityData[]
     */
    private function repoAdvisories(PackageData $package): array
    {
        // Encode owner and repo individually — the '/' between them is a real
        // path separator, but anything inside a segment must not be able to
        // rewrite the request path.
        $path = '/repos/'.implode('/', array_map('rawurlencode', explode('/', $package->name, 2)))
            .'/security-advisories?per_page=100';

        $advisories = [];
        // Hard safety cap on Link-header pagination; log when it truncates.
        $maxPages = (int) $this->config('max_pages', 10);

        try {
            for ($page = 0; $path !== null && $page < $maxPages; $page++) {
                $response = $this->http->get($path);
                $advisories = array_merge($advisories, json_decode($response->getBody()->getContents(), true) ?? []);

                // RFC 5988 Link header: follow rel="next" until absent.
                $path = preg_match('/<([^>]+)>;\s*rel="next"/', $response->getHeaderLine('Link'), $m)
                    ? $m[1]
                    : null;
            }
        } catch (GuzzleException $e) {
            $this->log('warning', '[vulns] GitHub repo-advisory query failed', [
                'repo' => $package->name, 'error' => $e->getMessage(),
            ]);

            return [];
        }

        if ($path !== null) {
            $this->log('warning', '[vulns] GitHub repo-advisory pagination cap reached — results truncated', [
                'repo' => $package->name,
            ]);
        }

        $vulns = [];
        foreach ($advisories as $a) {
            if (($a['state'] ?? 'published') !== 'published') {
                continue;
            }

            // The repo's own vulnerability entry carries the range/patch info.
            $entry = collect($a['vulnerabilities'] ?? [])
                ->first(fn ($v) => strcasecmp($v['package']['name'] ?? '', $package->name) === 0)
                ?? ($a['vulnerabilities'][0] ?? []);
            $range = $entry['vulnerable_version_range'] ?? null;
            $patched = $entry['patched_versions'] ?? null;

            // Translate the REST shape into the GraphQL field names so both
            // advisory flavours share one mapper.
            $vuln = $this->parseAdvisory([
                'ghsaId' => $a['ghsa_id'] ?? null,
                'summary' => $a['summary'] ?? null,
                'description' => $a['description'] ?? null,
                'severity' => $a['severity'] ?? null,
                'publishedAt' => $a['published_at'] ?? null,
                'updatedAt' => $a['updated_at'] ?? null,
                'permalink' => $a['html_url'] ?? null,
                'identifiers' => $a['identifiers'] ?? [],
                'references' => [['url' => $a['html_url'] ?? '']],
                'cwes' => ['nodes' => array_map(fn ($c) => ['cweId' => $c['cwe_id'] ?? null], $a['cwes'] ?? [])],
                'cvss' => [
                    'score' => $a['cvss']['score'] ?? null,
                    'vectorString' => $a['cvss']['vector_string'] ?? null,
                ],
            ], array_filter([
                'range' => $range,
                'fixed' => $patched,
                'ecosystem' => 'github',
            ]) ? [array_filter(['range' => $range, 'fixed' => $patched, 'ecosystem' => 'github'])] : [], $patched);

            if ($vuln) {
                $vulns[] = $vuln;
            }
        }

        return $vulns;
    }

    private function graphql(string $query, array $variables): array
    {
        $response = $this->http->post('/graphql', [
            'json' => ['query' => $query, 'variables' => $variables],
        ]);

        return json_decode($response->getBody()->getContents(), true) ?? [];
    }

    private function parseNode(array $node, string $ecosystem): ?VulnerabilityData
    {
        $advisory = $node['advisory'] ?? null;
        if (! $advisory) {
            return null;
        }

        $range = array_filter([
            'range' => $node['vulnerableVersionRange'] ?? null,
            'fixed' => $node['firstPatchedVersion']['identifier'] ?? null,
            'ecosystem' => $ecosystem,
        ]);

        return $this->parseAdvisory($advisory, [$range], $node['firstPatchedVersion']['identifier'] ?? null);
    }

    private function parseAdvisory(array $advisory, array $ranges, ?string $fixedVersion): ?VulnerabilityData
    {
        if (empty($advisory['ghsaId'])) {
            return null;
        }

        // Prefer the CVE ID as the canonical identifier when available
        $aliases = array_column($advisory['identifiers'] ?? [], 'value');
        $cveId = collect($advisory['identifiers'] ?? [])->firstWhere('type', 'CVE')['value'] ?? null;
        $vulnId = $cveId ?? $advisory['ghsaId'];

        $cvssScore = isset($advisory['cvss']['score']) && $advisory['cvss']['score'] > 0
            ? (float) $advisory['cvss']['score']
            : null;

        $severity = $cvssScore !== null
            ? SeverityLevel::fromCvssScore($cvssScore)
            : SeverityLevel::fromLabel($advisory['severity'] ?? null);

        return new VulnerabilityData(
            vulnId: $vulnId,
            source: 'github',
            summary: $advisory['summary'] ?? null,
            details: $advisory['description'] ?? null,
            severity: $severity,
            cvssV3Score: $cvssScore,
            cvssV3Vector: $advisory['cvss']['vectorString'] ?? null,
            aliases: array_values(array_diff($aliases, [$vulnId])),
            affectedRanges: $ranges,
            references: array_map(fn ($r) => ['type' => null, 'url' => $r['url'] ?? ''], $advisory['references'] ?? []),
            cwes: array_column($advisory['cwes']['nodes'] ?? [], 'cweId'),
            isFixed: $fixedVersion !== null,
            fixedVersions: $fixedVersion ? [$fixedVersion] : [],
            sourcePublishedAt: isset($advisory['publishedAt']) ? new \DateTime($advisory['publishedAt']) : null,
            sourceModifiedAt: isset($advisory['updatedAt']) ? new \DateTime($advisory['updatedAt']) : null,
            sourceUrl: $advisory['permalink'] ?? null,
            rawDataChecksum: hash('sha256', json_encode($advisory)),
            extra: ['ghsa_id' => $advisory['ghsaId']],
        );
    }

}
