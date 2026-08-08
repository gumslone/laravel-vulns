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
 * Snyk vulnerability database adapter (commercial, REST API).
 * https://apidocs.snyk.io/ — "List issues for a package" endpoint.
 *
 * Requires SNYK_API_TOKEN and SNYK_ORG_ID.
 */
class SnykSource extends AbstractSource
{
    private const API_VERSION = '2024-10-15';


    private ?string $orgId;

    public function __construct(private readonly PurlBuilder $purlBuilder, ?Client $http = null, array $options = [], ?\Psr\Log\LoggerInterface $logger = null, ?\Psr\SimpleCache\CacheInterface $cache = null)
    {
        $this->boot($options, $logger, $cache);
        $this->orgId = $this->config('org_id');
        $this->http = $http ?? $this->makeClient(
            rtrim((string) $this->config('base_url', 'https://api.snyk.io'), '/'),
            [
                'Accept' => 'application/vnd.api+json',
                'Authorization' => 'token '.$this->config('api_token'),
            ],
        );
    }

    public function name(): string
    {
        return 'snyk';
    }

    public function isEnabled(): bool
    {
        return (bool) $this->config('enabled', false)
            && (bool) $this->config('api_token')
            && (bool) $this->orgId;
    }

    public function queryBatch(array $packages): array
    {
        $results = array_fill_keys(array_keys($packages), []);

        $purls = [];
        foreach ($packages as $key => $package) {
            $purl = $package->purl ?? $this->purlBuilder->fromPackageArray($package->toArray());
            if ($purl && $package->version) {
                $purls[$key] = $purl; // Snyk's purl endpoint requires an exact version
            }
        }

        // key => request path for the package's next page. Page 1 is built
        // here; later pages come verbatim from the JSON:API `links.next`.
        $pending = [];
        foreach ($purls as $key => $purl) {
            $pending[$key] = "/rest/orgs/{$this->orgId}/packages/".rawurlencode($purl).'/issues'
                .'?version='.self::API_VERSION.'&limit=100';
        }

        // Fail safe: a rejected request must not read as "no known
        // vulnerabilities" for its package — collect rejections during the
        // pool run and throw once the pool has drained.
        $failed = 0;
        $requested = 0;
        $firstReason = null;

        // Hard safety cap on pagination rounds so a livelocked `links.next`
        // (or an absurdly large result) can't spin forever.
        $maxPages = (int) $this->config('max_pages', 10);

        for ($round = 0; $pending !== []; $round++) {
            if ($round >= $maxPages) {
                $this->log('warning', '[vulns] Snyk pagination cap reached — results truncated', [
                    'packages' => count($pending),
                ]);

                break;
            }

            $next = [];
            $requested += count($pending);

            $requests = function () use ($pending) {
                foreach ($pending as $key => $path) {
                    yield $key => fn () => $this->http->getAsync($path);
                }
            };

            $pool = new Pool($this->http, $requests(), [
                'concurrency' => (int) $this->config('max_concurrency', 8),
                'fulfilled' => function ($response, $key) use (&$results, &$next, $packages) {
                    $data = json_decode($response->getBody()->getContents(), true) ?? [];

                    $results[$key] = array_merge($results[$key], array_values(array_filter(array_map(
                        fn (array $issue) => $this->parseIssue($issue, $packages[$key]),
                        $data['data'] ?? [],
                    ))));

                    if (! empty($data['links']['next'])) {
                        $next[$key] = (string) $data['links']['next'];
                    }
                },
                'rejected' => function ($reason, $key) use ($packages, &$failed, &$firstReason) {
                    $failed++;
                    $message = $reason instanceof \Throwable ? $reason->getMessage() : (string) $reason;
                    $firstReason ??= $message;
                    $this->log('warning', '[vulns] Snyk query failed', [
                        'package' => $packages[$key]->name,
                        'error' => $message,
                    ]);
                },
            ]);

            $pool->promise()->wait();

            $pending = $next;
        }

        if ($failed > 0) {
            throw new \RuntimeException(sprintf(
                'Snyk: %d of %d requests failed: %s', $failed, $requested, $firstReason,
            ));
        }

        return $results;
    }

    public function fetchById(string $vulnId): ?VulnerabilityData
    {
        // Snyk's REST API is package-scoped; no public by-ID lookup endpoint.
        return null;
    }

    private function parseIssue(array $issue, PackageData $package): ?VulnerabilityData
    {
        $attrs = $issue['attributes'] ?? [];
        if (! $attrs) {
            return null;
        }

        // Prefer a CVE alias as the canonical ID, falling back to the Snyk key
        $problems = $attrs['problems'] ?? [];
        $aliases = array_values(array_filter(array_column($problems, 'id')));
        $cveId = collect($problems)->first(fn ($p) => ($p['source'] ?? '') === 'CVE')['id'] ?? null;
        $vulnId = $cveId ?? ($attrs['key'] ?? $issue['id'] ?? null);

        if (! $vulnId) {
            return null;
        }

        $cvss = collect($attrs['severities'] ?? [])->first(fn ($s) => isset($s['score']));

        $fixedVersions = [];
        foreach ($attrs['coordinates'] ?? [] as $coordinate) {
            foreach ($coordinate['remedies'] ?? [] as $remedy) {
                $fixedVersions = array_merge($fixedVersions, $remedy['details']['upgrade_package_versions'] ?? []);
            }
        }

        return new VulnerabilityData(
            vulnId: $vulnId,
            source: 'snyk',
            summary: $attrs['title'] ?? null,
            details: $attrs['description'] ?? null,
            severity: SeverityLevel::fromLabel($attrs['effective_severity_level'] ?? null),
            cvssV3Score: isset($cvss['score']) ? (float) $cvss['score'] : null,
            cvssV3Vector: $cvss['vector'] ?? null,
            aliases: array_values(array_diff($aliases, [$vulnId])),
            affectedEcosystems: [$package->ecosystem],
            references: [],
            isFixed: ! empty($fixedVersions),
            fixedVersions: array_values(array_unique($fixedVersions)),
            sourcePublishedAt: isset($attrs['created_at']) ? new \DateTime($attrs['created_at']) : null,
            sourceModifiedAt: isset($attrs['updated_at']) ? new \DateTime($attrs['updated_at']) : null,
            sourceUrl: 'https://security.snyk.io/vuln/'.($attrs['key'] ?? ''),
            rawDataChecksum: hash('sha256', json_encode($issue)),
            extra: ['snyk_key' => $attrs['key'] ?? null, 'type' => $attrs['type'] ?? null],
        );
    }

}
