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

        $requests = function () use ($purls) {
            foreach ($purls as $key => $purl) {
                yield $key => fn () => $this->http->getAsync(
                    "/rest/orgs/{$this->orgId}/packages/".rawurlencode($purl).'/issues',
                    ['query' => ['version' => self::API_VERSION, 'limit' => 100]],
                );
            }
        };

        $pool = new Pool($this->http, $requests(), [
            'concurrency' => (int) $this->config('max_concurrency', 8),
            'fulfilled' => function ($response, $key) use (&$results, $packages) {
                $data = json_decode($response->getBody()->getContents(), true) ?? [];

                $results[$key] = array_values(array_filter(array_map(
                    fn (array $issue) => $this->parseIssue($issue, $packages[$key]),
                    $data['data'] ?? [],
                )));
            },
            'rejected' => function ($reason, $key) use ($packages) {
                $this->log('warning', '[vulns] Snyk query failed', [
                    'package' => $packages[$key]->name,
                    'error' => $reason instanceof \Throwable ? $reason->getMessage() : (string) $reason,
                ]);
            },
        ]);

        $pool->promise()->wait();

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
