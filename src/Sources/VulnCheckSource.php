<?php

declare(strict_types=1);

namespace Gumslone\Vulns\Sources;

use Gumslone\Vulns\Data\VulnerabilityData;
use Gumslone\Vulns\Severity as SeverityLevel;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\BadResponseException;
use GuzzleHttp\Exception\GuzzleException;

/**
 * VulnCheck Community API adapter — https://api.vulncheck.com/v3.
 *
 * Requires a (free) API token, so the source is config-gated like Snyk:
 * disabled unless both `enabled` and `api_token` are set.
 *
 * The community tier exposes CVE-id-indexed indexes; we query the NVD-2 index
 * (GET index/nist-nvd2?cve=CVE-...) exactly like the reference GumVulns
 * implementation, and its `data` array carries NVD-2.0-shaped CVE records, so
 * the field mapping mirrors NvdSource's (metrics cvssMetricV31/V30/V2/V40,
 * weaknesses, references, configurations).
 */
class VulnCheckSource extends AbstractSource
{
    public function __construct(?Client $http = null, array $options = [], ?\Psr\Log\LoggerInterface $logger = null, ?\Psr\SimpleCache\CacheInterface $cache = null)
    {
        $this->boot($options, $logger, $cache);
        $this->http = $http ?? $this->makeClient(
            rtrim((string) $this->config('base_url', 'https://api.vulncheck.com/v3'), '/').'/',
        );
    }

    public function name(): string
    {
        return 'vulncheck';
    }

    public function isEnabled(): bool
    {
        return (bool) $this->config('enabled', false)
            && (bool) $this->config('api_token');
    }

    /**
     * Always empty, without any HTTP traffic: the community-tier indexes are
     * queried by CVE id (`index/nist-nvd2?cve=...`), there is no package-
     * coordinate search — matching the reference implementation, which only
     * builds requests for CVE-id queries. This source hydrates ids seen
     * elsewhere via fetchById. Every input key is still present so callers
     * can attribute per-package outcomes uniformly.
     */
    public function queryBatch(array $packages): array
    {
        return array_fill_keys(array_keys($packages), []);
    }

    public function fetchById(string $vulnId): ?VulnerabilityData
    {
        // CVE-id-indexed APIs are case-sensitive; normalize like the CVE list.
        $vulnId = strtoupper($vulnId);

        try {
            // The Bearer header rides on the request (not only the default
            // client) so an injected client — the test seam — still sends it.
            $response = $this->http->get('index/nist-nvd2', [
                'query' => ['cve' => $vulnId],
                'headers' => ['Authorization' => 'Bearer '.$this->config('api_token')],
            ]);
        } catch (BadResponseException $e) {
            // An unknown id is a semantic miss, not an outage
            if ($e->getResponse()->getStatusCode() === 404) {
                return null;
            }

            $this->log('warning', '[vulns] VulnCheck fetch failed', ['id' => $vulnId, 'error' => $e->getMessage()]);

            throw new \RuntimeException("VulnCheck: fetch of {$vulnId} failed: {$e->getMessage()}", 0, $e);
        } catch (GuzzleException $e) {
            $this->log('warning', '[vulns] VulnCheck fetch failed', ['id' => $vulnId, 'error' => $e->getMessage()]);

            throw new \RuntimeException("VulnCheck: fetch of {$vulnId} failed: {$e->getMessage()}", 0, $e);
        }

        $data = json_decode($response->getBody()->getContents(), true);
        $cve = $data['data'][0] ?? null;

        return is_array($cve) ? $this->parseCve($cve) : null;
    }

    /** Map one NVD-2.0-shaped record (as served in the index's `data` array). */
    private function parseCve(array $cve): ?VulnerabilityData
    {
        if (empty($cve['id'])) {
            return null;
        }

        $description = collect($cve['descriptions'] ?? [])->firstWhere('lang', 'en')['value'] ?? null;

        [$v3Score, $v3Vector] = $this->extractCvss($cve['metrics'] ?? [], ['cvssMetricV31', 'cvssMetricV30']);
        [$v2Score, $v2Vector] = $this->extractCvss($cve['metrics'] ?? [], ['cvssMetricV2']);
        [$v4Score, $v4Vector] = $this->extractCvss($cve['metrics'] ?? [], ['cvssMetricV40']);

        $bestScore = $v4Score ?? $v3Score ?? $v2Score;

        $cwes = [];
        foreach ($cve['weaknesses'] ?? [] as $weakness) {
            foreach ($weakness['description'] ?? [] as $desc) {
                if (str_starts_with($desc['value'] ?? '', 'CWE-')) {
                    $cwes[] = $desc['value'];
                }
            }
        }

        $references = array_map(
            fn ($r) => ['type' => implode(',', $r['tags'] ?? []) ?: null, 'url' => $r['url'] ?? ''],
            $cve['references'] ?? [],
        );

        return new VulnerabilityData(
            vulnId: $cve['id'],
            source: 'vulncheck',
            summary: $description ? mb_substr($description, 0, 255) : null,
            details: $description,
            severity: $bestScore !== null ? SeverityLevel::fromCvssScore($bestScore) : SeverityLevel::Unknown,
            cvssV3Score: $v3Score,
            cvssV3Vector: $v3Vector,
            cvssV2Score: $v2Score,
            cvssV2Vector: $v2Vector,
            cvssV4Score: $v4Score,
            cvssV4Vector: $v4Vector,
            affectedRanges: $this->configurationRanges($cve['configurations'] ?? []),
            references: $references,
            cwes: array_values(array_unique($cwes)),
            sourcePublishedAt: isset($cve['published']) ? new \DateTime($cve['published']) : null,
            sourceModifiedAt: isset($cve['lastModified']) ? new \DateTime($cve['lastModified']) : null,
            sourceUrl: 'https://vulncheck.com/cve/'.rawurlencode((string) $cve['id']),
            rawDataChecksum: hash('sha256', json_encode($cve)),
            extra: ['vuln_status' => $cve['vulnStatus'] ?? null],
        );
    }

    /**
     * First populated metric among the given NVD 2.0 metric keys →
     * [score, vector] (keys are tried in preference order, e.g. V31 over V30).
     *
     * @param  string[]  $keys
     * @return array{0: ?float, 1: ?string}
     */
    private function extractCvss(array $metrics, array $keys): array
    {
        foreach ($keys as $key) {
            $data = $metrics[$key][0]['cvssData'] ?? null;
            if ($data) {
                return [(float) $data['baseScore'], $data['vectorString'] ?? null];
            }
        }

        return [null, null];
    }

    /**
     * NVD `configurations` nodes → constraint strings VersionRange can parse
     * (same shape NvdSource emits), so range evidence merges identically no
     * matter which of the two NVD-shaped sources delivered the record.
     *
     * @return array<int, array{range: string, source: string}>
     */
    private function configurationRanges(array $configurations): array
    {
        $ranges = [];
        foreach ($configurations as $config) {
            foreach ($config['nodes'] ?? [] as $node) {
                foreach ($node['cpeMatch'] ?? [] as $match) {
                    if (($match['vulnerable'] ?? true) === false) {
                        continue;
                    }

                    $clauses = [];
                    foreach ([
                        'versionStartIncluding' => '>=', 'versionStartExcluding' => '>',
                        'versionEndIncluding' => '<=', 'versionEndExcluding' => '<',
                    ] as $key => $op) {
                        if (isset($match[$key])) {
                            $clauses[] = "{$op} {$match[$key]}";
                        }
                    }

                    if ($clauses === []) {
                        // Exact version pinned in the CPE itself?
                        $cpeVersion = explode(':', (string) ($match['criteria'] ?? ''))[5] ?? '*';
                        if ($cpeVersion !== '*' && $cpeVersion !== '-' && $cpeVersion !== '') {
                            $clauses[] = "= {$cpeVersion}";
                        }
                    }

                    if ($clauses !== []) {
                        $ranges[] = ['range' => implode(', ', $clauses), 'source' => $this->name()];
                    }
                }
            }
        }

        return $ranges;
    }
}
