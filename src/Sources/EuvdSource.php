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
 * European Union Vulnerability Database (ENISA) adapter.
 * https://euvd.enisa.europa.eu/apidoc
 *
 * No API key required.
 */
class EuvdSource extends AbstractSource
{

    public function __construct(?Client $http = null, array $options = [], ?\Psr\Log\LoggerInterface $logger = null, ?\Psr\SimpleCache\CacheInterface $cache = null)
    {
        $this->boot($options, $logger, $cache);
        $this->http = $http ?? $this->makeClient(
            rtrim((string) $this->config('base_url', 'https://euvd.enisa.europa.eu/api'), '/').'/',
        );
    }

    public function name(): string
    {
        return 'euvd';
    }

    public function queryBatch(array $packages): array
    {
        $results = array_fill_keys(array_keys($packages), []);

        // Lookup is a product-name search (no version), so packages sharing
        // a name — e.g. the same dependency at different versions — share
        // one request.
        $keysByProduct = [];
        foreach ($packages as $key => $package) {
            $keysByProduct[$package->name][] = $key;
        }

        // The API's documented paging surface isn't reflected anywhere in the
        // shapes we consume, so request the largest page we know is accepted
        // and flag a full page as possible truncation instead of guessing at
        // parameters.
        $pageSize = 100;

        $requests = function () use ($keysByProduct, $pageSize) {
            foreach (array_keys($keysByProduct) as $product) {
                yield $product => fn () => $this->http->getAsync('search', [
                    'query' => ['product' => $product, 'size' => $pageSize],
                ]);
            }
        };

        // Fail safe: a rejected request must not read as "no known
        // vulnerabilities" for its product — collect rejections during the
        // pool run and throw once the pool has drained.
        $failed = 0;
        $firstReason = null;

        $pool = new Pool($this->http, $requests(), [
            'concurrency' => (int) $this->config('max_concurrency', 8),
            'fulfilled' => function ($response, $product) use (&$results, $keysByProduct, $pageSize) {
                $data = json_decode($response->getBody()->getContents(), true) ?? [];
                $items = $data['items'] ?? [];

                if (count($items) >= $pageSize) {
                    $this->log('warning', '[vulns] EUVD returned a full page — results may be truncated', [
                        'product' => $product,
                        'size' => $pageSize,
                    ]);
                }

                $vulns = array_values(array_filter(array_map(
                    [$this, 'parseItem'],
                    $items,
                )));

                foreach ($keysByProduct[$product] as $key) {
                    $results[$key] = $vulns;
                }
            },
            'rejected' => function ($reason, $product) use (&$failed, &$firstReason) {
                $failed++;
                $message = $reason instanceof \Throwable ? $reason->getMessage() : (string) $reason;
                $firstReason ??= $message;
                $this->log('warning', '[vulns] EUVD query failed', [
                    'product' => $product,
                    'error' => $message,
                ]);
            },
        ]);

        $pool->promise()->wait();

        if ($failed > 0) {
            throw new \RuntimeException(sprintf(
                'EUVD: %d of %d requests failed: %s', $failed, count($keysByProduct), $firstReason,
            ));
        }

        return $results;
    }

    public function fetchById(string $vulnId): ?VulnerabilityData
    {
        try {
            $response = $this->http->get('enisaid', ['query' => ['id' => $vulnId]]);
            $data = json_decode($response->getBody()->getContents(), true);

            return $data ? $this->parseItem($data) : null;
        } catch (GuzzleException) {
            return null;
        }
    }

    private function parseItem(array $item): ?VulnerabilityData
    {
        $euvdId = $item['id'] ?? null;
        if (! $euvdId) {
            return null;
        }

        // Prefer the CVE alias as the canonical identifier
        $aliases = array_values(array_filter(array_map('trim', explode("\n", $item['aliases'] ?? ''))));
        $cveId = collect($aliases)->first(fn ($a) => str_starts_with($a, 'CVE-'));
        $vulnId = $cveId ?? $euvdId;

        $score = isset($item['baseScore']) && $item['baseScore'] > 0 ? (float) $item['baseScore'] : null;

        $references = array_values(array_filter(array_map('trim', explode("\n", $item['references'] ?? ''))));

        return new VulnerabilityData(
            vulnId: $vulnId,
            source: 'euvd',
            summary: isset($item['description']) ? mb_substr($item['description'], 0, 255) : null,
            details: $item['description'] ?? null,
            severity: $score !== null ? SeverityLevel::fromCvssScore($score) : SeverityLevel::Unknown,
            cvssV3Score: $score,
            cvssV3Vector: $item['baseScoreVector'] ?? null,
            aliases: array_values(array_diff(array_merge($aliases, [$euvdId]), [$vulnId])),
            references: array_map(fn ($url) => ['type' => null, 'url' => $url], $references),
            sourcePublishedAt: isset($item['datePublished']) ? new \DateTime($item['datePublished']) : null,
            sourceModifiedAt: isset($item['dateUpdated']) ? new \DateTime($item['dateUpdated']) : null,
            sourceUrl: "https://euvd.enisa.europa.eu/vulnerability/{$euvdId}",
            rawDataChecksum: hash('sha256', json_encode($item)),
            extra: [
                'euvd_id' => $euvdId,
                'epss' => $item['epss'] ?? null,
                'exploited' => $item['exploitedSince'] ?? null,
            ],
        );
    }
}
