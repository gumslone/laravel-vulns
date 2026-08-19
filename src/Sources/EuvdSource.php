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
        // The API lives on the euvdservices host; the euvd.enisa.europa.eu
        // domain answers /api/* with the SPA's HTML shell (HTTP 200), which
        // would silently parse to zero results.
        $this->http = $http ?? $this->makeClient(
            rtrim((string) $this->config('base_url', 'https://euvdservices.enisa.europa.eu/api'), '/').'/',
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
            'fulfilled' => function ($response, $product) use (&$results, &$failed, &$firstReason, $keysByProduct, $packages, $pageSize) {
                $data = json_decode($response->getBody()->getContents(), true);

                // A 200 whose body isn't the expected JSON (the SPA's HTML
                // shell, a proxy outage page) is a failed request, not an
                // authoritative "no vulnerabilities".
                if (! is_array($data) || ! array_key_exists('items', $data)) {
                    $failed++;
                    $firstReason ??= 'malformed response body';
                    $this->log('warning', '[vulns] EUVD returned a malformed body', ['product' => $product]);

                    return;
                }
                $items = $data['items'];

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

                // The search matched by product NAME only; drop advisories the
                // queried version provably escapes. Fail-safe: an advisory is
                // only dropped when its ranges for THIS product parsed cleanly
                // and none matched — unparseable or missing version text keeps
                // the advisory ("can't tell" must not read as "not affected").
                foreach ($keysByProduct[$product] as $key) {
                    $results[$key] = array_values(array_filter(
                        $vulns,
                        fn (VulnerabilityData $vuln) => $this->versionMayBeAffected($vuln, $product, $packages[$key]->version),
                    ));
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

        [$ranges, $fixedVersions] = $this->productRanges($item);

        return new VulnerabilityData(
            vulnId: $vulnId,
            source: 'euvd',
            summary: isset($item['description']) ? mb_substr($item['description'], 0, 255) : null,
            details: $item['description'] ?? null,
            severity: $score !== null ? SeverityLevel::fromCvssScore($score) : SeverityLevel::Unknown,
            cvssV3Score: $score,
            cvssV3Vector: $item['baseScoreVector'] ?? null,
            aliases: array_values(array_diff(array_merge($aliases, [$euvdId]), [$vulnId])),
            affectedRanges: $ranges,
            isFixed: $fixedVersions !== [],
            fixedVersions: $fixedVersions,
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

    /**
     * Affected ranges (and fixed versions) from the advisory's product list.
     * EUVD flattens the CVE v5 affected data into free-text
     * `enisaIdProduct[].product_version` strings — the version constraints
     * only exist inside those strings, so they are regex-extracted. Every
     * entry keeps the raw text and its product name: an unparseable string
     * still marks the product as "constraint exists but unknown", which the
     * version filter must treat as possibly affected.
     *
     * @return array{0: array<int, array<string, mixed>>, 1: string[]} [ranges, fixedVersions]
     */
    private function productRanges(array $item): array
    {
        $ranges = [];
        $fixed = [];

        foreach ($item['enisaIdProduct'] ?? [] as $entry) {
            $product = trim((string) ($entry['product']['name'] ?? ''));
            $raw = trim((string) ($entry['product_version'] ?? ''));
            if ($raw === '') {
                continue;
            }

            // "patch: X" entries are fix metadata, not affected ranges.
            if (preg_match('/^patch(?:ed)?\s*:\s*(\S+)$/iu', $raw, $m)) {
                $fixed[] = $m[1];

                continue;
            }

            $ranges[] = array_filter([
                'range' => self::constraintFromText($raw),
                'raw' => $raw,
                'product' => $product !== '' ? $product : null,
                'source' => 'euvd',
            ], fn ($v) => $v !== null);
        }

        return [$ranges, array_values(array_unique($fixed))];
    }

    /**
     * Constraint string ("＞= a, < b" grammar VersionRange understands) from
     * one EUVD product_version text, or null when the text doesn't parse.
     *
     * Observed live grammar (start bound then bounded end, Unicode or ASCII
     * operators; prefixes are module names, not versions):
     *   "2.13.1 <2.25.5"      → ">= 2.13.1, < 2.25.5"
     *   "0 ≤1.8.3"            → "<= 1.8.3"
     *   "log4j-core <2.17.1"  → "< 2.17.1"
     *   "log4j-core 2.13.0"   → "= 2.13.0"
     *   "Apache Log4j 1.2.x"  → ">= 1.2, < 1.3"
     */
    private static function constraintFromText(string $text): ?string
    {
        // Normalise Unicode comparison operators.
        $text = str_replace(['≤', '≥', '＜', '＞'], ['<=', '>=', '<', '>'], trim($text));

        $version = '\d+(?:[.\-+][0-9A-Za-z.\-+]*)?';

        // "<start> <op><end>" or "<module-name> <op><end>" or bare "<op><end>"
        if (preg_match("/^(.*?)\s*(<=|>=|<|>)\s*({$version})$/u", $text, $m)) {
            $prefix = trim($m[1]);
            $clauses = [];
            // The prefix is a lower bound only when it IS a version; module
            // names ("log4j-core") and vendor prose are dropped. "0" means
            // "from the beginning" — always true, so omitted.
            if ($prefix !== '' && $prefix !== '0' && preg_match("/^{$version}\$/u", $prefix)) {
                $clauses[] = ">= {$prefix}";
            }
            $clauses[] = "{$m[2]} {$m[3]}";

            return implode(', ', $clauses);
        }

        // Trailing x-wildcard: "… 1.2.x" → the whole 1.2 line.
        if (preg_match('/(^|\s)(\d+(?:\.\d+)*)\.[x*](?:$|\s)/iu', $text, $m)) {
            $parts = explode('.', $m[2]);
            $parts[count($parts) - 1] = (string) ((int) end($parts) + 1);

            return ">= {$m[2]}, < ".implode('.', $parts);
        }

        // A single exact version, possibly behind a module-name prefix.
        if (preg_match("/^(?:.*\s)?({$version})\$/u", $text, $m)) {
            return "= {$m[1]}";
        }

        return null;
    }

    /**
     * Whether the queried version may be affected, judged ONLY by ranges
     * belonging to the searched product — an advisory usually lists several
     * products, and another product's parseable range must not clear ours.
     * Undeterminable (no relevant ranges, or any relevant range that didn't
     * parse) keeps the advisory.
     */
    private function versionMayBeAffected(VulnerabilityData $vuln, string $product, ?string $version): bool
    {
        if ($version === null || $version === '') {
            return true;
        }

        $needle = strtolower($product);
        $relevant = array_values(array_filter(
            $vuln->affectedRanges,
            fn ($range) => is_array($range)
                && str_contains(strtolower((string) ($range['product'] ?? '')), $needle),
        ));

        if ($relevant === []) {
            return true; // nothing product-specific to judge by
        }

        foreach ($relevant as $range) {
            if (! isset($range['range'])) {
                return true; // a relevant constraint exists but didn't parse
            }
        }

        return \Gumslone\Vulns\Support\VersionRange::isVulnerable($version, $relevant) !== false;
    }
}
