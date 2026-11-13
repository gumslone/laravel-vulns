<?php

declare(strict_types=1);

namespace Gumslone\Vulns\Sources;

use Gumslone\Vulns\Contracts\CpeLookup;
use Gumslone\Vulns\Data\PackageData;
use Gumslone\Vulns\Data\VulnerabilityData;
use Gumslone\Vulns\Severity as SeverityLevel;
use Gumslone\Vulns\Support\ProductMatch;
use Gumslone\Vulns\Support\VersionRange;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Pool;
use Psr\Log\LoggerInterface;
use Psr\SimpleCache\CacheInterface;

/**
 * European Union Vulnerability Database (ENISA) adapter.
 * https://euvd.enisa.europa.eu/apidoc
 *
 * No API key required.
 */
class EuvdSource extends AbstractSource
{
    /**
     * @param  CpeLookup|null  $cpeLookup  a curated PURL → CPE mapping, when the host has one. Its
     *                                     vendor tells same-named products apart — the Rust crate
     *                                     "openssl" (CPE vendor "sfackler") from OpenSSL itself —
     *                                     which EUVD's free-text records cannot.
     */
    public function __construct(?Client $http = null, array $options = [], ?LoggerInterface $logger = null, ?CacheInterface $cache = null, private readonly ?CpeLookup $cpeLookup = null)
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

    public function supports(PackageData $package): bool
    {
        return trim($package->name) !== '';
    }

    public function queryBatch(array $packages): array
    {
        $results = array_fill_keys(array_keys($packages), []);

        // Lookup is a product-name search (no version), so the same package
        // at different versions shares one request. Packages are grouped by
        // IDENTITY, not bare name: "@vueuse/core" and "@inertiajs/core" both
        // search "core", but an advisory concerns at most one of them.
        $keysByProduct = [];
        $identities = [];
        $vendorHints = [];
        foreach ($packages as $key => $package) {
            $lookup = strtolower(trim((string) $package->namespace)).'|'.$package->name;
            $keysByProduct[$lookup][] = $key;
            $identities[$lookup] = $package;
            // Resolved once per identity: the lookup may be a database round-trip.
            $vendorHints[$lookup] ??= $this->vendorHints($package);
        }

        // `size` tops out at 100; `page` (0-based) and the response's `total`
        // walk the rest. A popular product runs to hundreds of records, and
        // an old installed version is affected by exactly the older ones.
        $pageSize = 100;
        $maxPages = max(1, (int) $this->config('max_pages', 20));

        // Fail safe: a rejected or malformed page must not read as "no known
        // vulnerabilities" for its product — collect failures during the
        // pool rounds and throw once they have drained.
        $failed = 0;
        $requested = 0;
        $firstReason = null;
        $itemsByProduct = array_fill_keys(array_keys($keysByProduct), []);
        // Records read per lookup — paging runs on this, not on what was
        // kept: the search is a "contains" match on the product name, and
        // only the records that concern the package are held on to.
        $seen = array_fill_keys(array_keys($keysByProduct), 0);

        $pending = array_fill_keys(array_keys($keysByProduct), 0);
        // Product-level lookups answered recently come from the cache (see
        // AbstractSource::cachedLookup) — only complete answers are stored.
        $truncated = [];
        // The stored answer is already filtered to the package, so the key
        // carries the identity and the matching mode, not just the name.
        $cachePrefix = 'euvd|'.$this->config('match', 'strict').'|'.($this->cpeLookup !== null ? 'cpe|' : '');
        foreach (array_keys($pending) as $lookup) {
            if (($cached = $this->cachedLookup($cachePrefix.$lookup)) !== null) {
                $itemsByProduct[$lookup] = $cached;
                unset($pending[$lookup]);
            }
        }
        $fetched = array_keys($pending);
        while ($pending !== []) {
            $next = [];
            $requests = function () use ($pending, $pageSize, $identities) {
                foreach ($pending as $product => $page) {
                    yield $product => fn () => $this->http->getAsync('search', [
                        'query' => ['product' => self::searchTerm($identities[$product]), 'size' => $pageSize] + ($page > 0 ? ['page' => $page] : []),
                    ]);
                }
            };

            $pool = new Pool($this->http, $requests(), [
                'concurrency' => (int) $this->config('max_concurrency', 8),
                'fulfilled' => function ($response, $product) use (&$itemsByProduct, &$seen, &$next, &$failed, &$firstReason, &$truncated, $pending, $keysByProduct, $identities, $vendorHints, $pageSize, $maxPages) {
                    $data = json_decode($response->getBody()->getContents(), true);

                    // A 200 whose body isn't the expected JSON (the SPA's HTML
                    // shell, a proxy outage page) is a failed request, not an
                    // authoritative "no vulnerabilities".
                    if (! is_array($data) || ! array_key_exists('items', $data) || ! is_array($data['items'])) {
                        $failed++;
                        $firstReason ??= 'malformed response body';
                        $this->log('warning', '[vulns] EUVD returned a malformed body', ['product' => $product]);

                        return;
                    }

                    $items = $data['items'];
                    $seen[$product] += count($items);
                    // Keep only what concerns THIS package, page by page: a
                    // generic name ("core", "config") returns thousands of
                    // other vendors' products, far too many to carry along.
                    $itemsByProduct[$product] = array_merge($itemsByProduct[$product], array_values(array_filter(
                        $items,
                        fn ($item) => is_array($item) && $this->concerns($item, $identities[$product], $vendorHints[$product]),
                    )));

                    $total = is_numeric($data['total'] ?? null) ? (int) $data['total'] : null;
                    $more = $total !== null ? $seen[$product] < $total : count($items) >= $pageSize;
                    if ($items === [] || ! $more) {
                        return;
                    }
                    if ($maxPages <= $pending[$product] + 1) {
                        $truncated[$product] = true;
                        $this->warn(
                            sprintf('results for "%s" truncated at %d of %s records (max_pages=%d)', self::searchTerm($identities[$product]), $seen[$product], $total ?? 'unknown', $maxPages),
                            [], $keysByProduct[$product],
                        );

                        return;
                    }
                    $next[$product] = $pending[$product] + 1;
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

            $requested += count($pending);
            $pool->promise()->wait();
            $pending = $next;
        }

        if ($failed > 0) {
            throw new \RuntimeException(sprintf(
                'EUVD: %d of %d requests failed: %s', $failed, $requested, $firstReason,
            ));
        }

        foreach ($fetched as $lookup) {
            if (! isset($truncated[$lookup])) {
                $this->cacheLookup($cachePrefix.$lookup, $itemsByProduct[$lookup]);
            }
        }

        foreach ($itemsByProduct as $product => $items) {
            $vulns = [];
            foreach (array_filter($items, 'is_array') as $item) {
                $vuln = $this->parseItem($item);
                if ($vuln !== null) {
                    $vulns[$vuln->vulnId] ??= $vuln;
                }
            }

            // What is left concerns the package (see concerns()); now drop
            // the advisories the queried version provably escapes. Fail-safe: an advisory is
            // only dropped when its ranges for THIS product parsed cleanly
            // and none matched — unparseable or missing version text keeps
            // the advisory ("can't tell" must not read as "not affected").
            foreach ($keysByProduct[$product] as $key) {
                $results[$key] = array_values(array_filter(
                    $vulns,
                    fn (VulnerabilityData $vuln) => $this->versionMayBeAffected($vuln, self::searchTerm($identities[$product]), $packages[$key]->version),
                ));
            }
        }

        return $results;
    }

    /**
     * The product name to search EUVD for: the package's own name without a
     * vendor prefix ("laravel/framework" → "framework") — EUVD keeps the
     * vendor in a field of its own, which concerns() checks.
     */
    private static function searchTerm(PackageData $package): string
    {
        $name = trim($package->name);
        $at = max((int) strrpos($name, '/'), (int) strrpos($name, ':'));

        return $at > 0 ? substr($name, $at + 1) : $name;
    }

    /**
     * Whether a search hit is about the package at all. The search answers
     * every product whose name CONTAINS the term, so most hits for a generic
     * name are other vendors' products. A record that names no product
     * cannot be judged and is kept (fail-safe); `match => 'name'` accepts an
     * exact product name from any vendor.
     */
    private function concerns(array $item, PackageData $package, array $vendorHints = []): bool
    {
        $names = fn (string $list, string $field): array => array_values(array_filter(array_map(
            fn ($entry) => is_array($entry) ? trim((string) ($entry[$field]['name'] ?? '')) : '',
            is_array($item[$list] ?? null) ? $item[$list] : [],
        )));

        return ProductMatch::concerns(
            $names('enisaIdProduct', 'product'),
            $names('enisaIdVendor', 'vendor'),
            $package->name,
            $package->namespace,
            requireVendor: $this->config('match', 'strict') !== 'name',
            vendorHints: $vendorHints,
        ) !== false;
    }

    /**
     * The vendor of the package's CPE — one the caller supplied, or the
     * curated lookup's. A heuristic CPE is no use here: it would only repeat
     * the package name.
     *
     * @return string[]
     */
    private function vendorHints(PackageData $package): array
    {
        $cpe = $package->cpe23 ?? $this->cpeLookup?->bestCpe23($package->purl, $package->version);
        $parts = is_string($cpe) ? explode(':', $cpe) : [];
        $vendor = ($parts[0] ?? '') === 'cpe' && ($parts[1] ?? '') === '2.3' ? trim((string) ($parts[3] ?? '')) : '';

        return $vendor !== '' && $vendor !== '*' && $vendor !== '-' ? [$vendor] : [];
    }

    /** The by-id endpoint is keyed on EUVD's own ids. */
    public function knowsId(string $vulnId): bool
    {
        return (bool) preg_match('/^EUVD-\d{4}-\d+$/i', trim($vulnId));
    }

    public function fetchById(string $vulnId): ?VulnerabilityData
    {
        if (! $this->knowsId($vulnId)) {
            return null;
        }

        try {
            $response = $this->http->get('enisaid', ['query' => ['id' => $vulnId]]);
            $body = trim((string) $response->getBody());
            if ($body === '') {
                return null; // an unknown id answers 200 with an empty body
            }
            $data = $this->decode($response, "EUVD lookup of {$vulnId}", allowNull: true);

            return $data ? $this->parseItem($data) : null;
        } catch (GuzzleException $e) {
            if (self::isNotFound($e)) {
                return null;
            }

            // Fail safe: an unreachable EUVD is not "unknown advisory".
            throw new \RuntimeException("EUVD lookup failed for {$vulnId}: {$e->getMessage()}", 0, $e);
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

        $exploitedSince = null;
        if (is_string($item['exploitedSince'] ?? null) && trim($item['exploitedSince']) !== '') {
            try {
                $exploitedSince = new \DateTimeImmutable($item['exploitedSince']);
            } catch (\Exception) {
                $exploitedSince = null;
            }
        }

        return new VulnerabilityData(
            vulnId: $vulnId,
            source: 'euvd',
            summary: isset($item['description']) ? mb_substr($item['description'], 0, 255) : null,
            details: $item['description'] ?? null,
            severity: $score !== null ? SeverityLevel::fromCvssScore($score) : SeverityLevel::Unknown,
            cvssV3Score: $score,
            cvssV3Vector: $item['baseScoreVector'] ?? null,
            // `exploitedSince` is EUVD's relay of the CISA KEV listing date.
            isKnownExploited: $exploitedSince !== null,
            kevSince: $exploitedSince,
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

        // fixedVersions carries no product dimension, so a patch entry is
        // only unambiguous when the advisory concerns a single product —
        // in a multi-product advisory another product's patch would wrongly
        // feed isPastAllFixes for ours.
        $names = collect($item['enisaIdProduct'] ?? [])
            ->map(fn ($e) => strtolower(trim((string) ($e['product']['name'] ?? ''))));
        // "Single product" requires every entry to be NAMED and all names to
        // agree — unnamed entries (old backfilled records) make the patch's
        // owner unidentifiable, so the claim stays ambiguous.
        $singleProduct = $names->isNotEmpty()
            && $names->unique()->count() === 1
            && $names->first() !== '';

        foreach ($item['enisaIdProduct'] ?? [] as $entry) {
            $product = trim((string) ($entry['product']['name'] ?? ''));
            $raw = trim((string) ($entry['product_version'] ?? ''));
            if ($raw === '') {
                continue;
            }

            // "patch: X" entries are fix metadata, not affected ranges.
            if (preg_match('/^patch(?:ed)?\s*:\s*(\S+)$/iu', $raw, $m)) {
                if ($singleProduct) {
                    $fixed[] = $m[1];
                } else {
                    // Ambiguous — keep it as evidence, never as a fix claim.
                    $ranges[] = array_filter([
                        'raw' => $raw,
                        'product' => $product !== '' ? $product : null,
                        'source' => 'euvd',
                    ], fn ($v) => $v !== null);
                }

                continue;
            }

            // Old backfilled records carry CVE's "no version given"
            // placeholders. They are noise, not an unknown constraint —
            // recording them would block filtering on the real enumerated
            // versions the same record lists alongside.
            if (in_array(strtolower($raw), ['n/a', 'na', '-', 'unspecified', 'unknown'], true)) {
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

        // Old records enumerate hyphen-joined release tags: "openssl-1.1.0a",
        // "openssl-1.0.2j" — name segments (letter-led) then the version,
        // which may carry a letter suffix.
        if (preg_match('/^[A-Za-z][\w.]*(?:-[A-Za-z][\w.]*)*-(\d[0-9A-Za-z.\-+]*)$/u', $text, $m)) {
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

        // Word-boundary product match: "express" must not borrow ExpressVPN's
        // ranges (nor be cleared by them).
        $relevant = array_values(array_filter(
            $vuln->affectedRanges,
            fn ($range) => is_array($range)
                && VersionRange::sameProduct((string) ($range['product'] ?? ''), $product),
        ));

        if ($relevant === []) {
            return true; // nothing product-specific to judge by
        }

        foreach ($relevant as $range) {
            if (! isset($range['range'])) {
                return true; // a relevant constraint exists but didn't parse
            }
        }

        return VersionRange::isVulnerable($version, $relevant) !== false;
    }
}
