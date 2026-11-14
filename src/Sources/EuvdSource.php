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

        // The lookup is a product-name search (no version). Two groupings:
        //  - by IDENTITY — who the package is: vendor, name and CPE-vendor
        //    hint. Every version of a package shares one answer, while
        //    "@vueuse/core" and "@inertiajs/core", or the Rust crate
        //    "openssl" and OpenSSL itself, keep theirs apart;
        //  - by SEARCH TERM — the bare name. Identities that search the same
        //    word read the same pages, which are fetched once.
        $keysByIdentity = [];
        $identities = [];
        $hints = [];
        $identitiesByTerm = [];
        foreach ($packages as $key => $package) {
            $packageHints = $this->vendorHints($package);
            $identity = strtolower(trim((string) $package->namespace)).'|'.$package->name.'|'.implode(',', $packageHints);
            $keysByIdentity[$identity][] = $key;
            if (! isset($identities[$identity])) {
                $identities[$identity] = $package;
                $hints[$identity] = $packageHints;
                $identitiesByTerm[self::searchTerm($package)][] = $identity;
            }
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
        $itemsByIdentity = array_fill_keys(array_keys($identities), []);

        // An identity answered recently comes from the cache (see
        // AbstractSource::cachedLookup) — only complete answers are stored.
        // The stored answer is already filtered to the package, so the key
        // is the identity (hint included) and the matching mode.
        $cachePrefix = 'euvd|'.$this->config('match', 'strict').'|';
        $cached = [];
        foreach (array_keys($identities) as $identity) {
            if (($hit = $this->cachedLookup($cachePrefix.$identity)) !== null) {
                $itemsByIdentity[$identity] = $hit;
                $cached[$identity] = true;
            }
        }

        // A term is searched while any identity that uses it lacks an answer;
        // only those identities are filled from its pages.
        $pending = [];
        $seen = []; // records READ per term — paging runs on this, not on what was kept
        foreach ($identitiesByTerm as $term => $termIdentities) {
            $open = array_values(array_filter($termIdentities, fn (string $identity) => ! isset($cached[$identity])));
            $identitiesByTerm[$term] = $open;
            if ($open !== []) {
                $pending[$term] = 0;
                $seen[$term] = 0;
            }
        }
        $searched = array_keys($pending);
        $truncated = [];
        // Terms with more records than `max_pages` allows to read: searched
        // again per identity, narrowed to the package's vendor (see below).
        $tooMany = [];

        while ($pending !== []) {
            $next = [];
            $requests = function () use ($pending, $pageSize) {
                foreach ($pending as $term => $page) {
                    yield $term => fn () => $this->http->getAsync('search', [
                        'query' => ['product' => (string) $term, 'size' => $pageSize] + ($page > 0 ? ['page' => $page] : []),
                    ]);
                }
            };

            $pool = new Pool($this->http, $requests(), [
                'concurrency' => (int) $this->config('max_concurrency', 8),
                'fulfilled' => function ($response, $term) use (&$itemsByIdentity, &$seen, &$next, &$failed, &$firstReason, &$tooMany, $pending, $identitiesByTerm, $identities, $hints, $pageSize, $maxPages) {
                    $data = json_decode($response->getBody()->getContents(), true);

                    // A 200 whose body isn't the expected JSON (the SPA's HTML
                    // shell, a proxy outage page) is a failed request, not an
                    // authoritative "no vulnerabilities".
                    if (! is_array($data) || ! array_key_exists('items', $data) || ! is_array($data['items'])) {
                        $failed++;
                        $firstReason ??= 'malformed response body';
                        $this->log('warning', '[vulns] EUVD returned a malformed body', ['product' => $term]);

                        return;
                    }

                    $items = $data['items'];
                    $seen[$term] += count($items);
                    // Keep, per identity, only what concerns THAT package, page
                    // by page: a generic name ("core", "config") returns
                    // thousands of other vendors' products, far too many to
                    // carry along.
                    foreach ($identitiesByTerm[$term] as $identity) {
                        foreach ($items as $item) {
                            if (is_array($item) && $this->concerns($item, $identities[$identity], $hints[$identity])) {
                                $itemsByIdentity[$identity][] = $item;
                            }
                        }
                    }

                    $total = is_numeric($data['total'] ?? null) ? (int) $data['total'] : null;
                    $more = $total !== null ? $seen[$term] < $total : count($items) >= $pageSize;
                    if ($items === [] || ! $more) {
                        return;
                    }
                    // More than can be read — known from the first page when
                    // the server says how many there are, else on reaching
                    // the cap. No point in paging on through other vendors'
                    // products: the term is searched again, by vendor.
                    if (($total !== null && $total > $maxPages * $pageSize) || $maxPages <= $pending[$term] + 1) {
                        $tooMany[$term] = $total;

                        return;
                    }
                    $next[$term] = $pending[$term] + 1;
                },
                'rejected' => function ($reason, $term) use (&$failed, &$firstReason) {
                    $failed++;
                    $message = $reason instanceof \Throwable ? $reason->getMessage() : (string) $reason;
                    $firstReason ??= $message;
                    $this->log('warning', '[vulns] EUVD query failed', [
                        'product' => $term,
                        'error' => $message,
                    ]);
                },
            ]);

            $requested += count($pending);
            $pool->promise()->wait();
            $pending = $next;
        }

        // A bare name with thousands of records ("core", "version", "config")
        // cannot be read to the end, and almost none of it is about the
        // package. EUVD's own vendor filter — a case-insensitive "contains"
        // match — narrows it to what could pass concerns() anyway: records
        // whose vendor contains the package's vendor, its CPE vendor, or —
        // for a package without either — its own name. What was read of the
        // unfiltered search is kept as well; duplicates fall out on parsing.
        foreach ($tooMany as $term => $total) {
            foreach ($identitiesByTerm[$term] as $identity) {
                foreach ($this->vendorSearches($identities[$identity], $hints[$identity]) as $vendor) {
                    try {
                        [$items, $complete] = $this->searchByVendor((string) $term, $vendor, $pageSize, $maxPages);
                        $requested++;
                    } catch (\Throwable $e) {
                        $failed++;
                        $requested++;
                        $firstReason ??= $e->getMessage();
                        $this->log('warning', '[vulns] EUVD query failed', ['product' => $term, 'vendor' => $vendor, 'error' => $e->getMessage()]);

                        continue;
                    }
                    foreach ($items as $item) {
                        if (is_array($item) && $this->concerns($item, $identities[$identity], $hints[$identity])) {
                            $itemsByIdentity[$identity][] = $item;
                        }
                    }
                    if (! $complete) {
                        // Even the vendor's share is too large to read.
                        $truncated[$identity] = true;
                        $this->warn(
                            sprintf('results for "%s" (vendor "%s") truncated at %d records of %s (max_pages=%d)', $term, $vendor, $maxPages * $pageSize, $total ?? 'unknown', $maxPages),
                            [], $keysByIdentity[$identity],
                        );
                    }
                }
            }
        }

        if ($failed > 0) {
            throw new \RuntimeException(sprintf(
                'EUVD: %d of %d requests failed: %s', $failed, $requested, $firstReason,
            ));
        }

        foreach ($searched as $term) {
            foreach ($identitiesByTerm[$term] as $identity) {
                if (! isset($truncated[$identity])) {
                    $this->cacheLookup($cachePrefix.$identity, $itemsByIdentity[$identity]);
                }
            }
        }

        foreach ($itemsByIdentity as $identity => $items) {
            $vulns = [];
            foreach (array_filter($items, 'is_array') as $item) {
                $vuln = $this->parseItem($item);
                if ($vuln !== null) {
                    $vulns[$vuln->vulnId] ??= $vuln;
                }
            }

            // What is left concerns the package (see concerns()); now drop
            // the advisories the queried version provably escapes. Fail-safe:
            // an advisory is only dropped when its ranges for THIS product
            // parsed cleanly and none matched — unparseable or missing
            // version text keeps the advisory ("can't tell" must not read as
            // "not affected").
            $term = self::searchTerm($identities[$identity]);
            foreach ($keysByIdentity[$identity] as $key) {
                $results[$key] = array_values(array_filter(
                    $vulns,
                    fn (VulnerabilityData $vuln) => $this->versionMayBeAffected($vuln, $term, $packages[$key]->version),
                ));
            }
        }

        return $results;
    }

    /**
     * The vendor strings to narrow an oversized search by, most telling first
     * and at most four: the package's vendor (an npm scope without its "@",
     * the last segment of a path-like namespace, the telling words of a
     * dotted Maven group) and its CPE vendor — or, for a package that has
     * neither, its own name, which is what concerns() would accept as the
     * vendor of a self-named project anyway.
     *
     * @param  string[]  $vendorHints
     * @return string[]
     */
    private function vendorSearches(PackageData $package, array $vendorHints): array
    {
        $candidates = [];
        $namespace = trim(ltrim(trim((string) $package->namespace), '@'), '/');
        if ($namespace === '' && preg_match('#^(.+)[/:][^/:]+$#', ProductMatch::withoutGoMajor($package->name), $m)) {
            $namespace = ltrim($m[1], '@'); // the name carries its vendor: "vendor/name", "group:artifact"
        }
        if ($namespace !== '') {
            $last = (string) preg_replace('#^.*/#', '', $namespace);
            if (str_contains($last, '.') && ! str_contains($namespace, '/')) {
                // A Maven group: "org.apache.logging.log4j" is nobody's vendor name; its words are.
                foreach (explode('.', $last) as $word) {
                    if (strlen($word) >= 4 && ! in_array($word, ['org', 'com', 'net', 'io'], true)) {
                        $candidates[] = $word;
                    }
                }
            } else {
                $candidates[] = $last;
            }
        }
        foreach ($vendorHints as $hint) {
            $candidates[] = (string) preg_replace('/_project$/i', '', $hint);
        }
        if ($candidates === []) {
            $candidates[] = self::searchTerm($package);
        }

        return array_slice(array_values(array_unique(array_filter(array_map('strtolower', $candidates)))), 0, 4);
    }

    /**
     * Every record for a product term whose vendor contains `$vendor`.
     *
     * @return array{0: array<int, mixed>, 1: bool} [records, whether all of them were read]
     */
    private function searchByVendor(string $term, string $vendor, int $pageSize, int $maxPages): array
    {
        $items = [];
        for ($page = 0; $page < $maxPages; $page++) {
            $data = json_decode((string) $this->http->get('search', [
                'query' => ['product' => $term, 'vendor' => $vendor, 'size' => $pageSize] + ($page > 0 ? ['page' => $page] : []),
            ])->getBody(), true);
            if (! is_array($data) || ! is_array($data['items'] ?? null)) {
                throw new \RuntimeException('malformed response body');
            }

            $items = array_merge($items, $data['items']);
            $total = is_numeric($data['total'] ?? null) ? (int) $data['total'] : null;
            if ($data['items'] === [] || ($total !== null ? count($items) >= $total : count($data['items']) < $pageSize)) {
                return [$items, true];
            }
        }

        return [$items, false];
    }

    /**
     * The product name to search EUVD for: the package's own name without a
     * vendor prefix ("laravel/framework" → "framework") — EUVD keeps the
     * vendor in a field of its own, which concerns() checks.
     */
    private static function searchTerm(PackageData $package): string
    {
        // Also without a Go major-version suffix: ".../jwt/v5" is "jwt".
        return ProductMatch::bareName($package->name);
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

        // A product the advisory names without usable version text is a
        // constraint that cannot be read. Say so: left out, another product's
        // clean range would stand for the whole advisory and clear ours.
        $covered = array_map(fn (array $range) => strtolower((string) ($range['product'] ?? '')), $ranges);
        foreach ($item['enisaIdProduct'] ?? [] as $entry) {
            $product = trim((string) ($entry['product']['name'] ?? ''));
            if ($product !== '' && ! in_array(strtolower($product), $covered, true)
                && ! in_array(strtolower($product), ['n/a', 'na', '-', 'unspecified', 'unknown'], true)) {
                $ranges[] = ['product' => $product, 'source' => 'euvd'];
                $covered[] = strtolower($product);
            }
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
            // "1.7.0, < 1.16.0" — the comma is punctuation, not part of the
            // version; left on, the lower bound was lost and the range read
            // as "everything below 1.16.0".
            $prefix = rtrim(trim($m[1]), " ,;\t");
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

        // The ranges of the product itself decide. Only when the advisory
        // has none under that exact name do look-alikes count ("log4j" for
        // "log4j-core") — on a word boundary, so "express" neither borrows
        // ExpressVPN's ranges nor is cleared by them. A sibling's range
        // ("vite-plugin-foo") must never speak for the package when the
        // package is named in the advisory too.
        $ranges = array_values(array_filter($vuln->affectedRanges, 'is_array'));
        $relevant = array_values(array_filter(
            $ranges,
            fn (array $range) => ProductMatch::sameName((string) ($range['product'] ?? ''), $product),
        ));
        if ($relevant === []) {
            $relevant = array_values(array_filter(
                $ranges,
                fn (array $range) => VersionRange::sameProduct((string) ($range['product'] ?? ''), $product),
            ));
        }

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
