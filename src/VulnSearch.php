<?php

declare(strict_types=1);

namespace Gumslone\Vulns;

use Gumslone\Vulns\Contracts\Source;
use Gumslone\Vulns\Data\PackageData;
use Gumslone\Vulns\Data\VulnerabilityData;
use Gumslone\Vulns\Enrichment\ThreatEnricher;
use Gumslone\Vulns\Sources\AbstractSource;
use Gumslone\Vulns\Support\VersionRange;

/**
 * Queries every enabled source and merges the answers.
 *
 * Sources disagree in useful ways — one has ranges, another a CVSS vector, a
 * third only knows the GHSA id — so results are merged by canonical id (CVE
 * when known, else the primary id) with aliases pooled and the richest field
 * kept. A source that throws is recorded in errors() rather than aborting the
 * search: an unreachable feed means "possibly under-reported", not "clean".
 */
class VulnSearch
{
    /**
     * Default trust order when sources disagree about the same advisory.
     * Curated ecosystem feeds first (they know package-level ranges), the
     * CPE-driven aggregators last (they map coarsest).
     */
    public const DEFAULT_PRIORITY = [
        'osv', 'github', 'nvd', 'mitre', 'redhat', 'oss_index',
        'vulncheck', 'snyk', 'euvd', 'shodan_cvedb', 'cve_search',
    ];

    /** @var array<string, string> source name => error message from the last search */
    private array $errors = [];

    /** @var array<array-key, array{queried: string[], skipped: string[], failed: string[]}> per package key */
    private array $coverage = [];

    /** @var string[] */
    private readonly array $priority;

    /**
     * @param  iterable<Source>  $sources
     * @param  string[]|null  $priority  trust order for merging; null = DEFAULT_PRIORITY
     * @param  bool  $preferLatest  let the most recently modified record win the merge
     */
    public function __construct(
        private readonly iterable $sources,
        ?array $priority = null,
        private readonly bool $preferLatest = false,
        private readonly ?ThreatEnricher $enricher = null,
        private readonly bool $filterByVersion = true,
        private readonly ?\Closure $listener = null,
    ) {
        $this->priority = array_values(array_map('strtolower', $priority ?? self::DEFAULT_PRIORITY));
    }

    /**
     * A copy restricted to the named sources — the library equivalent of
     * `--source=nvd,osv`. Names are the sources' own `name()` values
     * ('osv', 'nvd', 'github', 'cve_search', 'euvd', 'snyk', 'oss_index',
     * 'redhat', 'shodan_cvedb', 'mitre', 'vulncheck').
     *
     * An unknown name throws rather than quietly searching a smaller set:
     * a typo that silently narrows the search would read as "nothing found".
     *
     * @param  string|string[]  $names
     */
    public function only(string|array $names): self
    {
        $wanted = array_map('strtolower', (array) $names);
        $known = array_map(fn (Source $s) => $s->name(), $this->all());

        if ($unknown = array_diff($wanted, $known)) {
            throw new \InvalidArgumentException(sprintf(
                'Unknown vulnerability source(s): %s. Available: %s.',
                implode(', ', $unknown),
                implode(', ', $known),
            ));
        }

        return new self(array_values(array_filter(
            $this->all(),
            fn (Source $s) => in_array($s->name(), $wanted, true),
        )), $this->priority, $this->preferLatest, $this->enricher, $this->filterByVersion, $this->listener);
    }

    /**
     * A copy with the named sources removed — e.g. skip a feed that needs
     * credentials you don't have, or one that is rate-limiting you.
     *
     * @param  string|string[]  $names
     */
    public function except(string|array $names): self
    {
        $unwanted = array_map('strtolower', (array) $names);

        return new self(array_values(array_filter(
            $this->all(),
            fn (Source $s) => ! in_array($s->name(), $unwanted, true),
        )), $this->priority, $this->preferLatest, $this->enricher, $this->filterByVersion, $this->listener);
    }

    /**
     * A copy with a different trust order for merging. When several sources
     * describe the same advisory, the earliest-listed source's record becomes
     * the merge base — its score, severity, and summary win; the rest only
     * fill gaps. Sources not listed rank after all listed ones.
     *
     * @param  string|string[]  $names
     */
    public function prioritize(string|array $names): self
    {
        return new self($this->sources, (array) $names, $this->preferLatest, $this->enricher, $this->filterByVersion, $this->listener);
    }

    /**
     * A copy where the most recently modified record wins the merge instead
     * of the highest-priority source — so a CVSS rescore or rewritten
     * description reaches the result no matter which feed published it first.
     * Records without a modification date fall back to priority order.
     */
    public function preferLatest(bool $prefer = true): self
    {
        return new self($this->sources, $this->priority, $prefer, $this->enricher, $this->filterByVersion, $this->listener);
    }

    /**
     * A copy with a (different) threat enricher, or null to disable
     * EPSS / KEV stamping for this instance.
     */
    public function withEnricher(?ThreatEnricher $enricher): self
    {
        return new self($this->sources, $this->priority, $this->preferLatest, $enricher, $this->filterByVersion, $this->listener);
    }

    /**
     * A copy that keeps (or drops) advisories the package's version provably
     * escapes. On by default: several feeds answer by package NAME alone
     * (GitHub, CVE-Search, Shodan), so without it a fully patched package is
     * flagged for every advisory its name ever had. Only a provable miss is
     * dropped — a range that can't be read or ordered keeps the advisory.
     */
    public function filterByVersion(bool $filter = true): self
    {
        return new self($this->sources, $this->priority, $this->preferLatest, $this->enricher, $filter, $this->listener);
    }

    /**
     * A copy that reports what happens to a listener: Events\SourceFailed for
     * every source that threw or answered partially, Events\SearchCompleted
     * (with the SearchReport) after each batch. The Laravel provider wires
     * this to the event dispatcher; a listener's own exception never breaks
     * a search.
     *
     * @param  callable(object): void|null  $listener
     */
    public function listen(?callable $listener): self
    {
        return new self(
            $this->sources, $this->priority, $this->preferLatest, $this->enricher, $this->filterByVersion,
            $listener === null ? null : $listener(...),
        );
    }

    private function emit(object $event): void
    {
        try {
            ($this->listener)?->__invoke($event);
        } catch (\Throwable) {
            // observers must not be able to fail a lookup
        }
    }

    /**
     * Names of every registered source, enabled or not — the vocabulary
     * only()/except() accept.
     *
     * @return string[]
     */
    public function availableSources(): array
    {
        return array_map(fn (Source $s) => $s->name(), $this->all());
    }

    /** @return Source[] every registered source, enabled or not */
    private function all(): array
    {
        return is_array($this->sources) ? $this->sources : iterator_to_array($this->sources);
    }

    /**
     * Every vulnerability affecting a package, from all enabled sources.
     *
     * @return VulnerabilityData[]
     */
    public function search(PackageData $package): array
    {
        return $this->searchBatch([$package])[0] ?? [];
    }

    /** Search by Package URL: `pkg:npm/lodash@4.17.20`. */
    public function searchPurl(string $purl): array
    {
        return $this->search(PackageData::fromPurl($purl));
    }

    /**
     * Search by CPE 2.3. The CPE-driven sources (NVD, CVE-Search, Shodan
     * CVEDB's cpe23 filter) use it directly; product-name sources (EUVD,
     * Red Hat) query the CPE's product, with the CPE's version applied to
     * their version filtering.
     */
    public function searchCpe(string $cpe23): array
    {
        return $this->search(PackageData::fromCpe($cpe23));
    }

    /**
     * Search by git commit — a bare sha or a forge commit URL. OSV resolves
     * commits directly against advisory git ranges; a URL additionally
     * yields forge coordinates (pkg:github/…@sha) for the other sources.
     */
    public function searchCommit(string $commitOrUrl): array
    {
        return $this->search(PackageData::fromCommit($commitOrUrl));
    }

    /**
     * One entry point for any identifier a user might paste: an advisory id
     * (CVE, GHSA, EUVD, or an OSV-family id like PYSEC-/RUSTSEC-/GO-/MAL-/RHSA-
     * → the single matching record), a purl, a CPE 2.3, a
     * git commit sha, or a forge commit URL. Unrecognisable input throws
     * rather than guessing — a wrong guess would read as "nothing found".
     *
     * @return VulnerabilityData[]
     */
    public function searchAny(string $query): array
    {
        $query = trim($query);

        if (VulnerabilityData::looksLikeAdvisoryId($query)) {
            $found = $this->fetchById(VulnerabilityData::normaliseId($query));

            return $found !== null ? [$found] : [];
        }
        if (str_starts_with($query, 'pkg:')) {
            return $this->searchPurl($query);
        }
        if (str_starts_with($query, 'cpe:2.3:')) {
            return $this->searchCpe($query);
        }
        if (preg_match('/^[0-9a-f]{7,64}$/i', $query)) {
            return $this->searchCommit($query);
        }
        if (preg_match('#^https?://#i', $query)) {
            return $this->searchUrl($query);
        }

        throw new \InvalidArgumentException(
            "Unrecognised query '{$query}'. Pass an advisory id (CVE, GHSA, EUVD, PYSEC, RUSTSEC, GO, MAL, RHSA, …), a purl (pkg:…), a CPE 2.3, a commit sha, or a package URL.",
        );
    }

    /**
     * Search by any package-ish URL — commit pages natively; download,
     * release, archive and registry URLs when gumslone/laravel-package-url
     * is installed (see PackageData::fromUrl).
     */
    public function searchUrl(string $url): array
    {
        return $this->search(PackageData::fromUrl($url));
    }

    /**
     * Batch search — sources use their bulk endpoints and request pooling
     * where they have them. Results keep the input array's keys.
     *
     * @param  PackageData[]  $packages
     * @return array<array-key, VulnerabilityData[]>
     */
    public function searchBatch(array $packages): array
    {
        $results = array_fill_keys(array_keys($packages), []);
        $this->errors = [];
        $this->coverage = array_fill_keys(array_keys($packages), ['queried' => [], 'skipped' => [], 'failed' => []]);

        foreach ($this->sources as $source) {
            if (! $source->isEnabled()) {
                continue;
            }

            // Which packages this source can look up at all — an unmapped
            // ecosystem, a purl-less package on a purl-keyed feed — so an
            // empty answer can be told apart from "not covered". Inside the
            // try: supports() may consult a curated CPE catalog, and a
            // catalog outage is this source failing, not the search aborting.
            $applicable = array_keys($packages);
            if ($source instanceof AbstractSource) {
                $source->resetWarnings();
            }
            try {
                if ($source instanceof AbstractSource) {
                    $applicable = [];
                    foreach ($packages as $key => $package) {
                        if ($source->supports($package)) {
                            $applicable[] = $key;
                        } else {
                            $this->coverage[$key]['skipped'][] = $source->name();
                        }
                    }
                }

                foreach ($source->queryBatch($packages) as $key => $vulns) {
                    if (array_key_exists($key, $results)) {
                        $results[$key] = array_merge($results[$key], $this->affecting($packages[$key], $vulns));
                    }
                }

                // Partial trouble — one package's lookup failed or was cut
                // short while the rest stood: the results are kept, the gap
                // is reported, and those packages don't count as covered.
                $incomplete = [];
                if ($source instanceof AbstractSource && $source->warnings() !== []) {
                    $this->errors[$source->name()] = implode('; ', $source->warnings());
                    $incomplete = $source->incompleteKeys();
                    $this->emit(new Events\SourceFailed($source->name(), $this->errors[$source->name()], partial: true));
                }
                foreach ($applicable as $key) {
                    $this->coverage[$key][in_array($key, $incomplete, true) ? 'failed' : 'queried'][] = $source->name();
                }
            } catch (\Throwable $e) {
                $this->errors[$source->name()] = $e->getMessage();
                $this->emit(new Events\SourceFailed($source->name(), $e->getMessage()));
                // Everything not already recorded as skipped failed — the
                // throw may have come from supports() part-way through.
                foreach (array_keys($packages) as $key) {
                    if (! in_array($source->name(), $this->coverage[$key]['skipped'], true)) {
                        $this->coverage[$key]['failed'][] = $source->name();
                    }
                }
            }
        }

        $results = $this->enrich(array_map($this->merge(...), $results));
        if ($this->listener !== null) {
            $this->emit(new Events\SearchCompleted(new SearchReport($results, $this->errors, $this->coverage)));
        }

        return $results;
    }

    /**
     * The advisories that may affect the package's version: only a provable
     * "outside every range that speaks about this package" drops one.
     *
     * @param  VulnerabilityData[]  $vulns
     * @return VulnerabilityData[]
     */
    private function affecting(PackageData $package, array $vulns): array
    {
        if (! $this->filterByVersion || $package->version === null || trim($package->version) === '') {
            return $vulns;
        }

        return array_values(array_filter($vulns, fn (VulnerabilityData $vuln) => VersionRange::isVulnerable(
            $package->version,
            VersionRange::relevantTo($vuln->affectedRanges, $package->name),
        ) !== false));
    }

    /**
     * searchBatch() with its outcome attached: results, source failures and
     * per-package coverage in one immutable SearchReport that belongs to this
     * call — prefer it over errors()/coverage() wherever the instance is
     * shared (the container singleton under Octane or in a queue worker).
     *
     * @param  PackageData[]  $packages
     */
    public function report(array $packages): SearchReport
    {
        $results = $this->searchBatch($packages);

        return new SearchReport($results, $this->errors, $this->coverage);
    }

    /**
     * Stamp merged results with EPSS / KEV signals. Runs after the merge so
     * canonical CVE ids are settled; a failing feed leaves results
     * un-enriched and lands in errors() rather than aborting the search.
     *
     * @param  array<array-key, VulnerabilityData[]>  $results
     * @return array<array-key, VulnerabilityData[]>
     */
    private function enrich(array $results): array
    {
        if ($this->enricher === null) {
            return $results;
        }

        try {
            $results = $this->enricher->apply($results);
            $this->errors += $this->enricher->errors();
        } catch (\Throwable $e) {
            $this->errors['enrichment'] = $e->getMessage();
        }

        return $results;
    }

    /**
     * Look up one advisory by id (CVE, GHSA, …) across sources, richest
     * answer first. Returns null when no source knows it.
     */
    public function fetchById(string $vulnId): ?VulnerabilityData
    {
        // errors() reports the most recent operation only — without the reset
        // a stale failure from an earlier search would taint this lookup.
        $this->errors = [];
        $this->coverage = [$vulnId => ['queried' => [], 'skipped' => [], 'failed' => []]];
        $found = [];

        foreach ($this->sources as $source) {
            if (! $source->isEnabled()) {
                continue;
            }

            // A CVE-only feed can't look a GHSA up (and would 400 on it):
            // that is "not covered", never an outage.
            if ($source instanceof AbstractSource && ! $source->knowsId($vulnId)) {
                $this->coverage[$vulnId]['skipped'][] = $source->name();

                continue;
            }

            try {
                if ($data = $source->fetchById($vulnId)) {
                    $found[] = $data;
                }
                $this->coverage[$vulnId]['queried'][] = $source->name();
            } catch (\Throwable $e) {
                $this->errors[$source->name()] = $e->getMessage();
                $this->coverage[$vulnId]['failed'][] = $source->name();
                $this->emit(new Events\SourceFailed($source->name(), $e->getMessage()));
            }
        }

        return $this->enrich([$this->merge($found)])[0][0] ?? null;
    }

    /**
     * The freshest merged record for one advisory id: every enabled source
     * asked, the most recently modified answer winning the merge — so a
     * rescore or rewritten description reaches you whichever feed published
     * it — then EPSS / KEV stamped. Null when no source knows the id; check
     * errors() before reading that as "gone", a feed may just be down.
     */
    public function latest(string $vulnId): ?VulnerabilityData
    {
        $vulnId = trim($vulnId);
        if (VulnerabilityData::isCveId($vulnId)) {
            $vulnId = strtoupper($vulnId);
        }

        $fresh = $this->preferLatest ? $this : $this->preferLatest();
        $found = $fresh->fetchById($vulnId);
        $this->errors = $fresh->errors();

        return $found;
    }

    /**
     * Re-query a stored advisory and classify what changed: ->current is
     * the fresh merged record, ->impact() whether triage should reopen.
     * Null when no source knows it any more.
     */
    public function refresh(VulnerabilityData $stored): ?VulnChange
    {
        return $this->latest($stored->canonicalId())?->changesSince($stored);
    }

    /**
     * Which sources actually looked at each package in the most recent
     * batch search: `queried` answered, `skipped` could not look the package
     * up at all (unmapped ecosystem, no purl/CPE/version, id-only feed),
     * `failed` threw. An empty result with nothing queried is "not covered",
     * not "clean" — surface it like errors().
     *
     * @return array<array-key, array{queried: string[], skipped: string[], failed: string[]}> keyed like the input
     */
    public function coverage(): array
    {
        return $this->coverage;
    }

    /**
     * Source failures from the most recent search. Non-empty means results
     * may be incomplete — surface it rather than reporting a clean bill.
     *
     * @return array<string, string> source name => error
     */
    public function errors(): array
    {
        return $this->errors;
    }

    /** The enabled sources this instance will actually query. */
    public function sources(): array
    {
        return array_values(array_filter($this->all(), fn (Source $s) => $s->isEnabled()));
    }

    /**
     * Merge records describing the same advisory, keeping the strongest
     * signal for each field.
     *
     * @param  VulnerabilityData[]  $vulns
     * @return VulnerabilityData[]
     */
    private function merge(array $vulns): array
    {
        // Records describe the same advisory when they share ANY id — not
        // only a CVE: OSV may know GHSA-x as an alias of CVE-1 while GitHub's
        // GHSA-x record has no CVE yet and Snyk only cites the GHSA. Group
        // transitively (union-find over ids + aliases), then merge a group.
        $parent = [];
        $find = function (string $id) use (&$parent, &$find): string {
            $parent[$id] ??= $id;

            return $parent[$id] === $id ? $id : $parent[$id] = $find($parent[$id]);
        };
        foreach ($vulns as $vuln) {
            $root = $find(strtoupper($vuln->vulnId));
            foreach ($vuln->aliases as $alias) {
                $parent[$find(strtoupper($alias))] = $root;
            }
        }

        /** @var array<string, VulnerabilityData> $byId */
        $byId = [];
        foreach ($vulns as $vuln) {
            $key = $find(strtoupper($vuln->vulnId));
            $byId[$key] = isset($byId[$key]) ? $this->mergePair($byId[$key], $vuln) : $vuln;
        }

        $merged = array_values($byId);
        // effectiveCvssScore (v4 → v3 → v2) so a v4-only-scored Critical
        // doesn't sort below a v3-scored Low.
        usort($merged, fn ($a, $b) => ($b->effectiveCvssScore() ?? -1) <=> ($a->effectiveCvssScore() ?? -1)
            ?: $b->severity->weight() <=> $a->severity->weight());

        return $merged;
    }

    private function mergePair(VulnerabilityData $a, VulnerabilityData $b): VulnerabilityData
    {
        [$base, $other] = $this->pickBase($a, $b);

        // The displayed id stays the CVE regardless of which record wins the
        // merge — canonical ids are how consumers correlate across scans.
        $vulnId = VulnerabilityData::isCveId($base->vulnId) || ! VulnerabilityData::isCveId($other->vulnId)
            ? $base->vulnId
            : $other->vulnId;

        $aliases = array_values(array_unique(array_filter(array_merge(
            $base->aliases, $other->aliases, [$a->vulnId, $b->vulnId],
        ), fn (string $id) => $id !== $vulnId)));

        // Scores merge as before — the base's opinion wins, gaps fill from
        // the other (a score computed from a source's own vector is exact
        // and counts as its opinion). Vectors are different: one inferred
        // for a bare score is only representative, so a source's own
        // vector beats it whichever record wins — provided it belongs to
        // the score being kept. With none that fits, the merged record
        // infers one again, so inferredFields stays truthful.
        $cvss = function (int $v) use ($base, $other): array {
            $score = $base->{"cvssV{$v}Score"} ?? $other->{"cvssV{$v}Score"};
            foreach ([$base, $other] as $record) {
                $vector = $record->reported("cvss_v{$v}_vector");
                if ($vector !== null && ($score === null || $record->{"cvssV{$v}Score"} === $score)) {
                    return [$score, $vector];
                }
            }

            return [$score, null];
        };
        [$v2Score, $v2Vector] = $cvss(2);
        // Severity likewise: only a source's stated rating counts (the base's
        // first); one a record derived from its score is re-derived from the
        // merged score, and stays flagged.
        $severity = fn (VulnerabilityData $r) => $r->severity === Severity::Unknown ? null : $r->reported('severity');
        [$v3Score, $v3Vector] = $cvss(3);
        [$v4Score, $v4Vector] = $cvss(4);

        // A source's own link beats a fallback one, and every source's own
        // link survives the merge, keyed by source.
        $sourceUrls = array_filter(
            ($base->extra['source_urls'] ?? []) + ($other->extra['source_urls'] ?? [])
            + [$base->source => $base->reported('source_url'), $other->source => $other->reported('source_url')],
        );

        return new VulnerabilityData(
            vulnId: $vulnId,
            source: $base->source,
            summary: $base->summary ?? $other->summary,
            details: $base->details ?? $other->details,
            // The base is authoritative when it has an opinion — taking the
            // max instead would undo a deliberate downward rescore.
            severity: $severity($base) ?? $severity($other) ?? Severity::Unknown,
            cvssV3Score: $v3Score,
            cvssV3Vector: $v3Vector,
            cvssV2Score: $v2Score,
            cvssV2Vector: $v2Vector,
            cvssV4Score: $v4Score,
            cvssV4Vector: $v4Vector,
            epssScore: $base->epssScore ?? $other->epssScore,
            epssPercentile: $base->epssPercentile ?? $other->epssPercentile,
            isKnownExploited: $base->isKnownExploited || $other->isKnownExploited,
            kevSince: $base->kevSince ?? $other->kevSince,
            kevDueDate: $base->kevDueDate ?? $other->kevDueDate,
            usedInRansomware: $base->usedInRansomware || $other->usedInRansomware,
            // One source retracting is a signal, not a majority vote — the
            // flag survives the merge either way.
            isWithdrawn: $base->isWithdrawn || $other->isWithdrawn,
            isDisputed: $base->isDisputed || $other->isDisputed,
            ssvc: $base->ssvc ?: $other->ssvc,
            aliases: $aliases,
            affectedEcosystems: $base->affectedEcosystems ?: $other->affectedEcosystems,
            // Version evidence is the scarcest signal — keep whichever has it.
            affectedRanges: $base->affectedRanges ?: $other->affectedRanges,
            // Pooled, the base's first: an EXPLOIT link or a fix only one feed
            // knows about must survive whichever record wins the merge.
            references: self::poolReferences($base->references, $other->references),
            cwes: array_values(array_unique(array_merge($base->cwes, $other->cwes))),
            isFixed: $base->isFixed || $other->isFixed,
            fixedVersions: self::poolFixes($base->fixedVersions, $other->fixedVersions),
            remediationAdvice: $base->remediationAdvice ?? $other->remediationAdvice,
            sourcePublishedAt: $base->sourcePublishedAt ?? $other->sourcePublishedAt,
            sourceModifiedAt: $base->sourceModifiedAt ?? $other->sourceModifiedAt,
            sourceUrl: $base->reported('source_url') ?? $other->reported('source_url'),
            rawDataChecksum: $base->rawDataChecksum,
            // The pooled links must come FIRST: + is left-biased, and a pair-merge
            // has already stored a (shorter) source_urls in the base's extra.
            extra: ['source_urls' => $sourceUrls] + $base->extra + $other->extra,
        );
    }

    /**
     * @param  array<int, array<string, mixed>|string>  $a
     * @param  array<int, array<string, mixed>|string>  $b
     * @return array<int, array<string, mixed>|string> unique by URL; a typed entry beats an untyped duplicate
     */
    private static function poolReferences(array $a, array $b): array
    {
        $byUrl = [];
        foreach (array_merge($a, $b) as $ref) {
            $url = is_array($ref) ? (string) ($ref['url'] ?? '') : (string) $ref;
            $key = $url !== '' ? rtrim(strtolower($url), '/') : 'ref#'.count($byUrl);
            if (! isset($byUrl[$key]) || (is_array($ref) && ! empty($ref['type']) && (! is_array($byUrl[$key]) || empty($byUrl[$key]['type'])))) {
                $byUrl[$key] = $ref;
            }
        }

        return array_values($byUrl);
    }

    /**
     * @param  string[]  $a
     * @param  string[]  $b
     * @return string[] unique by bare version ("Packagist:1.2.0" and "1.2.0" are one fix)
     */
    private static function poolFixes(array $a, array $b): array
    {
        $bare = fn (string $fix): string => strtolower(ltrim((string) preg_replace('/^[A-Za-z][^:]*:/', '', trim($fix)), 'vV'));
        $seen = [];
        $fixes = [];
        foreach (array_merge($a, $b) as $fix) {
            $fix = (string) $fix;
            if ($fix !== '' && ! isset($seen[$bare($fix)])) {
                $seen[$bare($fix)] = true;
                $fixes[] = $fix;
            }
        }

        return $fixes;
    }

    /**
     * Which of two records describing the same advisory wins the merge.
     * preferLatest: the newer sourceModifiedAt wins (a rescore or rewritten
     * description reaches the result no matter who published it). Ties and
     * missing dates fall back to the source trust order.
     *
     * @return array{0: VulnerabilityData, 1: VulnerabilityData} [base, other]
     */
    private function pickBase(VulnerabilityData $a, VulnerabilityData $b): array
    {
        if ($this->preferLatest && $a->sourceModifiedAt !== null && $b->sourceModifiedAt !== null
            && $a->sourceModifiedAt->getTimestamp() !== $b->sourceModifiedAt->getTimestamp()) {
            return $a->sourceModifiedAt > $b->sourceModifiedAt ? [$a, $b] : [$b, $a];
        }

        return $this->rank($a->source) <= $this->rank($b->source) ? [$a, $b] : [$b, $a];
    }

    /** Position of a source in the trust order; unlisted sources rank last. */
    private function rank(string $source): int
    {
        $rank = array_search(strtolower($source), $this->priority, true);

        return $rank === false ? PHP_INT_MAX : $rank;
    }
}
