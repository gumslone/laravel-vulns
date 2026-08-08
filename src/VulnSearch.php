<?php

declare(strict_types=1);

namespace Gumslone\Vulns;

use Gumslone\Vulns\Contracts\Source;
use Gumslone\Vulns\Data\PackageData;
use Gumslone\Vulns\Data\VulnerabilityData;

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
        private readonly ?\Gumslone\Vulns\Enrichment\ThreatEnricher $enricher = null,
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
        )), $this->priority, $this->preferLatest, $this->enricher);
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
        )), $this->priority, $this->preferLatest, $this->enricher);
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
        return new self($this->sources, (array) $names, $this->preferLatest, $this->enricher);
    }

    /**
     * A copy where the most recently modified record wins the merge instead
     * of the highest-priority source — so a CVSS rescore or rewritten
     * description reaches the result no matter which feed published it first.
     * Records without a modification date fall back to priority order.
     */
    public function preferLatest(bool $prefer = true): self
    {
        return new self($this->sources, $this->priority, $prefer, $this->enricher);
    }

    /**
     * A copy with a (different) threat enricher, or null to disable
     * EPSS / KEV stamping for this instance.
     */
    public function withEnricher(?\Gumslone\Vulns\Enrichment\ThreatEnricher $enricher): self
    {
        return new self($this->sources, $this->priority, $this->preferLatest, $enricher);
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
     * Search by CPE 2.3. Only the CPE-driven sources (NVD, CVE-Search) can
     * answer; the rest return nothing for want of registry coordinates.
     */
    public function searchCpe(string $cpe23): array
    {
        return $this->search(PackageData::fromCpe($cpe23));
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

        foreach ($this->sources as $source) {
            if (! $source->isEnabled()) {
                continue;
            }

            try {
                foreach ($source->queryBatch($packages) as $key => $vulns) {
                    if (array_key_exists($key, $results)) {
                        $results[$key] = array_merge($results[$key], $vulns);
                    }
                }
            } catch (\Throwable $e) {
                $this->errors[$source->name()] = $e->getMessage();
            }
        }

        return $this->enrich(array_map($this->merge(...), $results));
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
        $found = [];

        foreach ($this->sources as $source) {
            if (! $source->isEnabled()) {
                continue;
            }

            try {
                if ($data = $source->fetchById($vulnId)) {
                    $found[] = $data;
                }
            } catch (\Throwable $e) {
                $this->errors[$source->name()] = $e->getMessage();
            }
        }

        return $this->enrich([$this->merge($found)])[0][0] ?? null;
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
        /** @var array<string, VulnerabilityData> $byId */
        $byId = [];

        foreach ($vulns as $vuln) {
            $key = $vuln->canonicalId();
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

        return new VulnerabilityData(
            vulnId: $vulnId,
            source: $base->source,
            summary: $base->summary ?? $other->summary,
            details: $base->details ?? $other->details,
            // The base is authoritative when it has an opinion — taking the
            // max instead would undo a deliberate downward rescore.
            severity: $base->severity !== Severity::Unknown ? $base->severity : $other->severity,
            cvssV3Score: $base->cvssV3Score ?? $other->cvssV3Score,
            cvssV3Vector: $base->cvssV3Vector ?? $other->cvssV3Vector,
            cvssV2Score: $base->cvssV2Score ?? $other->cvssV2Score,
            cvssV2Vector: $base->cvssV2Vector ?? $other->cvssV2Vector,
            cvssV4Score: $base->cvssV4Score ?? $other->cvssV4Score,
            cvssV4Vector: $base->cvssV4Vector ?? $other->cvssV4Vector,
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
            aliases: $aliases,
            affectedEcosystems: $base->affectedEcosystems ?: $other->affectedEcosystems,
            // Version evidence is the scarcest signal — keep whichever has it.
            affectedRanges: $base->affectedRanges ?: $other->affectedRanges,
            references: $base->references ?: $other->references,
            cwes: $base->cwes ?: $other->cwes,
            isFixed: $base->isFixed || $other->isFixed,
            fixedVersions: $base->fixedVersions ?: $other->fixedVersions,
            remediationAdvice: $base->remediationAdvice ?? $other->remediationAdvice,
            sourcePublishedAt: $base->sourcePublishedAt ?? $other->sourcePublishedAt,
            sourceModifiedAt: $base->sourceModifiedAt ?? $other->sourceModifiedAt,
            sourceUrl: $base->sourceUrl ?? $other->sourceUrl,
            rawDataChecksum: $base->rawDataChecksum,
            extra: $base->extra + $other->extra,
        );
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
