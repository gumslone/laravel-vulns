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
    /** @var array<string, string> source name => error message from the last search */
    private array $errors = [];

    /** @param iterable<Source> $sources */
    public function __construct(private readonly iterable $sources) {}

    /**
     * A copy restricted to the named sources — the library equivalent of
     * `--source=nvd,osv`. Names are the sources' own `name()` values
     * ('osv', 'nvd', 'github', 'cve_search', 'euvd', 'snyk').
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
        )));
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
        )));
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

        return array_map($this->merge(...), $results);
    }

    /**
     * Look up one advisory by id (CVE, GHSA, …) across sources, richest
     * answer first. Returns null when no source knows it.
     */
    public function fetchById(string $vulnId): ?VulnerabilityData
    {
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

        return $this->merge($found)[0] ?? null;
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
        usort($merged, fn ($a, $b) => ($b->cvssV3Score ?? -1) <=> ($a->cvssV3Score ?? -1)
            ?: $b->severity->weight() <=> $a->severity->weight());

        return $merged;
    }

    private function mergePair(VulnerabilityData $a, VulnerabilityData $b): VulnerabilityData
    {
        // Prefer the record carrying a CVE id as the base, then fill gaps.
        [$base, $other] = VulnerabilityData::isCveId($a->vulnId) || ! VulnerabilityData::isCveId($b->vulnId)
            ? [$a, $b]
            : [$b, $a];

        $aliases = array_values(array_unique(array_filter(array_merge(
            $base->aliases, $other->aliases, [$other->vulnId],
        ), fn (string $id) => $id !== $base->vulnId)));

        return new VulnerabilityData(
            vulnId: $base->vulnId,
            source: $base->source,
            summary: $base->summary ?? $other->summary,
            details: $base->details ?? $other->details,
            severity: $base->severity->weight() >= $other->severity->weight() ? $base->severity : $other->severity,
            cvssV3Score: $base->cvssV3Score ?? $other->cvssV3Score,
            cvssV3Vector: $base->cvssV3Vector ?? $other->cvssV3Vector,
            cvssV2Score: $base->cvssV2Score ?? $other->cvssV2Score,
            cvssV2Vector: $base->cvssV2Vector ?? $other->cvssV2Vector,
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
}
