<?php

declare(strict_types=1);

namespace Gumslone\Vulns;

use Gumslone\Vulns\Data\VulnerabilityData;

/**
 * Everything one search produced, in one immutable value: the merged results,
 * which sources failed (or were cut short), and which sources actually looked
 * at each package. Unlike VulnSearch::errors()/coverage() — which describe
 * "the most recent call" on a shared instance — a report belongs to its call,
 * so it is safe under Octane, in queue workers and across nested searches.
 *
 * @implements \IteratorAggregate<array-key, VulnerabilityData[]>
 */
final class SearchReport implements \Countable, \IteratorAggregate, \JsonSerializable
{
    /**
     * @param  array<array-key, VulnerabilityData[]>  $results  keyed like the input packages
     * @param  array<string, string>  $errors  source name => what went wrong
     * @param  array<array-key, array{queried: string[], skipped: string[], failed: string[]}>  $coverage
     */
    public function __construct(
        public readonly array $results,
        public readonly array $errors = [],
        public readonly array $coverage = [],
    ) {}

    /** @return VulnerabilityData[] the findings for one input key ([] when unknown) */
    public function for(int|string $key): array
    {
        return $this->results[$key] ?? [];
    }

    /** @return VulnerabilityData[] every finding, flattened (one entry per package it affects) */
    public function all(): array
    {
        return $this->results === [] ? [] : array_merge(...array_values($this->results));
    }

    /** No source failed or was cut short, anywhere in the batch. */
    public function isComplete(): bool
    {
        return $this->errors === [];
    }

    /**
     * Whether an EMPTY answer for this package can be read as "clean": at
     * least one source looked it up and none that could have failed. False
     * means "not covered" or "under-reported" — never show it as a clean bill.
     */
    public function isConclusive(int|string $key): bool
    {
        $coverage = $this->coverage[$key] ?? null;

        return $coverage !== null && $coverage['queried'] !== [] && $coverage['failed'] === [];
    }

    /** @return array<int, int|string> input keys whose answer is not conclusive */
    public function inconclusiveKeys(): array
    {
        return array_values(array_filter(array_keys($this->results), fn ($key) => ! $this->isConclusive($key)));
    }

    /** @return array<int, int|string> input keys with at least one finding */
    public function vulnerableKeys(): array
    {
        return array_keys(array_filter($this->results));
    }

    public function count(): int
    {
        return count($this->all());
    }

    public function getIterator(): \ArrayIterator
    {
        return new \ArrayIterator($this->results);
    }

    /** @return array{results: array<array-key, array<int, array<string, mixed>>>, errors: array<string, string>, coverage: array<array-key, mixed>} */
    public function toArray(): array
    {
        return [
            'results' => array_map(fn (array $vulns) => array_map(fn (VulnerabilityData $v) => $v->toArray(), $vulns), $this->results),
            'errors' => $this->errors,
            'coverage' => $this->coverage,
        ];
    }

    public function jsonSerialize(): array
    {
        return $this->toArray();
    }
}
