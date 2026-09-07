<?php

declare(strict_types=1);

namespace Gumslone\Vulns\Testing;

use Gumslone\Vulns\Data\PackageData;
use Gumslone\Vulns\Data\VulnerabilityData;
use Gumslone\Vulns\Sources\AbstractSource;

/**
 * A canned source for tests of code that consumes VulnSearch — answers by
 * package name (or purl), finds records by id or alias, and can be made to
 * fail so the caller's "source down" path is exercised:
 *
 *   $search = new VulnSearch([
 *       new FakeSource('osv', ['lodash' => [$vuln]]),
 *       (new FakeSource('nvd'))->failing('503 Service Unavailable'),
 *   ]);
 */
class FakeSource extends AbstractSource
{
    private ?\Throwable $failure = null;

    /**
     * @param  array<string, VulnerabilityData[]>  $byPackage  package name or purl => records
     */
    public function __construct(
        private readonly string $sourceName,
        private readonly array $byPackage = [],
        bool $enabled = true,
    ) {
        $this->boot(['enabled' => $enabled], null);
    }

    /** Every query and lookup throws — the way a real source reports a transport failure. */
    public function failing(\Throwable|string $failure): self
    {
        $this->failure = is_string($failure) ? new \RuntimeException($failure) : $failure;

        return $this;
    }

    public function name(): string
    {
        return $this->sourceName;
    }

    public function queryBatch(array $packages): array
    {
        $this->failOrContinue();

        $results = [];
        foreach ($packages as $key => $package) {
            $results[$key] = $this->byPackage[$package->name]
                ?? ($package->purl !== null ? $this->byPackage[$package->purl] ?? [] : []);
        }

        return $results;
    }

    public function fetchById(string $vulnId): ?VulnerabilityData
    {
        $this->failOrContinue();

        foreach ($this->byPackage as $vulns) {
            foreach ($vulns as $vuln) {
                if (strcasecmp($vuln->vulnId, $vulnId) === 0
                    || in_array(strtoupper($vulnId), array_map('strtoupper', $vuln->aliases), true)) {
                    return $vuln;
                }
            }
        }

        return null;
    }

    public function supports(PackageData $package): bool
    {
        return true;
    }

    private function failOrContinue(): void
    {
        if ($this->failure !== null) {
            throw $this->failure;
        }
    }
}
