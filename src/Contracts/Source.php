<?php

declare(strict_types=1);

namespace Gumslone\Vulns\Contracts;

use Gumslone\Vulns\Data\PackageData;
use Gumslone\Vulns\Data\VulnerabilityData;

interface Source
{
    /**
     * Return the unique source identifier.
     * e.g. 'osv', 'nvd', 'github', 'snyk', 'euvd', 'cve_search'
     */
    public function name(): string;

    /**
     * Whether this source is enabled and configured.
     */
    public function isEnabled(): bool;

    /**
     * Query vulnerabilities affecting a specific package.
     *
     * @return VulnerabilityData[]
     */
    public function queryPackage(PackageData $package): array;

    /**
     * Batch query for multiple packages (optional optimisation).
     *
     * The result is keyed by the input array's keys so callers can attribute
     * vulnerabilities back to the package they were reported for. Every input
     * key must be present in the result (empty array when nothing was found
     * or the lookup failed for that package).
     *
     * @param  PackageData[]  $packages
     * @return array<array-key, VulnerabilityData[]> package key => vulnerabilities
     */
    public function queryBatch(array $packages): array;

    /**
     * Fetch a single vulnerability by ID.
     */
    public function fetchById(string $vulnId): ?VulnerabilityData;
}
