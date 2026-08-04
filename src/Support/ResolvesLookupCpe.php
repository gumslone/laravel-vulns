<?php

declare(strict_types=1);

namespace Gumslone\Vulns\Support;

use Gumslone\Vulns\Data\PackageData;

/**
 * Shared CPE resolution for vulnerability sources that query NVD-style CPE
 * databases: an optional curated lookup (accurate vendor:product), then a
 * PURL-derived heuristic via the required readonly CpeResolver $cpeResolver.
 *
 * Requires the using class to expose CpeResolver $cpeResolver and a nullable
 * Contracts\CpeLookup $cpeLookup.
 */
trait ResolvesLookupCpe
{
    protected function resolveLookupCpe(PackageData $package): ?string
    {
        return $this->cpeLookup?->bestCpe23($package->purl, $package->version)
            ?? $this->cpeResolver->resolveCpe23($package);
    }
}
