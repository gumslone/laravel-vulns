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
    /** @var \WeakMap<PackageData, ?string>|null */
    private ?\WeakMap $resolvedCpes = null;

    protected function resolveLookupCpe(PackageData $package): ?string
    {
        // Memoised per package object: supports() and queryBatch() both
        // resolve, and the curated lookup may be a database round-trip.
        $this->resolvedCpes ??= new \WeakMap;
        if (! isset($this->resolvedCpes[$package])) {
            // An explicitly supplied CPE is the caller's intent — never override it.
            $this->resolvedCpes[$package] = $package->cpe23
                ?? $this->cpeLookup?->bestCpe23($package->purl, $package->version)
                ?? $this->cpeResolver->resolveCpe23($package);
        }

        return $this->resolvedCpes[$package];
    }
}
