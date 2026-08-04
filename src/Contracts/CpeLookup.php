<?php

declare(strict_types=1);

namespace Gumslone\Vulns\Contracts;

/**
 * Optional curated PURL → CPE lookup consulted before the heuristic
 * CpeResolver when building NVD-style query CPEs. Host applications with a
 * curated mapping (e.g. the scanoss/purl2cpe dataset) implement this; without
 * one, sources fall back to the heuristic.
 */
interface CpeLookup
{
    public function bestCpe23(?string $purl, ?string $version): ?string;
}
