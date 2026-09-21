<?php

declare(strict_types=1);

namespace Gumslone\Vulns\Facades;

use Gumslone\Vulns\VulnSearch;
use Illuminate\Support\Facades\Facade;

/**
 * Vulns::searchPurl('pkg:npm/lodash@4.17.20'), Vulns::report($packages), …
 *
 * @method static \Gumslone\Vulns\Data\VulnerabilityData[] search(\Gumslone\Vulns\Data\PackageData $package)
 * @method static \Gumslone\Vulns\Data\VulnerabilityData[] searchPurl(string $purl)
 * @method static \Gumslone\Vulns\Data\VulnerabilityData[] searchCpe(string $cpe23)
 * @method static \Gumslone\Vulns\Data\VulnerabilityData[] searchCommit(string $commitOrUrl)
 * @method static \Gumslone\Vulns\Data\VulnerabilityData[] searchUrl(string $url)
 * @method static \Gumslone\Vulns\Data\VulnerabilityData[] searchAny(string $query)
 * @method static array<array-key, \Gumslone\Vulns\Data\VulnerabilityData[]> searchBatch(array $packages)
 * @method static \Gumslone\Vulns\SearchReport report(array $packages)
 * @method static \Gumslone\Vulns\Data\VulnerabilityData|null fetchById(string $vulnId)
 * @method static \Gumslone\Vulns\Data\VulnerabilityData|null latest(string $vulnId)
 * @method static \Gumslone\Vulns\VulnChange|null refresh(\Gumslone\Vulns\Data\VulnerabilityData $stored)
 * @method static VulnSearch only(string|array $names)
 * @method static VulnSearch except(string|array $names)
 * @method static VulnSearch prioritize(string|array $names)
 * @method static VulnSearch preferLatest(bool $prefer = true)
 * @method static VulnSearch filterByVersion(bool $filter = true)
 * @method static array<string, string> errors()
 * @method static array<array-key, array{queried: string[], skipped: string[], failed: string[]}> coverage()
 * @method static string[] availableSources()
 *
 * @see VulnSearch
 */
class Vulns extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return VulnSearch::class;
    }
}
