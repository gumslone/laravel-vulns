# laravel-vulns

[![CI](https://github.com/gumslone/laravel-vulns/actions/workflows/ci.yml/badge.svg)](https://github.com/gumslone/laravel-vulns/actions/workflows/ci.yml)

Multi-source vulnerability lookups for PHP — six production sources behind one
contract, extracted from and battle-tested in [OSSaur](https://ossaur.com).

| Source | Coverage |
|---|---|
| `OsvSource` | OSV.dev — registry ecosystems, PURLs, **git commits** (submodules), batch + pagination + payload caching |
| `GitHubAdvisorySource` | GitHub Advisory DB (GraphQL, token) **and repository security advisories** (REST, tokenless) |
| `NvdSource` | NVD 2.0 by CPE, rate-limit aware, parses `configurations` into real version ranges |
| `CveSearchSource` | CVE-Search / CIRCL by CPE |
| `EuvdSource` | ENISA EU Vulnerability Database |
| `SnykSource` | Snyk REST (token + org) |

The core is **framework-free** (plain Guzzle, PSR-3, PSR-16); the Laravel
service provider is optional sugar.

## Install

```bash
composer require gumslone/laravel-vulns
```

## Laravel

Auto-discovered. Publish the config to tune sources:

```bash
php artisan vendor:publish --tag=vulns-config
```

```php
use Gumslone\Vulns\Data\PackageData;
use Gumslone\Vulns\Sources\OsvSource;

$vulns = app(OsvSource::class)->queryPackage(
    new PackageData(name: 'lodash', version: '4.17.20', ecosystem: 'npm')
);

// …or every enabled source at once
foreach (app('vulns.enabled_sources') as $source) {
    $found = $source->queryPackage($package);
}
```

Logging goes to the app logger and payload caching to the app cache
automatically. Bind `Gumslone\Vulns\Contracts\CpeLookup` to plug a curated
PURL→CPE catalog into the NVD-style sources.

## Plain PHP

```php
$source = new OsvSource(
    options: ['timeout' => 15],
    cache: new Gumslone\Vulns\Support\ArrayCache,
);
$vulns = $source->queryPackage(new PackageData(name: 'left-pad', version: '1.0', ecosystem: 'npm'));
```

Every source takes `(?Client $http, array $options, ?LoggerInterface $logger,
?CacheInterface $cache)`.

## What you get back

`Gumslone\Vulns\Data\VulnerabilityData` — id + aliases, severity (normalised
from any string-backed enum), CVSS v2/v3 score and vector, affected ranges,
fixed versions, references, CWEs, publication stamps and a payload checksum.

`VersionRange::isVulnerable($version, $ranges)` answers whether an installed
version actually falls inside a finding's ranges — returning `null` when the
data can't prove it either way, so callers can decide their own fail-safe.

## Related

- [gumslone/GumVulns](https://github.com/gumslone/GumVulns) — a standalone,
  dependency-free CLI for ad-hoc CVE / keyword / CPE lookups across an even
  wider set of feeds. Different tool, different job: that one answers
  "tell me about this identifier", this one answers "what affects this
  package at this version".

## Tests

```bash
composer install && composer test
```

## License

MIT
