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

## Searching

Every lookup starts from a `PackageData` — build one from a **purl**, a **CPE**,
or explicit coordinates — and goes to one source or to all of them.

### Search all sources at once

```php
use Gumslone\Vulns\VulnSearch;

$search = app(VulnSearch::class);              // Laravel
// $search = new VulnSearch([$osv, $nvd, …]);  // plain PHP

$vulns = $search->searchPurl('pkg:npm/lodash@4.17.20');
$vulns = $search->searchCpe('cpe:2.3:a:prasathmani:tiny_file_manager:2.6:*:*:*:*:*:*:*');
$vulns = $search->search(new PackageData(name: 'lodash', version: '4.17.20', ecosystem: 'npm'));

foreach ($vulns as $v) {
    printf("%s  %s  %s\n", $v->vulnId, $v->severity->value, $v->cvssV3Score ?? '-');
}
```

Results are **merged across sources** by canonical id (the CVE when any source
knows one), aliases pooled, and the richest field kept — OSV's version ranges
plus NVD's CVSS score end up on the same record, sorted by score.

A source that fails does **not** abort the search; check `errors()` so an
unreachable feed reads as "possibly incomplete", never as "clean":

```php
if ($search->errors()) {
    logger()->warning('Vulnerability sources failed', $search->errors());
}
```

### Choosing which sources to search

`only()` and `except()` return a restricted copy — the library equivalent of
the CLI's `--source=`:

```php
$search->only('nvd')->searchCpe($cpe);              // one source
$search->only(['osv', 'github'])->searchPurl($purl); // a subset
$search->except('snyk')->search($package);           // everything but one

$search->availableSources(); // ['osv','github','nvd','cve_search','euvd','snyk']
$search->sources();          // the enabled subset this instance will query
```

An unknown name throws rather than quietly searching fewer feeds — a typo that
silently narrowed the search would look exactly like "nothing found".

Batching lets sources use their bulk endpoints and request pooling — one call
for a whole lockfile, results keyed like the input:

```php
$byPackage = $search->searchBatch([
    'lodash'  => PackageData::fromPurl('pkg:npm/lodash@4.17.20'),
    'guzzle'  => PackageData::fromPurl('pkg:composer/guzzlehttp/guzzle@7.9.0'),
]);
$byPackage['lodash']; // VulnerabilityData[]
```

Look one advisory up by id across every source:

```php
$search->fetchById('CVE-2021-44228');
$search->fetchById('GHSA-jfh8-c2jp-5v3q');
```

### Calling one source directly

```php
use Gumslone\Vulns\Data\PackageData;
use Gumslone\Vulns\Sources\NvdSource;

$nvd = app(NvdSource::class);                       // Laravel (config-wired)
// $nvd = new NvdSource(new CpeResolver, options: ['api_key' => env('NVD_API_KEY')]);

$vulns = $nvd->queryPackage(PackageData::fromCpe('cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*'));
$vulns = $nvd->queryBatch([$pkgA, $pkgB]);          // batch/pooled where supported
$one   = $nvd->fetchById('CVE-2021-44228');         // single advisory
```

### What each source needs

| Source | Queried by | Needs | Notes |
|---|---|---|---|
| `OsvSource` | ecosystem + name + version; **purl** (deb/apk/rpm); **git commit** | — | Batch endpoint, pagination, payload cache. Unmapped ecosystems are skipped, not guessed. |
| `NvdSource` | **CPE** | `api_key` recommended | 5 req/30s anonymous, 50/30s with a key — the source throttles itself. Parses `configurations` into real version ranges. |
| `CveSearchSource` | **CPE** | — | CIRCL; records often carry no version data (treat as undeterminable). |
| `GitHubAdvisorySource` | ecosystem + name (registry); **owner/repo** (repository advisories) | `token` for the registry feed | Repository advisories work **without** a token — they cover projects that are in no registry database. |
| `EuvdSource` | ecosystem + name | — | ENISA EUVD. |
| `SnykSource` | **purl** | `token` + `org_id` | Disabled unless both are configured. |

A CPE-driven source given a package without a CPE derives one from the purl or
name (`CpeResolver`), or from your curated catalog if you bind
`Contracts\CpeLookup`. Passing `PackageData::fromCpe(...)` — or `cpe23:` on the
constructor — always wins over both.

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
