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

$search->availableSources(); // ['osv','github','nvd','cve_search','euvd','snyk',
                             //  'oss_index','redhat','shodan_cvedb','mitre','vulncheck']
$search->sources();          // the enabled subset this instance will query
```

An unknown name throws rather than quietly searching fewer feeds — a typo that
silently narrowed the search would look exactly like "nothing found".

### When sources disagree: priority and freshness

Several sources usually know the same CVE, with different scores, severities
and wording. The merge picks one record as the **base** — its fields win, the
others only fill gaps (ranges, vectors, references are still pooled from all).

By default the base comes from the source **trust order** — `osv → github →
nvd → snyk → euvd → cve_search`, configurable via `config('vulns.priority')`
or per call:

```php
$search->prioritize(['nvd', 'osv'])->search($package); // trust NVD's score first
```

`preferLatest()` makes the **most recently modified** record win instead, so a
CVSS rescore or rewritten description reaches the result no matter which feed
published it first — including downward rescores, which a "keep the highest
score" merge would silently undo:

```php
$search->preferLatest()->search($package);
// or globally: VULNS_MERGE=latest
```

Records without a modification date fall back to the trust order. Both
settings survive `only()` / `except()` chaining, and the merged record's
`sourceModifiedAt` always carries the base's timestamp so you can see how
fresh the winning data is.

### EPSS and KEV: how likely, and actually exploited?

CVSS says how bad; **EPSS** (FIRST.org) says how *likely* — the probability
of exploitation in the wild within 30 days — and **CISA KEV** says it *is*
being exploited. Merged results are stamped with both automatically (keyed
by canonical CVE id, cached, no API keys needed):

```php
$vuln->cvssV3Score;        // 9.8  — severity  (also cvssV4Score, cvssV2Score)
$vuln->effectiveCvssScore(); // newest standard first: v4 → v3 → v2
$vuln->epssScore;          // 0.94 — probability of exploitation (0..1)
$vuln->epssPercentile;     // 0.999 — relative to all scored CVEs
$vuln->isKnownExploited;   // true — listed in CISA KEV
```

Configure or disable via `vulns.epss` / `vulns.kev` (`VULNS_EPSS_ENABLED`,
`VULNS_KEV_ENABLED`), or per instance with `$search->withEnricher(null)`.
A failing feed leaves results un-enriched and lands in `errors()` — a
missing EPSS score reads as "unknown", never "not exploited".

### Detecting what changed on a re-query

When you refresh a stored advisory, `changesSince()` classifies the
difference so you can route on it — reopen triage on a major change, update
silently on a minor one:

```php
$change = $fresh->changesSince($stored);   // VulnChange

$change->impact();      // ChangeImpact::None | Minor | Major
$change->isMajor();     // score increased OR downgraded, severity shift,
                        // affected ranges edited, a fix appeared, listed in
                        // CISA KEV, or EPSS crossed the 0.1 triage threshold
$change->changes;       // [ChangeType::ScoreIncreased, ...]
$change->details;       // ['cvss_v3_score' => [5.0, 8.1], ...]
$change->summary();     // "score increased (5 → 8.1), description updated"
```

A description or reference update alone is `Minor`. A downgrade is
deliberately as major as an upgrade — it can release an SLA-tracked
assessment, which someone should look at rather than have slip through.
A source *dropping* its score (value → null) is treated as upstream data
loss, not a rescore.

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
| `OssIndexSource` | **purl** | — (`username`+`api_token` raise limits) | Sonatype's dataset; batched 128 purls per request. Versionless packages are skipped. |
| `RedHatSource` | name | — | Red Hat Security Data — the source for RPM-ecosystem and container base-image packages. NEVRA strings land in `extra`, not ranges. |
| `ShodanCvedbSource` | name (product search) | — | One record carries CVSS + EPSS + KEV. |
| `MitreCveSource` | `fetchById` only | — | Authoritative CVE Record v5 (incl. CNA CVSS v4), often live before NVD analysis. No package search. |
| `VulnCheckSource` | `fetchById` only | `api_token` | VulnCheck Community "NVD++" — NVD 2.0-shaped records without the NVD lag. Disabled without a token. |

A CPE-driven source given a package without a CPE derives one from the purl or
name (`CpeResolver`), or from your curated catalog if you bind
`Contracts\CpeLookup`. Passing `PackageData::fromCpe(...)` — or `cpe23:` on the
constructor — always wins over both.

## Credentials & configuration

No source needs a key to *work*; keys raise limits or unlock a feed:

| Env var | Used by | Effect if unset |
|---|---|---|
| `NVD_API_KEY` | NVD | Still works at 5 req/30s instead of 50 — the source throttles itself either way. |
| `GITHUB_TOKEN` | GitHub Advisories | **Repository** advisories still work; the registry GraphQL feed is skipped. |
| `SNYK_API_TOKEN` + `SNYK_ORG_ID` | Snyk | Source stays disabled (it needs both). |

OSV, CVE-Search and EUVD need no credentials at all.

**In Laravel — just set the env vars.** The package's config is merged
automatically, so `app(VulnSearch::class)` and every `app(…Source::class)` pick
the credentials up with no further wiring:

```dotenv
NVD_API_KEY=…
GITHUB_TOKEN=…
SNYK_API_TOKEN=…
SNYK_ORG_ID=…
```

```php
$vulns = app(VulnSearch::class)->searchPurl('pkg:npm/lodash@4.17.20');
// → OSV + GitHub + NVD (+ Snyk, once its two values are set) …
```

Publishing the config is optional — do it to change base URLs, cache TTLs,
concurrency, or to toggle sources per environment:

```bash
php artisan vendor:publish --tag=vulns-config
```

```php
// config/vulns.php
'nvd' => ['enabled' => true, 'api_key' => env('NVD_API_KEY')],
'snyk' => ['enabled' => true, 'api_token' => env('SNYK_API_TOKEN'), 'org_id' => env('SNYK_ORG_ID')],
```

Config beats env: anything you set in `config/vulns.php` (or at runtime with
`config([...])`) is what the source receives.

**In plain PHP** — there is no config file; pass the block directly, so the
credential comes from wherever you keep secrets:

```php
new NvdSource(new CpeResolver, options: [
    'api_key' => getenv('NVD_API_KEY') ?: null,
    'timeout' => 30,
]);
```

Every source also understands `enabled`, `timeout`, `retry` and `base_url`
(point CVE-Search or OSV at a self-hosted instance). Keys are read per request
and never written anywhere by this package.

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

`Gumslone\Vulns\Data\VulnerabilityData` — a normalised record, whatever source
answered. A real result from `searchPurl('pkg:npm/lodash@4.17.20')`:

```php
$v = $search->searchPurl('pkg:npm/lodash@4.17.20')[0];

$v->vulnId            // "CVE-2019-10744"
$v->canonicalId()     // "CVE-2019-10744"  — the CVE even when a source keyed it on a GHSA
$v->source            // "nvd"             — which source won the merge
$v->severity          // Severity::Critical  (->value === "critical")
$v->cvssV3Score       // 9.1
$v->cvssV3Vector      // "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H"
$v->cvssV2Score       // 6.4
$v->summary           // "Versions of lodash lower than 4.17.12 are vulnerable to Prototype Pollution…"
$v->details           // long-form description, when the source has one
$v->aliases           // ["GHSA-jf85-cpcp-j695", …]  — every other id for the same advisory
$v->affectedRanges    // [["range" => "< 4.17.12", "source" => "nvd"], …]
$v->fixedVersions     // ["4.17.12"]      (source-dependent)
$v->isFixed           // true when a fix is published
$v->cwes              // ["CWE-1321"]
$v->references        // [["type" => …, "url" => "https://…"], …]
$v->affectedEcosystems // ["npm"]         (OSV-style records)
$v->sourceUrl         // "https://nvd.nist.gov/vuln/detail/CVE-2019-10744"
$v->sourcePublishedAt // DateTimeInterface|null
$v->sourceModifiedAt  // DateTimeInterface|null
$v->rawDataChecksum   // sha256 of the raw payload — cheap change detection
$v->extra             // source-specific leftovers (e.g. ghsa_id, vuln_status)
```

Fields a given source doesn't provide are `null` or empty — merging across
sources is what fills them in, so OSV's ranges and NVD's score end up on the
same record.

### Does it actually affect my version?

Not every source version-filters: some return advisories for a package *name*.
`VersionRange` answers the real question, and deliberately distinguishes
"proven safe" from "can't tell":

```php
use Gumslone\Vulns\Support\VersionRange;

VersionRange::isVulnerable('4.17.20', $v->affectedRanges);  // true  — inside a range
VersionRange::isVulnerable('4.17.21', $v->affectedRanges);  // false — provably outside
VersionRange::isVulnerable('4.17.20', []);                  // null  — no evidence either way

// At or past every published fix, even without ranges:
VersionRange::isPastAllFixes('5.0.0', $v->fixedVersions);   // true
```

`null` means undeterminable — decide your own fail-safe (a scanner should
usually keep the finding and flag it for review rather than silently drop it).

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
