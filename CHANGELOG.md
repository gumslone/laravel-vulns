# Changelog

## 1.22.0

### Fixed
- **NVD rate limiting**: the pacer counted requests per calendar window, so up to twice the
  budget could land within seconds across a window boundary — NVD answers that with 403 /
  "too many connections" and `vulns:audit` died on it. `NvdSource` now keeps a ROLLING window
  (5 requests / 30 s anonymous, 50 with a key), spaces requests the way NVD asks (6 s without a
  key, 0.6 s with one; `min_interval`), shares the budget between workers through the cache,
  and retries a 403 / 429 / 503 after a full window instead of half a second later.
  `vulns:audit` warns up front how long an unkeyed NVD pass will take.
- **CVE-Search false positives**: records whose CNA block is the MITRE placeholder
  (`vendor/product/version: n/a`) were "affected, no bound" — undeterminable, so a 2018 CVE
  was reported against every later release. The placeholder is now no statement; the CISA
  ADP "Vulnrichment" block (`containers.adp[].affected`, matched by product or `cpes`) and
  the embedded legacy v4 record (`version_affected` + `version_value`, "5.5.x before 5.5.21",
  "through 8.70.2") are read; a lone "8" / "5.1" on an affected row is its release line
  (`>= 8, < 9`), not the single build 8.0.0 that zero-padding would clear 8.5.0 against.
- CVE-Search record links follow a configured `base_url` (a self-hosted instance's own UI)
  instead of always pointing at cve.circl.lu.

### Added
- `VulnSearch::completeRanges()` (config `vulns.complete_ranges`, **on by default** in
  Laravel): advisories the version filter cannot judge are looked up once by id on GitHub and
  NVD and judged again — only a proven "outside every range naming the package" drops one.
  A record whose own ranges could not be read ("0.0.0 to unspecified"), or that only says
  "affected from X" with no upper bound (a CNA's disclosure-time "no fix known"), takes the
  lookup's ranges as its evidence — the merge would otherwise keep the record's own and NVD's
  `< 1.16.0` would never get a vote. Bounded per search (`max`, reported under `errors()['ranges']`); a
  failing feed lands under its name. This is what clears `CVE-2020-19316` ("Laravel before
  5.8.17") and `CVE-2020-7776` from a current audit.
- `VulnSearch::enabledSources()`.
- `RetryHandlerFactory::stack()` / `middleware()` take the 4xx statuses that mean "slow down"
  for an API and a cap on one back-off pause; `AbstractSource::makeClient()` accepts a
  source-specific handler.
- README: a table of every source's base-URL override (`VULNS_*_URL`) for mirrors and
  self-hosted instances; NVD pacing knobs (`VULNS_NVD_RATE_WINDOW`, `VULNS_NVD_RATE_MAX`,
  `VULNS_NVD_MIN_INTERVAL`).

## 1.21.0

### Added
- `VulnSearch::completeAliases()` (config `vulns.complete_aliases`): CVE-only records are looked
  up once by id on OSV / GitHub after the merge, so a CVE reported by NVD or CVE-Search gains its
  GHSA / GO- / PYSEC- aliases (and any gap the lookup fills). Off by default; bounded per search;
  a failing feed lands in `errors()`.
- `GitHubAdvisorySource::fetchById()` accepts CVE ids (looked up through the advisory's CVE
  identifier); `knowsId()` reflects it.
- `VulnerabilityData::altId()` (GHSA first, else the first other alias) and `ghsaId()`.
- `fetchById()` answers on OSV and GitHub are cached per id — "no such id" included —
  under the same `result_cache_ttl` as product lookups.

## 1.20.1

### Fixed
- CVE-Search: newer / self-hosted instances (Vulnerability-Lookup) spell the flat record's
  keys in camelCase (`cvssVector`, `cvss3Vector`, `cvss4Vector`, `published`, `lastModified`)
  and send `cwe` as a list. The vectors were dropped and the list made every lookup throw —
  so no CVE arrived at all. All spellings are read now; `cwe` may be a string, a list of
  strings or a list of `{id}` objects (non-CWE markers like `NVD-CWE-Other` are ignored);
  a flat v4 vector lands in the v4 slot; an unparseable date no longer drops the record.

## 1.20.0

### Added
- `php artisan vulns:audit` — audits the app's own `composer.lock` / `package-lock.json`
  (`--no-dev`, `--min-severity`, `--source`, `--format=table|json|sarif`); exit 1 on findings,
  3 when nothing was found but a source failed. `Support\LockfileReader` behind it.
- `Gumslone\Vulns\Facades\Vulns` (auto-aliased as `Vulns`).
- `Events\SourceFailed` / `Events\SearchCompleted`, dispatched through Laravel's dispatcher
  (`vulns.events`) or any callable via `VulnSearch::listen()`.
- Exporters: `OsvExporter`, `CycloneDxExporter`, `SarifExporter`, `OpenVexExporter`.
- Lookup caching for the product-level feeds (NVD, CVE-Search, EUVD, Shodan CVEDB, Red Hat):
  complete answers only, `result_cache_ttl` per source (default 3600, `0` = off).
- README: custom sources (`vulns.sources` tag), exporting, caching, the audit command.

### Fixed
- Snyk / OSS Index `supports()` no longer throw for coordinates no purl can express.

### Packaging
- PHPStan (level 5) and Pint are dev dependencies and CI jobs; `composer check` runs all three.
- CI matrix: PHP 8.2–8.5 × Laravel 11 / 12 / 13 (Testbench 9–11) plus a lowest-dependencies job,
  and `composer audit`.
- `.gitattributes` keeps tests and tooling out of the dist archive; composer description and
  keywords cover all eleven sources.

## 1.19.0

### Added
- `VulnSearch::report()` → `SearchReport`: results, errors and coverage of ONE call in an
  immutable value (`for()`, `isComplete()`, `isConclusive()`, `inconclusiveKeys()`, JSON) —
  safe where the instance is shared (Octane, queue workers).
- `searchAny()` recognises the OSV-family and distro advisory ids (PYSEC-, RUSTSEC-, GO-, MAL-,
  OSV-, SNYK-, RHSA-, DSA-, USN-, ALSA-, SUSE-SU-, …) via
  `VulnerabilityData::looksLikeAdvisoryId()`; package names like `left-pad` still throw.
- `VulnerabilityData::affects()`, `recommendedFix()`; both records are `JsonSerializable` and
  `Arrayable` (`json_encode($vuln)` is `toArray()`).
- `Version::order()`: fail-safe ordering of pre-release tags, build metadata and Maven release
  markers; `VersionRange` evaluates OSV event timelines and ignores GIT ranges. OSV ranges are
  tagged with their package (`product`).
- Sources declare which ids they can look up (`knowsId()`): a CVE-only feed asked for a GHSA is
  *skipped* — no request, no bogus error — and `fetchById()` now fills `coverage()`.
- KEV / withdrawn state that was dropped: NVD & VulnCheck `cisaExploitAdd`/`cisaActionDue`,
  MITRE's CISA-ADP `kev` metric, EUVD `exploitedSince`, CVE-Search `REJECTED`, VulnCheck `Rejected`.

### Fixed
- `PurlBuilder`: the name is the last path segment (Go modules round-trip:
  `pkg:golang/github.com/gin-gonic/gin`), version `"0"` is kept, qualifiers are parsed by hand
  (no `parse_str` mangling), empty qualifiers dropped, subpaths normalised, types validated,
  names normalised per type (pypi, github, npm, composer, deb, …); `checksum()` canonicalises
  instead of lowercasing the whole purl. **Changed:** purls built for those types are lowercase.

## 1.18.0

### CVSS
- v4.0 scores that are exactly x.x5 round up like the FIRST reference calculator
  (they arrived as x.x4999… and landed 0.1 low — 522 base vectors, none across a
  severity band).
- One validation table for every parser (`CvssVector`, `CvssCalculator`, `Cvss4`,
  `Cvss2`): an illegal value (`AV:Z`, a v3 `UI:R` in a v4 vector, `E:Z`), a
  repeated metric or a `CVSS:3.2` prefix is a malformed vector everywhere —
  **previously some paths scored them**. Case and a trailing slash are tolerated
  everywhere.
- v3 temporal/environmental modifiers are validated: a typo returns `null` instead
  of scoring 0.0 with a PHP warning; lowercase keys work as on v2/v4.
- A CVSS score outside 0.0–10.0 is discarded by `VulnerabilityData`.

### Security
- `VulnerabilityData` allow-lists links: `references` entries and `sourceUrl` must
  be absolute http(s)/ftp URLs — `javascript:` / `data:` links relayed by a feed are
  dropped at construction (`VulnerabilityData::isSafeUrl()`).

### Sources
- NVD / VulnCheck prefer the `Primary` CVSS assessment over a CNA's `Secondary`.
- GitHub reads `cvssSeverities` (v3 **and** v4; the single `cvss` field is
  deprecated) and `withdrawnAt` → `isWithdrawn`.
- Snyk files `CWE-…` problems under `cwes` instead of `aliases`.

## 1.17.0

A correctness release: every item below either reported a vulnerable package
as clean or showed one advisory several times. **Behaviour changes are marked.**

### False negatives fixed
- `VersionRange`: versions are zero-padded before comparing — `1.0` is inside
  `>= 1.0.0, < 1.5.0`, NuGet `4.0.0.0` equals `4.0.0`.
- `VersionRange::isVulnerable()` answers `null`, not `false`, while **any**
  range is unreadable (Maven qualifiers, pre-releases, `||`, OSV event lists).
  `*` means every version. `isPastAllFixes()` is `false` when a fix can't be
  ordered; a numeric `1:` prefix is an epoch, not an ecosystem.
- `PackageData::fromPurl()` names Maven packages `group:artifact` (was
  `group/artifact`, which OSV and GitHub answer with nothing — Log4Shell read
  as clean). New `registryName()`; CPE product inference strips the group. **Changed.**
- NVD: range checks go through `VersionRange` (raw `version_compare` dropped
  `1.1.1k` and `5.3.0.RELEASE`), judge the queried product's ranges only, and
  an unbounded "all versions" match is kept as `*` instead of being reduced to
  the pins beside it (also VulnCheck). Ranges now carry `product`.
- OSV: an advisory whose details can't be fetched is kept as an id-only record
  (`extra.details_unavailable`) and reported, instead of vanishing.
- GitHub: a GraphQL error (rate limit) is attributed to its package on any
  page; a 403/5xx on repository advisories is a failure, not "no advisories".
- CVE-Search, EUVD, Shodan CVEDB and Red Hat walk **every** page (`max_pages`
  caps, reported when hit) — page 1 held only the newest CVEs.
- `fetchById()` throws when a feed is down (OSV, NVD, GitHub, EUVD,
  CVE-Search); `null` is reserved for a real "no such record". **Changed.**
- A 200 response that isn't JSON is a failed lookup in every source.

### Merging and filtering
- Records merge when they share **any** id, transitively (GHSA ↔ CVE ↔ SNYK),
  not only a CVE. Ids and aliases are normalised (trim, casing, de-duplicated).
- References, CWEs and fixed versions are pooled across feeds — an EXPLOIT
  link no longer disappears because another feed won the merge.
- `VulnSearch` drops advisories the version provably escapes
  (`filterByVersion()`, `vulns.version_filter`). **Changed:** name-only feeds
  used to return every advisory the name ever had.
- Red Hat is only asked about OS-level packages (`ecosystems` option) and by
  bare RPM name (`pkg:rpm/redhat/openssl` → `openssl`). **Changed.**
- Sources report partial trouble via `warnings()` / `incompleteKeys()`;
  `VulnSearch` folds them into `errors()` and `coverage()['failed']`.
- `coverage()` is reset by `fetchById()`.

### Security
- CVE-Search encodes vendor/product path segments.
