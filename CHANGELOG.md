# Changelog

## 1.23.0

### Added
- **Version ranges and wildcards, on both sides** (`Support\VersionSet`).
  An advisory range may be written in any common syntax, not only `>= a, < b`: alternatives
  (`5.4.x || 5.5.x`, Composer's `|`), wildcards (`1.2.*`, `1.x`, Gradle's `1.2.+`), caret,
  tilde (`~`, `~>`, `~=`), hyphen ranges and Maven / NuGet intervals — all of which used to be
  "can't tell". And the **installed** version may itself be a constraint (`^1.6.0` from a
  manifest without a lock file, `1.x` typed into a search): `VersionRange::isVulnerable()`
  then answers whether the versions it allows overlap an affected range, `isPastAllFixes()`
  goes by its lowest allowed version, and `VulnSearch` filters accordingly —
  `axios@1.18.x` finds what can affect that line instead of every advisory axios ever had.
  OSV is asked without a version for a constraint (it matches exact versions only), OSS Index
  and Snyk are skipped, and a CPE built for one carries `*`. Reading is strict: prose, `!=`,
  `latest`, a branch name or an unorderable bound stay "can't tell"; where ecosystems
  disagree (`~1.2`) the wider reading is taken. A bare version as an advisory range (`8`) is
  still left to the source that knows what it means.
- **`VulnerabilityLookupSource`** — [Vulnerability-Lookup](https://www.vulnerability-lookup.org),
  the successor of cve-search, through its documented API
  (`/api/vulnerability/search/{vendor}/{product}`, `/api/vulnerability/{id}`). Source name
  `vulnerability_lookup`, default instance `vulnerability.circl.lu`, record links to
  `…/vuln/{id}`; config block `vulns.vulnerability_lookup` (`VULNS_VULNERABILITY_LOOKUP_*`),
  registered in the service provider and the default priority order next to `cve_search`.
  It shares the record parsing of `CveSearchSource` (CNA / CISA ADP / legacy v4 version data).
  Background: `cve.circl.lu` — the default of `CveSearchSource` — has been a
  Vulnerability-Lookup instance for a while and only still answers `/api/search` and
  `/api/cve` as undocumented aliases; both sources return identical data from it.
  **Opt-in**, so nothing changes for existing set-ups: enable it with
  `VULNS_VULNERABILITY_LOOKUP_ENABLED=true` and set `VULNS_CVE_SEARCH_ENABLED=false` — with
  both on against the same service every lookup is made twice.

### Fixed
Found by an independent review of 1.22.1 – 1.22.4.

- **NVD: retries bypassed the pacer.** A retry was sent straight from the HTTP middleware, so
  it never counted against the rate budget: one worker whose requests each met a 503 put ten
  requests into a 30 s window against a limit of five, and a 403's retry left together with the
  next paced request — the very thing that earns the next 403. A retry now sits out its
  back-off and then takes its turn in the pacer like any first attempt.
- **NVD: a 403 / 429 was retried eight times.** Raising the retry count for 5xx in 1.22.2 also
  applied it to throttle statuses — 450 s of waiting instead of the 150 s the changelog
  promised. They keep three retries (`NvdSource::THROTTLE_RETRIES`); `RetryHandlerFactory`
  gains `throttleMaxRetries`.
- **NVD: empty settings.** `VULNS_NVD_RETRY=` meant "never retry" and an empty
  `VULNS_NVD_MIN_INTERVAL` / `VULNS_NVD_RETRY_DELAY` meant zero spacing / an immediate retry.
  Empty now reads as unset. A negative `Retry-After` no longer reaches the HTTP handler
  (it threw).
- **`VulnSearch`: a source that failed was asked again.** Range and alias completion looked
  ids up on a source that had just failed outright in the same search — with patient retries,
  minutes of extra waiting. A source that is down is skipped for the rest of the search.
- **EUVD: one package's answer served to another.** Packages were grouped by vendor and name
  only, so two that differ in their CPE vendor — the Rust crate `openssl` and OpenSSL itself —
  shared one filtered answer, in a batch and across the cache: whichever came first decided
  for both. The identity (and the cache key) now includes the vendor hint.
- **EUVD: the same search repeated per package.** `@vueuse/core`, `@inertiajs/core` and
  `@babel/core` each walked every page of the search for "core". Packages that search the
  same bare name now share the pages.
- **EUVD: a sibling product's range could clear the package.** An advisory naming `vite`
  without version text and `vite-plugin-foo <1.0.0` was dropped for vite 5.0.0. The package's
  own entries decide; a product named without usable version text counts as "cannot tell".
- **EUVD: names with more records than can be read.** A bare name such as "version" (9,090
  records) or "core" was paged to `max_pages`, cut off and reported as incomplete — every
  time, and nothing of it was about the package. Such a search is now repeated narrowed by
  EUVD's own vendor filter to the package's vendor, its CPE vendor or — for a package with
  neither — its own name, which is all the matching rules would accept anyway: two requests
  and a complete answer instead of twenty and none. Only when even the vendor's share is too
  large is the package still flagged.
- **EUVD: "1.7.0, < 1.16.0" lost its lower bound** to the comma and read as "below 1.16.0".
- **EUVD: Go modules searched by their major-version suffix** (`…/jwt/v5` searched "v5",
  `gopkg.in/yaml.v3` "yaml.v3").
- **`ProductMatch`: real vendor shapes were missed** — `vuejs` for `vue` and `koajs` for `koa`
  (short names), `thephpleague` for `league/*`, the vendor of PHP and Node.js themselves
  (their names are "noise" words elsewhere), `Apache Log4j2` / `Apache Tomcat` for the Maven
  artifacts. A placeholder product name (`n/a`) is treated as no name, not as a mismatch.
- `VulnsServiceProvider` now gives `EuvdSource` the bound `CpeLookup`, so 1.22.4's vendor
  hint works for hosts that use the package's own provider.

### Changed
- `CveSearchSource` is now described as what it is — the adapter for a self-hosted
  cve-search — and exposes `label()`, `searchPath()`, `recordPath()` and `recordUrl()` as
  protected extension points. Its behaviour, name, endpoints and cache entries are unchanged.

## 1.22.4

### Fixed
- **EUVD: same-named products of different vendors.** 1.22.3 accepts an unscoped package when
  the advisory's vendor is related to the package *name* — right for `axios` by `axios`, wrong
  for the Rust crate `openssl`, which collected OpenSSL's own 34 CVEs. `EuvdSource` now takes
  the optional `CpeLookup` the NVD and CVE-Search sources already use (5th constructor
  argument) and treats the vendor of the package's curated CPE — or of a `cpe23` supplied on
  the package — as its vendor: `openssl` (CPE vendor `sfackler`) no longer matches OpenSSL,
  while `express` (`expressjs`), `lodash`, `vite` and `axios` are unchanged. NVD's synthetic
  `<name>_project` vendors are read as the name. Without a lookup nothing changes.
  `ProductMatch::concerns()` gains `vendorHints`.

## 1.22.3

### Fixed
- **EUVD: advisories about other products were reported against the package.** EUVD's search
  answers every product whose name *contains* the term, and the source kept a hit whenever
  none of its products matched the package ("nothing to judge by"), never looking at the
  vendor. A generic name collected hundreds of unrelated advisories: a live fetch put Jenkins,
  Intel and Microsoft configuration tools on `league/config` (185), .NET on `laravel/framework`
  (167) and 685 records on the npm package `he` — 5,700 false findings across 98 packages.
  Each hit is now checked with the new `Support\ProductMatch`: the product must be the package
  (same name, or `vendor/name`), and the vendor must be related to the package's vendor / scope
  / group — or, for a package without one, to its own name. A looser name match (`log4j` ~
  `log4j-core`) counts only with a vendor match; a record naming no product is still kept.
  Against live EUVD: `league/config`, `he`, `ms`, `symfony/process` → 0; `laravel/framework`
  → 6, `express` → 6 (their own CVEs). `match` / `VULNS_EUVD_MATCH=name` restores name-only
  matching for exact names.
- **EUVD memory.** Hits are filtered page by page instead of being collected first — one
  lookup for `core` peaked at 99 MB (and killed 128 MB queue workers); it now stays under
  15 MB. Lookups are grouped, and cached, per package identity rather than per bare name, so
  `@vueuse/core` and `@inertiajs/core` no longer share one answer.

### Changed
- EUVD is searched by the package's bare name (`laravel/framework` → `framework`); the vendor
  is matched from EUVD's own vendor field.

## 1.22.2

### Fixed
- **NVD: 1.22.1 gave up too early.** Its three quick retries (2 s, 4 s, 8 s) are over after
  14 s, but NVD's `503 No server is available` bursts also last a minute and more. The lookup
  then failed, and a failed lookup costs the caller NVD's answer for the whole batch — in a
  live fetch every batch that met such a burst lost NVD for all its packages, which 1.22.0's
  slow 30 s / 60 s waits had ridden out. The 5xx back-off now starts as quick and doubles up
  to a window's length, with eight retries by default (`retry` / `VULNS_NVD_RETRY`): 2, 4, 8,
  16, 30, 30, 30, 30 s — the same 150 s of patience as 1.22.0, but a short burst is over in
  seconds. 403 / 429 are unchanged (a full window each).

## 1.22.1

### Changed
- **NVD: a 5xx is retried in seconds, not after a full rate-limit window.** 1.22.0 waited 30 s,
  then 60 s, on every retryable NVD failure. That is right for a 403 / 429 — a blown rate
  limit only time clears — but NVD's front end also answers `503 No server is available` in
  bursts lasting a few seconds, to keyed and well-paced clients alike, and a batch then spent
  about half its run asleep. A 5xx or a dropped connection is now retried after 2 s, 4 s, 8 s
  (`retry_delay` / `VULNS_NVD_RETRY_DELAY`), never sooner than the request spacing (6 s, 12 s,
  12 s without an API key, so a retry cannot itself break the limit); 403 / 429 still wait out
  the window.
- `RetryHandlerFactory::stack()` / `middleware()` take `throttleDelayMs` and
  `throttleMaxDelayMs`: throttle statuses can be paced separately from 5xx and connection
  errors. Both default to the existing delays, so other callers behave as before.

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
