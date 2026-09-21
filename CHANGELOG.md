# Changelog

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
