<?php

declare(strict_types=1);

/*
|--------------------------------------------------------------------------
| Vulnerability sources
|--------------------------------------------------------------------------
|
| One block per source, passed verbatim to the source's $options. Every
| source understands `enabled`, `timeout` and `retry`; the rest are
| source-specific. Publish with:
|
|   php artisan vendor:publish --tag=vulns-config
|
*/

return [
    /*
    |--------------------------------------------------------------------------
    | Merge behaviour
    |--------------------------------------------------------------------------
    |
    | When several sources describe the same advisory, `priority` is the trust
    | order: the earliest-listed source's record becomes the merge base — its
    | score, severity and summary win, the rest only fill gaps.
    |
    | `merge` = 'latest' makes the most recently modified record win instead,
    | so a CVSS rescore or rewritten description reaches the result no matter
    | which feed published it first (records without a modification date fall
    | back to the priority order). Default 'priority'.
    |
    */
    'priority' => [
        'osv', 'github', 'nvd', 'mitre', 'redhat', 'oss_index',
        'vulncheck', 'snyk', 'euvd', 'shodan_cvedb', 'cve_search',
    ],
    'merge' => env('VULNS_MERGE', 'priority'),

    /*
    | Several feeds answer by package NAME alone (GitHub, CVE-Search, Shodan),
    | so VulnSearch drops advisories the package's version provably escapes.
    | Only a provable miss is dropped — a range that can't be read or ordered
    | keeps the advisory. Set false to receive everything a name ever had.
    */
    'version_filter' => env('VULNS_VERSION_FILTER', true),

    /*
    | Complete the ids of CVE-only records: a CVE from NVD / CVE-Search comes
    | without its GHSA (PYSEC, GO-, …) aliases, and when OSV / GitHub had no
    | package-level answer those ids never arrive. On, every such CVE is looked
    | up once by id (cached) on the listed sources after the merge — one extra
    | request per NEW CVE per source, at most `max` per search. Off by default.
    */
    'complete_aliases' => [
        'enabled' => env('VULNS_COMPLETE_ALIASES', false),
        'sources' => ['osv', 'github'],
        'max' => (int) env('VULNS_COMPLETE_ALIASES_MAX', 50),
    ],

    // Dispatch Events\SourceFailed / Events\SearchCompleted through Laravel's
    // event dispatcher (listen for them like any other event).
    'events' => env('VULNS_EVENTS', true),

    /*
    |--------------------------------------------------------------------------
    | Threat enrichment
    |--------------------------------------------------------------------------
    |
    | Merged results are stamped with EPSS (FIRST.org's probability of
    | exploitation in the wild within 30 days — free, no key) and CISA KEV
    | (confirmed actively exploited). Both key off CVE ids and are cached;
    | a failing feed leaves results un-enriched and lands in errors().
    |
    */
    /*
    |--------------------------------------------------------------------------
    | Built-in search UI
    |--------------------------------------------------------------------------
    |
    | A single dependency-free page: paste an advisory id, purl, CPE, commit
    | or package URL and see the merged, enriched results. Disabled by
    | default — enable it and put auth middleware in front for production.
    |
    */
    'ui' => [
        'enabled' => env('VULNS_UI_ENABLED', false),
        'path' => env('VULNS_UI_PATH', 'vulns'),
        // Throttled by default: every search fans out to all enabled sources
        // (burning YOUR rate-limited API quotas). Add auth for production.
        'middleware' => ['web', 'throttle:30,1'],
    ],

    'epss' => [
        'enabled' => env('VULNS_EPSS_ENABLED', true),
        'base_url' => env('VULNS_EPSS_URL', 'https://api.first.org/data/v1/epss'),
        'cache_ttl' => (int) env('VULNS_EPSS_CACHE_TTL', 21600),
    ],
    'kev' => [
        'enabled' => env('VULNS_KEV_ENABLED', true),
        'url' => env('VULNS_KEV_URL', 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'),
        'cache_ttl' => (int) env('VULNS_KEV_CACHE_TTL', 21600),
    ],

    'osv' => [
        'enabled' => env('VULNS_OSV_ENABLED', true),
        // Requests append 'v1/...' themselves; a legacy '/v1' suffix here is
        // tolerated (stripped) for configs written against older releases.
        'base_url' => env('VULNS_OSV_URL', 'https://api.osv.dev'),
        // Raw advisory payloads are cached by id+modified stamp.
        'cache_ttl' => (int) env('VULNS_OSV_CACHE_TTL', 604800),
        'max_concurrency' => (int) env('VULNS_OSV_CONCURRENCY', 8),
    ],

    'github' => [
        // Repository advisories work without a token; the registry GraphQL
        // feed requires one (a classic PAT with no scopes is enough).
        'enabled' => env('VULNS_GITHUB_ENABLED', true),
        'token' => env('GITHUB_TOKEN'),
        'max_concurrency' => (int) env('VULNS_GITHUB_CONCURRENCY', 8),
    ],

    'nvd' => [
        'enabled' => env('VULNS_NVD_ENABLED', true),
        'api_key' => env('NVD_API_KEY'),
        'base_url' => env('VULNS_NVD_URL', 'https://services.nvd.nist.gov/rest/json'),
        // Product lookups are cached (complete answers only); 0 disables.
        'result_cache_ttl' => (int) env('VULNS_NVD_RESULT_CACHE_TTL', 3600),
        // 5 requests/30s anonymous, 50/30s with a key.
        'rate_limit_window' => 30,
        'rate_limit_max' => env('VULNS_NVD_RATE_MAX'),
    ],

    'cve_search' => [
        'enabled' => env('VULNS_CVE_SEARCH_ENABLED', true),
        'base_url' => env('VULNS_CVE_SEARCH_URL', 'https://cve.circl.lu/api'),
        'page_size' => (int) env('VULNS_CVE_SEARCH_PAGE_SIZE', 100),
        // Every page is walked; past this cap results are kept but the
        // truncation lands in errors() and coverage() ('failed').
        'max_pages' => (int) env('VULNS_CVE_SEARCH_MAX_PAGES', 20),
        'result_cache_ttl' => (int) env('VULNS_CVE_SEARCH_RESULT_CACHE_TTL', 3600),
        // Self-hosted instances often use a private CA; set false to skip
        // certificate verification (public CIRCL should stay true).
        'verify_tls' => env('VULNS_CVE_SEARCH_VERIFY_TLS', true),
        'max_concurrency' => (int) env('VULNS_CVE_SEARCH_CONCURRENCY', 8),
    ],

    'euvd' => [
        'enabled' => env('VULNS_EUVD_ENABLED', true),
        // euvdservices — the euvd.enisa.europa.eu domain serves the SPA's
        // HTML shell on /api/*, not the API.
        'base_url' => env('VULNS_EUVD_URL', 'https://euvdservices.enisa.europa.eu/api'),
        'max_pages' => (int) env('VULNS_EUVD_MAX_PAGES', 20), // × 100 records
        'result_cache_ttl' => (int) env('VULNS_EUVD_RESULT_CACHE_TTL', 3600),
        'max_concurrency' => (int) env('VULNS_EUVD_CONCURRENCY', 8),
    ],

    'snyk' => [
        'enabled' => env('VULNS_SNYK_ENABLED', false),
        // NB: the source reads `api_token`, not `token`.
        'api_token' => env('SNYK_API_TOKEN'),
        'org_id' => env('SNYK_ORG_ID'),
        'base_url' => env('VULNS_SNYK_URL', 'https://api.snyk.io'),
        'max_concurrency' => (int) env('VULNS_SNYK_CONCURRENCY', 8),
    ],

    'oss_index' => [
        // Sonatype's component-report API is purl-native and batched (128
        // coordinates per request). Requires a free account since 2025 —
        // the source stays disabled until username + api_token are set.
        'enabled' => env('VULNS_OSS_INDEX_ENABLED', true),
        'base_url' => env('VULNS_OSS_INDEX_URL', 'https://ossindex.sonatype.org/api/v3'),
        'username' => env('OSS_INDEX_USERNAME'),
        'api_token' => env('OSS_INDEX_API_TOKEN'),
        'max_concurrency' => (int) env('VULNS_OSS_INDEX_CONCURRENCY', 4),
    ],

    'redhat' => [
        // Red Hat Security Data — free, no key; the only good source for
        // RPM-ecosystem and container base-image packages.
        'enabled' => env('VULNS_REDHAT_ENABLED', true),
        'base_url' => env('VULNS_REDHAT_URL', 'https://access.redhat.com/hydra/rest/securitydata'),
        'page_size' => (int) env('VULNS_REDHAT_PAGE_SIZE', 1000),
        'max_pages' => (int) env('VULNS_REDHAT_MAX_PAGES', 10),
        'result_cache_ttl' => (int) env('VULNS_REDHAT_RESULT_CACHE_TTL', 3600),
        // The search is by RPM name alone, so it is only asked about OS-level
        // packages: for npm's `tar` the same name is different software.
        // ['*'] asks about every ecosystem.
        'ecosystems' => ['rpm', 'redhat', 'generic', ''],
        'max_concurrency' => (int) env('VULNS_REDHAT_CONCURRENCY', 8),
    ],

    'shodan_cvedb' => [
        // Shodan CVEDB — free, no key; carries CVSS + EPSS + KEV per record
        // and supports product search.
        'enabled' => env('VULNS_SHODAN_CVEDB_ENABLED', true),
        'base_url' => env('VULNS_SHODAN_CVEDB_URL', 'https://cvedb.shodan.io'),
        'page_size' => (int) env('VULNS_SHODAN_CVEDB_PAGE_SIZE', 50),
        'max_pages' => (int) env('VULNS_SHODAN_CVEDB_MAX_PAGES', 20),
        'result_cache_ttl' => (int) env('VULNS_SHODAN_CVEDB_RESULT_CACHE_TTL', 3600),
        'max_concurrency' => (int) env('VULNS_SHODAN_CVEDB_CONCURRENCY', 8),
    ],

    'mitre' => [
        // MITRE CVE Services — the authoritative CVE record, often live
        // before NVD analysis. fetchById only (no package search).
        'enabled' => env('VULNS_MITRE_ENABLED', true),
        'base_url' => env('VULNS_MITRE_URL', 'https://cveawg.mitre.org/api'),
    ],

    'vulncheck' => [
        // VulnCheck Community ("NVD++") — requires a free API token;
        // disabled until one is configured, like Snyk.
        'enabled' => env('VULNS_VULNCHECK_ENABLED', false),
        'api_token' => env('VULNCHECK_API_TOKEN'),
        'base_url' => env('VULNS_VULNCHECK_URL', 'https://api.vulncheck.com/v3'),
    ],
];
