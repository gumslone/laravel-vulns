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
        // 5 requests/30s anonymous, 50/30s with a key.
        'rate_limit_window' => 30,
        'rate_limit_max' => env('VULNS_NVD_RATE_MAX'),
    ],

    'cve_search' => [
        'enabled' => env('VULNS_CVE_SEARCH_ENABLED', true),
        'base_url' => env('VULNS_CVE_SEARCH_URL', 'https://cve.circl.lu/api'),
        'page_size' => (int) env('VULNS_CVE_SEARCH_PAGE_SIZE', 100),
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
        'max_concurrency' => (int) env('VULNS_REDHAT_CONCURRENCY', 8),
    ],

    'shodan_cvedb' => [
        // Shodan CVEDB — free, no key; carries CVSS + EPSS + KEV per record
        // and supports product search.
        'enabled' => env('VULNS_SHODAN_CVEDB_ENABLED', true),
        'base_url' => env('VULNS_SHODAN_CVEDB_URL', 'https://cvedb.shodan.io'),
        'page_size' => (int) env('VULNS_SHODAN_CVEDB_PAGE_SIZE', 50),
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
