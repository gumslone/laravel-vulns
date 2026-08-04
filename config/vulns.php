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
    'osv' => [
        'enabled' => env('VULNS_OSV_ENABLED', true),
        'base_url' => env('VULNS_OSV_URL', 'https://api.osv.dev/v1'),
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
        'base_url' => env('VULNS_EUVD_URL', 'https://euvd.enisa.europa.eu/api'),
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
];
