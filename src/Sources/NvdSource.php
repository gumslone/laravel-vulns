<?php

declare(strict_types=1);

namespace Gumslone\Vulns\Sources;

use Gumslone\Vulns\Contracts\CpeLookup;
use Gumslone\Vulns\Data\PackageData;
use Gumslone\Vulns\Data\VulnerabilityData;
use Gumslone\Vulns\Severity as SeverityLevel;
use Gumslone\Vulns\Support\BuildsCpeRanges;
use Gumslone\Vulns\Support\CpeResolver;
use Gumslone\Vulns\Support\ResolvesLookupCpe;
use Gumslone\Vulns\Support\RetryHandlerFactory;
use Gumslone\Vulns\Support\VersionRange;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\HandlerStack;
use Psr\Log\LoggerInterface;
use Psr\SimpleCache\CacheInterface;

/**
 * NIST National Vulnerability Database adapter.
 * API documentation: https://nvd.nist.gov/developers/vulnerabilities
 *
 * Rate limits: 5 req/30s without key, 50 req/30s with a (free) API key.
 */
class NvdSource extends AbstractSource
{
    /**
     * Retries per request when `retry` is not configured: 2 + 4 + 8 + 16 +
     * 30 × 4 = 150 s of patience for a flapping service.
     */
    public const DEFAULT_RETRIES = 8;

    use BuildsCpeRanges;
    use ResolvesLookupCpe;

    private ?string $apiKey;

    public function __construct(private readonly CpeResolver $cpeResolver, private readonly ?CpeLookup $cpeLookup = null, ?Client $http = null, array $options = [], ?LoggerInterface $logger = null, ?CacheInterface $cache = null)
    {
        $this->boot($options, $logger, $cache);
        $this->apiKey = $this->config('api_key');
        $this->http = $http ?? $this->makeClient(
            rtrim((string) $this->config('base_url', 'https://services.nvd.nist.gov/rest/json'), '/').'/',
            array_filter(['apiKey' => $this->apiKey]),
            defaultRetry: 3,
            handler: self::retryStack(
                (int) $this->config('retry', self::DEFAULT_RETRIES),
                $this->rateWindow(),
                $this->spacing(),
                $this->config('retry_delay') !== null ? (float) $this->config('retry_delay') : null,
            ),
        );
    }

    public function name(): string
    {
        return 'nvd';
    }

    public function queryPackage(PackageData $package): array
    {
        $cpe = $this->resolveLookupCpe($package);
        if (! $cpe) {
            return [];
        }

        // The lookup is by product (the match string carries no version), so
        // one answer serves every version of it — and anonymous NVD access is
        // throttled to a request every six seconds.
        $matchString = $this->matchString($cpe);
        $affecting = fn (array $cves): array => array_values(array_filter(array_map(
            fn (array $cve) => $this->versionIsAffected($cve, $package, $cpe) ? $this->parseCve($cve) : null,
            $cves,
        )));
        if (($cached = $this->cachedLookup($matchString)) !== null) {
            return $affecting($cached);
        }

        $cves = [];
        $startIndex = 0;
        // Hard safety cap: 10 pages × 2000 default page size covers any real
        // package; beyond that the truncation is reported rather than looping forever.
        $maxPages = (int) $this->config('max_pages', 10);

        try {
            for ($page = 0; $page < $maxPages; $page++) {
                $this->throttle();

                // virtualMatchString matches the CPE with wildcards against configurations
                $response = $this->http->get('cves/2.0', [
                    'query' => ['virtualMatchString' => $matchString, 'startIndex' => $startIndex],
                ]);
                $data = $this->decode($response, "NVD query for {$package->name}");

                $items = $data['vulnerabilities'] ?? [];
                foreach ($items as $item) {
                    if (is_array($item['cve'] ?? null)) {
                        $cves[] = $item['cve'];
                    }
                }

                // NVD 2.0 pages via totalResults/startIndex; an empty page
                // also ends the walk in case the server miscounts totalResults.
                $startIndex += count($items);
                if ($items === [] || $startIndex >= (int) ($data['totalResults'] ?? 0)) {
                    // A product with thousands of CVEs is too heavy to keep around.
                    if (count($cves) <= (int) $this->config('result_cache_max', 500)) {
                        $this->cacheLookup($matchString, $cves);
                    }

                    return $affecting($cves);
                }
            }
        } catch (GuzzleException|\RuntimeException $e) {
            $this->log('warning', '[vulns] NVD query failed', ['package' => $package->name, 'error' => $e->getMessage()]);

            // Fail safe: an unreachable NVD must surface as an error the
            // caller records, not read as "no known vulnerabilities".
            throw new \RuntimeException("NVD query failed for {$package->name}: {$e->getMessage()}", 0, $e);
        }

        $this->warn("results for {$package->name} truncated at {$startIndex} CVEs (max_pages={$maxPages})");

        return $affecting($cves);
    }

    public function supports(PackageData $package): bool
    {
        return $this->resolveLookupCpe($package) !== null;
    }

    public function queryBatch(array $packages): array
    {
        $results = [];
        foreach ($packages as $key => $package) {
            $results[$key] = $this->queryPackage($package);
        }

        return $results;
    }

    public function knowsId(string $vulnId): bool
    {
        return VulnerabilityData::isCveId(trim($vulnId));
    }

    public function fetchById(string $vulnId): ?VulnerabilityData
    {
        if (! $this->knowsId($vulnId)) {
            return null;
        }

        try {
            $this->throttle();

            $response = $this->http->get('cves/2.0', ['query' => ['cveId' => $vulnId]]);
            $data = $this->decode($response, "NVD lookup of {$vulnId}");
            $cve = $data['vulnerabilities'][0]['cve'] ?? null;

            return $cve ? $this->parseCve($cve) : null;
        } catch (GuzzleException $e) {
            if (self::isNotFound($e)) {
                return null;
            }

            // Fail safe: a rate-limited or unreachable NVD is not "unknown CVE".
            throw new \RuntimeException("NVD lookup failed for {$vulnId}: {$e->getMessage()}", 0, $e);
        }
    }

    private function parseCve(array $cve): ?VulnerabilityData
    {
        if (empty($cve['id'])) {
            return null;
        }

        $description = collect($cve['descriptions'] ?? [])->firstWhere('lang', 'en')['value'] ?? null;

        [$v3Score, $v3Vector] = $this->cvssMetric($cve['metrics'] ?? [], ['cvssMetricV31', 'cvssMetricV30']);
        [$v2Score, $v2Vector] = $this->cvssMetric($cve['metrics'] ?? [], ['cvssMetricV2']);
        [$v4Score, $v4Vector] = $this->cvssMetric($cve['metrics'] ?? [], ['cvssMetricV40']);

        $bestScore = $v4Score ?? $v3Score ?? $v2Score;
        $severity = $bestScore !== null ? SeverityLevel::fromCvssScore($bestScore) : SeverityLevel::Unknown;

        $cwes = [];
        foreach ($cve['weaknesses'] ?? [] as $weakness) {
            foreach ($weakness['description'] ?? [] as $desc) {
                if (str_starts_with($desc['value'] ?? '', 'CWE-')) {
                    $cwes[] = $desc['value'];
                }
            }
        }

        $references = array_map(
            fn ($r) => ['type' => implode(',', $r['tags'] ?? []) ?: null, 'url' => $r['url'] ?? ''],
            $cve['references'] ?? [],
        );

        return new VulnerabilityData(
            vulnId: $cve['id'],
            source: 'nvd',
            summary: $description ? mb_substr($description, 0, 255) : null,
            details: $description,
            severity: $severity,
            cvssV3Score: $v3Score,
            cvssV3Vector: $v3Vector,
            cvssV2Score: $v2Score,
            cvssV2Vector: $v2Vector,
            cvssV4Score: $v4Score,
            cvssV4Vector: $v4Vector,
            isKnownExploited: $this->cisaKev($cve)[0],
            kevSince: $this->cisaKev($cve)[1],
            kevDueDate: $this->cisaKev($cve)[2],
            isWithdrawn: ($cve['vulnStatus'] ?? '') === 'Rejected',
            // NVD marks contested records via cveTags since ~2023; older
            // records embedded a DISPUTED marker in the description text.
            isDisputed: $this->isDisputed($cve, $description),
            affectedRanges: $this->configurationRanges($cve['configurations'] ?? []),
            references: $references,
            cwes: array_values(array_unique($cwes)),
            sourcePublishedAt: isset($cve['published']) ? new \DateTime($cve['published']) : null,
            sourceModifiedAt: isset($cve['lastModified']) ? new \DateTime($cve['lastModified']) : null,
            sourceUrl: "https://nvd.nist.gov/vuln/detail/{$cve['id']}",
            rawDataChecksum: hash('sha256', json_encode($cve)),
            extra: ['vuln_status' => $cve['vulnStatus'] ?? null],
        );
    }

    /**
     * Check the CVE `configurations` node to determine whether the package
     * version falls inside any affected CPE match range.
     */
    private function versionIsAffected(array $cve, PackageData $package, ?string $lookupCpe = null): bool
    {
        if (! $package->version) {
            return true; // no version to judge — keep and let assessment decide
        }

        $ranges = $this->configurationRanges($cve['configurations'] ?? []);

        // Judge by the queried product's own ranges: a sibling product's
        // "< 9.0.0" says nothing about this one. (When no vulnerable match
        // names it — a platform-only match — every range is considered.)
        $cpe = $lookupCpe !== null ? $this->cpeResolver->parse23($lookupCpe) : [];
        $product = strtolower(($cpe['vendor'] ?? '').':'.($cpe['product'] ?? ''));
        $own = array_values(array_filter($ranges, fn (array $r) => $r['product'] === $product));

        // VersionRange is fail-safe where raw version_compare is not: it
        // refuses to order "1.1.1k" or "5.3.0.RELEASE" rather than sort them
        // below the bound and clear a vulnerable package. Only a provable
        // "outside every range" drops the CVE.
        return VersionRange::isVulnerable($package->version, $own ?: $ranges) !== false;
    }

    private function isDisputed(array $cve, ?string $description): bool
    {
        foreach ($cve['cveTags'] ?? [] as $tagGroup) {
            foreach ((array) ($tagGroup['tags'] ?? []) as $tag) {
                if (strcasecmp((string) $tag, 'disputed') === 0) {
                    return true;
                }
            }
        }

        return str_contains($description ?? '', 'DISPUTED');
    }

    /**
     * Convert a full CPE 2.3 string into a wildcard match string
     * (drop the exact version so ranges are matched server-side).
     */
    private function matchString(string $cpe): string
    {
        $parts = $this->cpeResolver->parse23($cpe);

        return implode(':', [
            'cpe', '2.3', $parts['part'], $parts['vendor'], $parts['product'],
            '*', '*', '*', '*', '*', '*', '*', '*',
        ]);
    }

    /**
     * The retrying handler for NVD, which fails in two distinct ways:
     *
     * - 403 (not 429, and without Retry-After) is a blown rate limit. Only
     *   time clears it, so the retry waits out a full window — a slipped
     *   limit becomes a delay, not a silent empty result.
     * - 5xx — typically "503 No server is available" from NVD's front end —
     *   and dropped connections are the service flapping. Most bursts clear
     *   within seconds, so the first retry is quick: `$retryDelay` seconds,
     *   doubling up to a window's length (2, 4, 8, 16, 30, 30 … s). It is
     *   never quicker than the pacer's `$spacing`, because a retry is a
     *   request like any other and must not itself break the limit.
     *
     * Both extremes have been tried and failed. Waiting a full window on
     * every 503 (1.22.0) made a batch spend half its run asleep. Three quick
     * retries (1.22.1; 14 s in all) gave up while NVD was still mid-burst —
     * bursts of a minute and more occur — and a failed lookup costs the
     * caller NVD's answer for the whole batch. Hence quick first, patient
     * overall: with the default eight retries the lookup rides out two and a
     * half minutes of trouble, as 1.22.0 did, but recovers from a short burst
     * in seconds.
     *
     * @param  float|null  $retryDelay  first 5xx back-off in seconds; null = 2 s
     */
    public static function retryStack(int $retries, int $window, float $spacing, ?float $retryDelay = null): HandlerStack
    {
        $transient = (int) round(max($retryDelay ?? 2.0, $spacing) * 1000);

        return RetryHandlerFactory::stack(
            $retries,
            $transient,
            [403, 429],
            max($window * 1000, $transient),
            throttleDelayMs: $window * 1000,
            throttleMaxDelayMs: $window * 2000,
        );
    }

    /** Length of NVD's rolling rate-limit window in seconds. */
    private function rateWindow(): int
    {
        return max(1, (int) $this->config('rate_limit_window', 30));
    }

    /** Requests NVD allows per window: 50 with an API key, 5 without. */
    private function rateLimit(): int
    {
        return max(1, (int) ($this->config('rate_limit_max') ?: ($this->apiKey ? 50 : 5)));
    }

    /** Seconds between two requests: `min_interval`, else the window spread evenly over the limit. */
    private function spacing(): float
    {
        return (float) $this->config('min_interval', $this->rateWindow() / $this->rateLimit());
    }

    /**
     * Hold the request until it fits NVD's limit: at most `rate_limit_max`
     * requests in any ROLLING `rate_limit_window` seconds (5/30 s anonymous,
     * 50/30 s with a key), spaced `min_interval` seconds apart (the six
     * seconds NVD asks for without a key, 0.6 s with one). A fixed calendar
     * window — the old counter — let ten requests through in a few seconds
     * across a boundary, which NVD answers with 403 / "too many connections".
     *
     * Request stamps live in the PSR-16 cache when one is bound, so every
     * worker of the app shares one budget; without a cache the budget is
     * per process. Read-modify-write is good enough for a best-effort pacer.
     */
    private function throttle(): void
    {
        $window = $this->rateWindow();
        $max = $this->rateLimit();
        $spacing = $this->spacing();
        // '.' separators, not ':' — PSR-16 reserves {}()/\@: and strict
        // implementations (e.g. Symfony's Psr16Cache) throw on them.
        $key = 'vulns.nvd.rate';
        // 'clock' and 'sleep' are test seams (like 'handler'): a pacer that
        // really sleeps cannot be unit-tested in bounded time.
        $clock = $this->config('clock') ?? static fn (): float => microtime(true);
        $sleep = $this->config('sleep') ?? static fn (float $seconds) => usleep((int) ceil($seconds * 1_000_000));

        static $local = [];
        for ($attempt = 0; $attempt < 100; $attempt++) {
            $now = (float) $clock();
            $stamps = $this->cache !== null ? (array) $this->cache->get($key, []) : $local;
            $stamps = array_values(array_filter($stamps, fn ($t) => is_numeric($t) && (float) $t > $now - $window));
            sort($stamps);

            $wait = 0.0;
            if (count($stamps) >= $max) {
                $wait = max($wait, (float) $stamps[count($stamps) - $max] + $window - $now);
            }
            if ($stamps !== [] && $spacing > 0) {
                $wait = max($wait, (float) end($stamps) + $spacing - $now);
            }

            if ($wait > 0) {
                $sleep($wait);

                continue; // re-read: another worker may have spent the budget meanwhile
            }

            $stamps[] = $now;
            if ($this->cache !== null) {
                $this->cache->set($key, $stamps, $window * 2);
            } else {
                $local = $stamps;
            }

            return;
        }
    }
}
