<?php

use Gumslone\Vulns\ChangeType;
use Gumslone\Vulns\Data\PackageData;
use Gumslone\Vulns\Data\VulnerabilityData;
use Gumslone\Vulns\ExploitMaturity;
use Gumslone\Vulns\Severity;
use Gumslone\Vulns\Sources\MitreCveSource;
use Gumslone\Vulns\Sources\OssIndexSource;
use Gumslone\Vulns\Support\PurlBuilder;
use Gumslone\Vulns\VulnSearch;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use Psr\SimpleCache\CacheInterface;

/** Minimal array-backed PSR-16 cache for poisoning checks. */
function arrayCache(): CacheInterface
{
    return new class implements CacheInterface
    {
        public array $store = [];

        public function get(string $key, mixed $default = null): mixed
        {
            return $this->store[$key] ?? $default;
        }

        public function set(string $key, mixed $value, \DateInterval|int|null $ttl = null): bool
        {
            $this->store[$key] = $value;

            return true;
        }

        public function delete(string $key): bool
        {
            unset($this->store[$key]);

            return true;
        }

        public function clear(): bool
        {
            $this->store = [];

            return true;
        }

        public function getMultiple(iterable $keys, mixed $default = null): iterable
        {
            $out = [];
            foreach ($keys as $k) {
                $out[$k] = $this->get($k, $default);
            }

            return $out;
        }

        public function setMultiple(iterable $values, \DateInterval|int|null $ttl = null): bool
        {
            foreach ($values as $k => $v) {
                $this->set($k, $v, $ttl);
            }

            return true;
        }

        public function deleteMultiple(iterable $keys): bool
        {
            foreach ($keys as $k) {
                $this->delete($k);
            }

            return true;
        }

        public function has(string $key): bool
        {
            return array_key_exists($key, $this->store);
        }
    };
}

it('does not cache misses from a 200 with a garbage body — the outage lands in errors()', function () {
    $cache = arrayCache();
    $enricher = new \Gumslone\Vulns\Enrichment\ThreatEnricher(
        new Client(['handler' => HandlerStack::create(new MockHandler([
            new Response(200, [], '<html>Service Temporarily Unavailable</html>'),
            new Response(200, [], '<html>Service Temporarily Unavailable</html>'),
        ]))]),
        [],
        cache: $cache,
    );

    $enriched = $enricher->apply([[new VulnerabilityData(vulnId: 'CVE-2021-44228', source: 'osv')]]);

    expect($enriched[0][0]->epssScore)->toBeNull()
        ->and($enricher->errors())->toHaveKeys(['epss', 'kev'])
        ->and($cache->store)->toBe([]);   // nothing poisoned for a whole TTL
});

it('tolerates a malformed KEV date without discarding the rest of the enrichment', function () {
    $enricher = new \Gumslone\Vulns\Enrichment\ThreatEnricher(
        new Client(['handler' => HandlerStack::create(new MockHandler([
            new Response(200, [], json_encode(['data' => [['cve' => 'CVE-2030-1', 'epss' => '0.5', 'percentile' => '0.9']]])),
            new Response(200, [], json_encode(['vulnerabilities' => [
                ['cveID' => 'CVE-2030-1', 'dateAdded' => 'not a real date!!', 'dueDate' => '2030-01-22'],
            ]])),
        ]))]),
    );

    $enriched = $enricher->apply([[new VulnerabilityData(vulnId: 'CVE-2030-1', source: 'osv')]]);

    expect($enriched[0][0]->epssScore)->toBe(0.5)          // EPSS survived
        ->and($enriched[0][0]->isKnownExploited)->toBeTrue()
        ->and($enriched[0][0]->kevSince)->toBeNull()        // only the bad field degraded
        ->and($enriched[0][0]->kevDueDate?->format('Y-m-d'))->toBe('2030-01-22');
});

it('reads NVD dispute markers from cveTags, not only description text', function () {
    $source = new \Gumslone\Vulns\Sources\NvdSource(
        new \Gumslone\Vulns\Support\CpeResolver,
        null,
        new Client(['handler' => HandlerStack::create(new MockHandler([
            new Response(200, [], json_encode(['vulnerabilities' => [['cve' => [
                'id' => 'CVE-2020-19909',
                'descriptions' => [['lang' => 'en', 'value' => 'Integer overflow in curl.']],
                'cveTags' => [['sourceIdentifier' => 'x', 'tags' => ['disputed']]],
                'metrics' => [],
            ]]], 'totalResults' => 1])),
        ]))]),
        ['rate_limit_max' => 1000],
    );

    expect($source->fetchById('CVE-2020-19909')?->isDisputed)->toBeTrue();
});

it('keeps MITRE summaries for en-US records and uppercases lowercase ids', function () {
    $history = [];
    $stack = HandlerStack::create(new MockHandler([
        new Response(200, [], json_encode([
            'cveMetadata' => ['cveId' => 'CVE-2024-21413', 'state' => 'PUBLISHED'],
            'containers' => ['cna' => [
                'descriptions' => [['lang' => 'en-US', 'value' => 'Microsoft Outlook RCE.']],
                'metrics' => [],
            ]],
        ])),
    ]));
    $stack->push(Middleware::history($history));
    $source = new MitreCveSource(new Client(['handler' => $stack]));

    $vuln = $source->fetchById('cve-2024-21413');

    expect($vuln?->summary)->toBe('Microsoft Outlook RCE.')
        ->and((string) $history[0]['request']->getUri())->toContain('CVE-2024-21413');
});

it('sorts a v4-only-scored Critical above a v3-scored Low in merged results', function () {
    $search = new VulnSearch([
        fakeSource('osv', ['lodash' => [
            new VulnerabilityData(vulnId: 'CVE-2030-2', source: 'osv', severity: Severity::Low, cvssV3Score: 2.0),
            new VulnerabilityData(vulnId: 'CVE-2030-3', source: 'osv', severity: Severity::Critical, cvssV4Score: 9.8),
        ]]),
    ]);

    $results = $search->search(new PackageData(name: 'lodash', version: '1.0', ecosystem: 'npm'));

    expect($results[0]->vulnId)->toBe('CVE-2030-3');
});

it("matches 'poc' only as a standalone token in reference URLs", function () {
    $benign = new VulnerabilityData(vulnId: 'CVE-2030-4', source: 'osv', references: [
        ['type' => null, 'url' => 'https://github.com/pmmp/PocketMine-MP/issues/123'],
        ['type' => null, 'url' => 'https://podcasts.apple.com/pocus'],
    ]);
    expect($benign->exploitMaturity())->toBe(ExploitMaturity::None);

    $real = new VulnerabilityData(vulnId: 'CVE-2030-4', source: 'osv', references: [
        ['type' => null, 'url' => 'https://github.com/x/CVE-2030-4-poc'],
    ]);
    expect($real->exploitMaturity())->toBe(ExploitMaturity::Poc);
});

it('keeps OSS Index disabled without credentials — anonymous access 401s since 2025', function () {
    $builder = new PurlBuilder;

    expect((new OssIndexSource($builder))->isEnabled())->toBeFalse()
        ->and((new OssIndexSource($builder, null, ['username' => 'u']))->isEnabled())->toBeFalse()
        ->and((new OssIndexSource($builder, null, ['username' => 'u', 'api_token' => 't']))->isEnabled())->toBeTrue();
});

it('fires ExploitationLikely on the first EPSS score above the threshold', function () {
    $before = new VulnerabilityData(vulnId: 'CVE-2030-5', source: 'osv');

    $first = new VulnerabilityData(vulnId: 'CVE-2030-5', source: 'osv', epssScore: 0.4);
    expect($first->changesSince($before)->has(ChangeType::ExploitationLikely))->toBeTrue();

    // A first score below the threshold is just the baseline, not a change.
    $baseline = new VulnerabilityData(vulnId: 'CVE-2030-5', source: 'osv', epssScore: 0.02);
    expect($baseline->changesSince($before)->hasChanges())->toBeFalse();
});
