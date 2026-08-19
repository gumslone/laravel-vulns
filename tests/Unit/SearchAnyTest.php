<?php

use Gumslone\Vulns\Data\PackageData;
use Gumslone\Vulns\Data\VulnerabilityData;
use Gumslone\Vulns\Sources\ShodanCvedbSource;
use Gumslone\Vulns\VulnSearch;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;

it('builds a queryable package from a forge commit URL', function () {
    $pkg = PackageData::fromCommit('https://github.com/gumslone/GumCP/commit/bf04e5f289885cf2f20a92b387bcc6df33e30809');

    expect($pkg->name)->toBe('gumcp')
        ->and($pkg->namespace)->toBe('gumslone')
        ->and($pkg->ecosystem)->toBe('github')
        ->and($pkg->gitCommitHash)->toBe('bf04e5f289885cf2f20a92b387bcc6df33e30809')
        ->and($pkg->purl)->toBe('pkg:github/gumslone/gumcp@bf04e5f289885cf2f20a92b387bcc6df33e30809');

    // GitLab's /-/commit/ route works too.
    expect(PackageData::fromCommit('https://gitlab.com/group/proj/-/commit/bf04e5f2')->ecosystem)->toBe('gitlab');
});

it('accepts a bare commit sha and rejects non-commits', function () {
    $pkg = PackageData::fromCommit('BF04E5F289885CF2');

    expect($pkg->gitCommitHash)->toBe('bf04e5f289885cf2')
        ->and($pkg->ecosystem)->toBe('git');

    expect(fn () => PackageData::fromCommit('not-a-commit'))
        ->toThrow(InvalidArgumentException::class);
});

it('converts between purl and CPE in both directions', function () {
    // purl → CPE (heuristic when no curated catalog is bound)
    $fromPurl = PackageData::fromPurl('pkg:composer/laravel/framework@11.0.0');
    expect($fromPurl->toCpe23())->toContain('cpe:2.3:a:')
        ->and($fromPurl->toCpe23())->toContain(':framework:11.0.0:');

    // CPE → purl (generic coordinates carry the product + version)
    $fromCpe = PackageData::fromCpe('cpe:2.3:a:tukaani:xz:5.6.0:*:*:*:*:*:*:*');
    expect($fromCpe->toPurl())->toContain('pkg:')
        ->and($fromCpe->toPurl())->toContain('xz@5.6.0');

    // Explicit values always win over derivation.
    expect($fromPurl->toPurl())->toBe('pkg:composer/laravel/framework@11.0.0')
        ->and($fromCpe->toCpe23())->toBe('cpe:2.3:a:tukaani:xz:5.6.0:*:*:*:*:*:*:*');
});

it('converts a commit to a CPE when it carries forge coordinates', function () {
    // owner → vendor, repo → product, sha → version
    $url = PackageData::fromCommit('https://github.com/gumslone/GumCP/commit/bf04e5f289885cf2f20a92b387bcc6df33e30809');
    expect($url->toCpe23())
        ->toBe('cpe:2.3:a:gumslone:gumcp:bf04e5f289885cf2f20a92b387bcc6df33e30809:*:*:*:*:*:*:*');

    // A bare sha has no vendor/product identity — null, never a
    // hash-as-vendor CPE that matches nothing.
    expect(PackageData::fromCommit('bf04e5f289885cf2')->toCpe23())->toBeNull();
});

/** A by-name source stub: results keyed on PackageData->name or vuln id. */
function anySearchSource(array $byName): \Gumslone\Vulns\Contracts\Source
{
    return new class($byName) implements \Gumslone\Vulns\Contracts\Source
    {
        public function __construct(private array $byName) {}

        public function name(): string
        {
            return 'osv';
        }

        public function isEnabled(): bool
        {
            return true;
        }

        public function queryPackage(PackageData $package): array
        {
            return $this->byName[$package->name] ?? [];
        }

        public function queryBatch(array $packages): array
        {
            return array_map(fn ($p) => $this->queryPackage($p), $packages);
        }

        public function fetchById(string $vulnId): ?VulnerabilityData
        {
            return ($this->byName[$vulnId] ?? [])[0] ?? null;
        }
    };
}

it('dispatches searchAny() by identifier shape', function () {
    $cve = new VulnerabilityData(vulnId: 'CVE-2030-77', source: 'osv');
    $search = new VulnSearch([
        anySearchSource([
            'lodash' => [new VulnerabilityData(vulnId: 'CVE-2030-70', source: 'osv')],
            'xz' => [new VulnerabilityData(vulnId: 'CVE-2030-71', source: 'osv')],
            'CVE-2030-77' => [$cve],
        ]),
    ]);

    // Advisory id → the single record (case-normalised).
    expect(array_map(fn ($v) => $v->vulnId, $search->searchAny('cve-2030-77')))->toBe(['CVE-2030-77'])
        // purl → registry search
        ->and(array_map(fn ($v) => $v->vulnId, $search->searchAny('pkg:npm/lodash@4.17.20')))->toBe(['CVE-2030-70'])
        // CPE 2.3 → product search
        ->and(array_map(fn ($v) => $v->vulnId, $search->searchAny('cpe:2.3:a:tukaani:xz:5.6.0:*:*:*:*:*:*:*')))->toBe(['CVE-2030-71'])
        // unrecognisable input throws instead of quietly returning []
        ->and(fn () => $search->searchAny('what even is this'))->toThrow(InvalidArgumentException::class);
});

it('uses the precise cpe23 filter on Shodan CVEDB for versioned CPE queries', function () {
    $history = [];
    $stack = HandlerStack::create(new MockHandler([
        new Response(200, [], json_encode(['cves' => []])),
        new Response(200, [], json_encode(['cves' => []])),
    ]));
    $stack->push(Middleware::history($history));
    $source = new ShodanCvedbSource(new Client(['handler' => $stack]));

    $source->queryBatch([
        PackageData::fromCpe('cpe:2.3:a:tukaani:xz:5.6.0:*:*:*:*:*:*:*'),   // versioned → cpe23
        new PackageData(name: 'lodash', version: null, ecosystem: 'npm'),   // no version → product
    ]);

    $queries = array_map(fn ($t) => $t['request']->getUri()->getQuery(), $history);
    sort($queries);
    expect(implode(' ', $queries))->toContain('cpe23=cpe%3A2.3%3Aa%3Atukaani%3Axz%3A5.6.0')
        ->and(implode(' ', $queries))->toContain('product=lodash');
});
