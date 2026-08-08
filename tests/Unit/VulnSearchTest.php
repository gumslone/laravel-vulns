<?php

use Gumslone\Vulns\Contracts\Source;
use Gumslone\Vulns\Data\PackageData;
use Gumslone\Vulns\Data\VulnerabilityData;
use Gumslone\Vulns\Severity;
use Gumslone\Vulns\Sources\OsvSource;
use Gumslone\Vulns\VulnSearch;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Request;

/** A source returning canned results (or throwing) for one package key. */
function fakeSource(string $name, array $byKey, bool $enabled = true, ?string $throws = null): Source
{
    return new class($name, $byKey, $enabled, $throws) implements Source
    {
        public function __construct(
            private string $sourceName,
            private array $byKey,
            private bool $enabled,
            private ?string $throws,
        ) {}

        public function name(): string
        {
            return $this->sourceName;
        }

        public function isEnabled(): bool
        {
            return $this->enabled;
        }

        public function queryPackage(PackageData $package): array
        {
            return $this->queryBatch([$package])[0] ?? [];
        }

        public function queryBatch(array $packages): array
        {
            if ($this->throws !== null) {
                throw new RuntimeException($this->throws);
            }

            $out = [];
            foreach ($packages as $key => $package) {
                $out[$key] = $this->byKey[$package->name] ?? [];
            }

            return $out;
        }

        public function fetchById(string $vulnId): ?VulnerabilityData
        {
            foreach ($this->byKey as $vulns) {
                foreach ($vulns as $v) {
                    if ($v->vulnId === $vulnId) {
                        return $v;
                    }
                }
            }

            return null;
        }
    };
}

it('merges the same advisory across sources, pooling aliases and keeping the richest fields', function () {
    // OSV knows it as a GHSA with ranges; NVD knows the CVE with a score.
    $ghsa = new VulnerabilityData(
        vulnId: 'GHSA-aaaa-bbbb-cccc', source: 'osv', severity: Severity::Medium,
        aliases: ['CVE-2030-1'], affectedRanges: [['range' => '< 2.0']],
    );
    $cve = new VulnerabilityData(
        vulnId: 'CVE-2030-1', source: 'nvd', severity: Severity::High,
        cvssV3Score: 7.5, cvssV3Vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
    );

    $search = new VulnSearch([
        fakeSource('osv', ['lodash' => [$ghsa]]),
        fakeSource('nvd', ['lodash' => [$cve]]),
    ]);

    $results = $search->search(new PackageData(name: 'lodash', version: '1.0', ecosystem: 'npm'));

    expect($results)->toHaveCount(1);
    $merged = $results[0];
    expect($merged->vulnId)->toBe('CVE-2030-1')               // CVE wins the id
        ->and($merged->aliases)->toContain('GHSA-aaaa-bbbb-cccc')
        ->and($merged->cvssV3Score)->toBe(7.5)                // gap-filled from NVD
        ->and($merged->severity)->toBe(Severity::Medium)      // OSV outranks NVD by default
        ->and($merged->affectedRanges)->toBe([['range' => '< 2.0']]); // ranges from OSV
});

it('lets prioritize() choose which source wins a disagreement', function () {
    $fromOsv = new VulnerabilityData(
        vulnId: 'CVE-2030-5', source: 'osv', severity: Severity::Medium,
        cvssV3Score: 5.0, summary: 'osv wording',
    );
    $fromNvd = new VulnerabilityData(
        vulnId: 'CVE-2030-5', source: 'nvd', severity: Severity::High,
        cvssV3Score: 8.1, summary: 'nvd wording',
    );
    $pkg = new PackageData(name: 'lodash', version: '1.0', ecosystem: 'npm');

    $search = new VulnSearch([
        fakeSource('osv', ['lodash' => [$fromOsv]]),
        fakeSource('nvd', ['lodash' => [$fromNvd]]),
    ]);

    // Default order: OSV outranks NVD.
    $default = $search->search($pkg)[0];
    expect($default->cvssV3Score)->toBe(5.0)
        ->and($default->summary)->toBe('osv wording');

    // Re-ranked: NVD's record becomes the base.
    $nvdFirst = $search->prioritize(['nvd', 'osv'])->search($pkg)[0];
    expect($nvdFirst->cvssV3Score)->toBe(8.1)
        ->and($nvdFirst->severity)->toBe(Severity::High)
        ->and($nvdFirst->summary)->toBe('nvd wording');
});

it('lets preferLatest() surface the most recently modified record', function () {
    // NVD rescored (downward!) a week after OSV's copy was last touched.
    $stale = new VulnerabilityData(
        vulnId: 'CVE-2030-6', source: 'osv', severity: Severity::High,
        cvssV3Score: 8.8, summary: 'old wording',
        sourceModifiedAt: new DateTimeImmutable('2030-01-01'),
    );
    $fresh = new VulnerabilityData(
        vulnId: 'CVE-2030-6', source: 'nvd', severity: Severity::Medium,
        cvssV3Score: 5.4, summary: 'rescored wording',
        sourceModifiedAt: new DateTimeImmutable('2030-01-08'),
    );
    $pkg = new PackageData(name: 'lodash', version: '1.0', ecosystem: 'npm');

    $search = new VulnSearch([
        fakeSource('osv', ['lodash' => [$stale]]),
        fakeSource('nvd', ['lodash' => [$fresh]]),
    ]);

    // Priority mode: OSV outranks NVD, the stale copy wins.
    expect($search->search($pkg)[0]->cvssV3Score)->toBe(8.8);

    // Latest mode: the rescore wins, including the downward severity.
    $latest = $search->preferLatest()->search($pkg)[0];
    expect($latest->cvssV3Score)->toBe(5.4)
        ->and($latest->severity)->toBe(Severity::Medium)
        ->and($latest->summary)->toBe('rescored wording')
        ->and($latest->sourceModifiedAt?->format('Y-m-d'))->toBe('2030-01-08');
});

it('falls back to priority order when modification dates are missing in latest mode', function () {
    $undated = new VulnerabilityData(vulnId: 'CVE-2030-7', source: 'nvd', cvssV3Score: 9.0);
    $alsoUndated = new VulnerabilityData(vulnId: 'CVE-2030-7', source: 'osv', cvssV3Score: 4.0);
    $pkg = new PackageData(name: 'lodash', version: '1.0', ecosystem: 'npm');

    $search = (new VulnSearch([
        fakeSource('nvd', ['lodash' => [$undated]]),
        fakeSource('osv', ['lodash' => [$alsoUndated]]),
    ]))->preferLatest();

    // No dates to compare — OSV still outranks NVD.
    expect($search->search($pkg)[0]->cvssV3Score)->toBe(4.0);
});

it('keeps priority and latest settings across only() and except()', function () {
    $fromOsv = new VulnerabilityData(vulnId: 'CVE-2030-8', source: 'osv', cvssV3Score: 3.0);
    $fromNvd = new VulnerabilityData(vulnId: 'CVE-2030-8', source: 'nvd', cvssV3Score: 9.0);
    $pkg = new PackageData(name: 'lodash', version: '1.0', ecosystem: 'npm');

    $search = (new VulnSearch([
        fakeSource('osv', ['lodash' => [$fromOsv]]),
        fakeSource('nvd', ['lodash' => [$fromNvd]]),
        fakeSource('euvd', []),
    ]))->prioritize(['nvd', 'osv']);

    expect($search->only(['osv', 'nvd'])->search($pkg)[0]->cvssV3Score)->toBe(9.0)
        ->and($search->except('euvd')->search($pkg)[0]->cvssV3Score)->toBe(9.0);
});

it('records a failing source instead of aborting the search', function () {
    $search = new VulnSearch([
        fakeSource('flaky', [], throws: 'rate limited'),
        fakeSource('osv', ['lodash' => [new VulnerabilityData(vulnId: 'CVE-2030-2', source: 'osv')]]),
    ]);

    $results = $search->search(new PackageData(name: 'lodash', version: '1.0', ecosystem: 'npm'));

    expect($results)->toHaveCount(1)
        ->and($search->errors())->toBe(['flaky' => 'rate limited']);
});

it('records a real transport failure in errors() while other sources still deliver', function () {
    // A genuine OsvSource whose HTTP client fails — the source must throw
    // (not swallow) so searchBatch can record it and results read as
    // "possibly under-reported" rather than "clean".
    $osv = new OsvSource(new Client(['handler' => HandlerStack::create(new MockHandler([
        new RequestException('connection refused', new Request('POST', 'v1/querybatch')),
    ]))]));

    $search = new VulnSearch([
        $osv,
        fakeSource('nvd', ['lodash' => [new VulnerabilityData(vulnId: 'CVE-2030-20', source: 'nvd')]]),
    ]);

    $results = $search->searchBatch([new PackageData(name: 'lodash', version: '4.17.20', ecosystem: 'npm')]);

    expect(array_map(fn ($v) => $v->vulnId, $results[0]))->toBe(['CVE-2030-20'])
        ->and($search->errors())->toHaveKey('osv')
        ->and($search->errors()['osv'])->toContain('connection refused');
});

it('resets errors from a previous search when fetchById runs', function () {
    $search = new VulnSearch([
        fakeSource('flaky', [], throws: 'down'),
        fakeSource('a', ['x' => [new VulnerabilityData(vulnId: 'CVE-2030-21', source: 'a', summary: 'found')]]),
    ]);

    $search->search(new PackageData(name: 'x', version: '1.0', ecosystem: 'npm'));
    expect($search->errors())->toBe(['flaky' => 'down']);

    // fetchById reports its OWN failures only — a stale search error must
    // not taint a clean lookup.
    expect($search->fetchById('CVE-2030-21')?->summary)->toBe('found')
        ->and($search->errors())->toBe([]);
});

it('skips disabled sources', function () {
    $search = new VulnSearch([
        fakeSource('off', ['lodash' => [new VulnerabilityData(vulnId: 'CVE-2030-3', source: 'x')]], enabled: false),
    ]);

    expect($search->search(new PackageData(name: 'lodash', version: '1.0', ecosystem: 'npm')))->toBe([])
        ->and($search->sources())->toHaveCount(0);
});

it('searches by purl, mapping the purl type onto the source ecosystem', function () {
    $package = PackageData::fromPurl('pkg:composer/vrana/adminer@5.5.1');

    expect($package->name)->toBe('vrana/adminer')
        ->and($package->namespace)->toBe('vrana')
        ->and($package->version)->toBe('5.5.1')
        ->and($package->ecosystem)->toBe('composer')
        ->and($package->purl)->toBe('pkg:composer/vrana/adminer@5.5.1');

    // pypi → pip, the name ecosystem sources expect
    expect(PackageData::fromPurl('pkg:pypi/django@3.2')->ecosystem)->toBe('pip');
});

it('searches by CPE, carrying the explicit CPE through untouched', function () {
    $package = PackageData::fromCpe('cpe:2.3:a:prasathmani:tiny_file_manager:2.6:*:*:*:*:*:*:*');

    expect($package->cpe23)->toBe('cpe:2.3:a:prasathmani:tiny_file_manager:2.6:*:*:*:*:*:*:*')
        ->and($package->name)->toBe('tiny_file_manager')
        ->and($package->version)->toBe('2.6');

    // A wildcard version means "any", not the literal "*"
    expect(PackageData::fromCpe('cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*')->version)->toBeNull();
});

it('fetches one advisory by id across sources', function () {
    $search = new VulnSearch([
        fakeSource('a', ['x' => [new VulnerabilityData(vulnId: 'CVE-2030-9', source: 'a', summary: 'from a')]]),
    ]);

    expect($search->fetchById('CVE-2030-9')?->summary)->toBe('from a')
        ->and($search->fetchById('CVE-1999-0001'))->toBeNull();
});

it('restricts the search to named sources with only()', function () {
    $osvHit = new VulnerabilityData(vulnId: 'CVE-2030-10', source: 'osv');
    $nvdHit = new VulnerabilityData(vulnId: 'CVE-2030-11', source: 'nvd');
    $search = new VulnSearch([
        fakeSource('osv', ['x' => [$osvHit]]),
        fakeSource('nvd', ['x' => [$nvdHit]]),
    ]);
    $package = new PackageData(name: 'x', version: '1.0', ecosystem: 'npm');

    expect($search->search($package))->toHaveCount(2)
        ->and($search->only('osv')->search($package))->toHaveCount(1)
        ->and($search->only('osv')->search($package)[0]->vulnId)->toBe('CVE-2030-10')
        ->and($search->only(['osv', 'nvd'])->search($package))->toHaveCount(2);

    // The original is untouched — only() returns a copy.
    expect($search->sources())->toHaveCount(2);
});

it('drops named sources with except()', function () {
    $search = new VulnSearch([
        fakeSource('osv', ['x' => [new VulnerabilityData(vulnId: 'CVE-2030-12', source: 'osv')]]),
        fakeSource('snyk', ['x' => [new VulnerabilityData(vulnId: 'CVE-2030-13', source: 'snyk')]]),
    ]);
    $package = new PackageData(name: 'x', version: '1.0', ecosystem: 'npm');

    $results = $search->except('snyk')->search($package);
    expect($results)->toHaveCount(1)
        ->and($results[0]->vulnId)->toBe('CVE-2030-12');
});

it('rejects an unknown source name instead of silently searching fewer feeds', function () {
    $search = new VulnSearch([fakeSource('osv', [])]);

    expect($search->availableSources())->toBe(['osv']);
    $search->only('nvdd');
})->throws(InvalidArgumentException::class, 'Unknown vulnerability source(s): nvdd');
