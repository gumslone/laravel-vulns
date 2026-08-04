<?php

use Gumslone\Vulns\Contracts\Source;
use Gumslone\Vulns\Data\PackageData;
use Gumslone\Vulns\Data\VulnerabilityData;
use Gumslone\Vulns\Severity;
use Gumslone\Vulns\VulnSearch;

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
        ->and($merged->cvssV3Score)->toBe(7.5)                // score from NVD
        ->and($merged->severity)->toBe(Severity::High)        // strongest severity
        ->and($merged->affectedRanges)->toBe([['range' => '< 2.0']]); // ranges from OSV
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
