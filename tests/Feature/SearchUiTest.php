<?php

use Gumslone\Vulns\Contracts\Source;
use Gumslone\Vulns\Data\PackageData;
use Gumslone\Vulns\Data\VulnerabilityData;
use Gumslone\Vulns\VulnSearch;


function uiSearch(array $vulns, array $errors = []): VulnSearch
{
    $source = new class($vulns) implements Source
    {
        public function __construct(private array $vulns) {}

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
            return $this->vulns;
        }

        public function queryBatch(array $packages): array
        {
            return array_map(fn () => $this->vulns, $packages);
        }

        public function fetchById(string $vulnId): ?VulnerabilityData
        {
            return $this->vulns[0] ?? null;
        }
    };

    return new VulnSearch([$source]);
}

it('is disabled by default — no route registered', function () {
    $this->get('/vulns')->assertNotFound();
});

it('renders the search page and results when enabled', function () {
    config(['vulns.ui.enabled' => true, 'app.key' => 'base64:'.base64_encode(random_bytes(32))]);
    // Re-boot the provider so the route registers under the test config.
    (new Gumslone\Vulns\VulnsServiceProvider(app()))->boot();

    app()->instance(VulnSearch::class, uiSearch([
        new VulnerabilityData(
            vulnId: 'CVE-2021-44228', source: 'osv', severity: 'critical',
            cvssV3Score: 10.0, epssScore: 0.97, isKnownExploited: true,
            summary: 'Log4Shell RCE', fixedVersions: ['2.17.1'],
            sourceUrl: 'https://osv.dev/CVE-2021-44228',
        ),
    ]));

    $this->get('/vulns?q=pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0')
        ->assertOk()
        ->assertSee('CVE-2021-44228')
        ->assertSee('critical')
        ->assertSee('KEV')
        ->assertSee('2.17.1');
});

it('shows a clear message for unrecognisable queries', function () {
    config(['vulns.ui.enabled' => true, 'app.key' => 'base64:'.base64_encode(random_bytes(32))]);
    (new Gumslone\Vulns\VulnsServiceProvider(app()))->boot();
    app()->instance(VulnSearch::class, uiSearch([]));

    $this->get('/vulns?q=what+even+is+this')
        ->assertOk()
        ->assertSee('Unrecognised query');
});

it('marks empty results as inconclusive when a source failed', function () {
    config(['vulns.ui.enabled' => true, 'app.key' => 'base64:'.base64_encode(random_bytes(32))]);
    (new Gumslone\Vulns\VulnsServiceProvider(app()))->boot();

    // A search whose only source throws: empty results + errors() populated.
    $failing = new class implements Source
    {
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
            throw new RuntimeException('connection refused');
        }

        public function queryBatch(array $packages): array
        {
            throw new RuntimeException('connection refused');
        }

        public function fetchById(string $vulnId): ?VulnerabilityData
        {
            throw new RuntimeException('connection refused');
        }
    };
    app()->instance(VulnSearch::class, new VulnSearch([$failing]));

    $this->get('/vulns?q=pkg:npm/lodash@4.17.20')
        ->assertOk()
        ->assertSee('results may be incomplete')
        ->assertSee('inconclusive');
});
