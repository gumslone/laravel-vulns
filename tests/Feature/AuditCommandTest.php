<?php

use Gumslone\Vulns\Console\AuditCommand;
use Gumslone\Vulns\Data\VulnerabilityData;
use Gumslone\Vulns\Events\SearchCompleted;
use Gumslone\Vulns\Events\SourceFailed;
use Gumslone\Vulns\Facades\Vulns;
use Gumslone\Vulns\Testing\FakeSource;
use Gumslone\Vulns\VulnSearch;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Event;

function auditFixtures(): array
{
    $dir = sys_get_temp_dir().'/vulns-audit-'.bin2hex(random_bytes(4));
    mkdir($dir);
    file_put_contents($composer = "{$dir}/composer.lock", json_encode([
        'packages' => [['name' => 'guzzlehttp/guzzle', 'version' => 'v7.4.0'], ['name' => 'acme/branch', 'version' => 'dev-main']],
        'packages-dev' => [['name' => 'phpunit/phpunit', 'version' => '10.0.0']],
    ]));
    file_put_contents($npm = "{$dir}/package-lock.json", json_encode([
        'lockfileVersion' => 3,
        'packages' => [
            '' => ['name' => 'app', 'version' => '1.0.0'],
            'node_modules/lodash' => ['version' => '4.17.20'],
            'node_modules/a/node_modules/@babel/core' => ['version' => '7.0.0', 'dev' => true],
            'node_modules/local' => ['resolved' => '../local', 'link' => true],
        ],
    ]));

    return [$composer, $npm];
}

function bindAudit(array $sources): void
{
    app()->instance(VulnSearch::class, new VulnSearch($sources));
}

it('audits the lockfiles and fails the build on findings at or above the threshold', function () {
    [$composer, $npm] = auditFixtures();
    $high = new VulnerabilityData(vulnId: 'CVE-2030-1', source: 'osv', cvssV3Score: 7.5, fixedVersions: ['7.4.5'], affectedRanges: [['range' => '< 7.4.5']]);
    $devOnly = new VulnerabilityData(vulnId: 'CVE-2030-4', source: 'osv', severity: 'high');
    $low = new VulnerabilityData(vulnId: 'CVE-2030-2', source: 'osv', cvssV3Score: 2.0);
    $withdrawn = new VulnerabilityData(vulnId: 'CVE-2030-3', source: 'osv', cvssV3Score: 9.8, isWithdrawn: true);
    bindAudit([new FakeSource('osv', ['guzzlehttp/guzzle' => [$high, $withdrawn], 'lodash' => [$low], 'phpunit/phpunit' => [$devOnly]])]);

    expect(Artisan::call('vulns:audit', ['--lock' => [$composer, $npm]]))->toBe(1);
    $table = Artisan::output();
    expect($table)->toContain('guzzlehttp/guzzle')->toContain('7.4.5')->toContain('phpunit/phpunit (dev)')
        ->toContain('CVE-2030-2')->not->toContain('CVE-2030-3')->not->toContain('acme/branch');

    // --no-dev and --min-severity narrow it; JSON stays machine-readable.
    expect(Artisan::call('vulns:audit', ['--lock' => [$composer, $npm], '--no-dev' => true, '--min-severity' => 'high', '--format' => 'json']))->toBe(1);
    $json = json_decode(Artisan::output(), true);
    expect($json['packages'])->toBe(2)
        ->and(array_column($json['findings'], 'package'))->toBe(['guzzlehttp/guzzle'])
        ->and($json['findings'][0]['advisories'][0]['vuln_id'])->toBe('CVE-2030-1');

    expect(Artisan::call('vulns:audit', ['--lock' => [$composer], '--format' => 'sarif']))->toBe(1);
    $sarif = json_decode(Artisan::output(), true);
    expect($sarif['version'])->toBe('2.1.0')
        ->and($sarif['runs'][0]['tool']['driver']['rules'][0]['properties']['security-severity'])->toBe('7.5')
        ->and($sarif['runs'][0]['results'][0]['level'])->toBe('error')
        ->and($sarif['runs'][0]['results'][0]['message']['text'])->toContain('upgrade to 7.4.5');
});

it('never turns a source outage into a green build, and rejects bad input', function () {
    [$composer] = auditFixtures();

    bindAudit([new FakeSource('osv')]);
    expect(Artisan::call('vulns:audit', ['--lock' => [$composer]]))->toBe(0);

    bindAudit([new FakeSource('osv'), (new FakeSource('nvd'))->failing('503')]);
    expect(Artisan::call('vulns:audit', ['--lock' => [$composer]]))->toBe(AuditCommand::INCONCLUSIVE)
        ->and(Artisan::output())->toContain('inconclusive')
        ->and(Artisan::call('vulns:audit', ['--lock' => [$composer], '--ignore-errors' => true]))->toBe(0)
        ->and(Artisan::call('vulns:audit', ['--lock' => ['/nonexistent/composer.lock']]))->toBe(2)
        ->and(Artisan::call('vulns:audit', ['--lock' => [$composer], '--min-severity' => 'scary']))->toBe(2);
});

it('resolves the Vulns facade and dispatches search events', function () {
    Event::fake([SourceFailed::class, SearchCompleted::class]);
    config(['vulns.osv.enabled' => false, 'vulns.github.enabled' => false, 'vulns.nvd.enabled' => false, 'vulns.cve_search.enabled' => false,
        'vulns.euvd.enabled' => false, 'vulns.oss_index.enabled' => false, 'vulns.redhat.enabled' => false, 'vulns.shodan_cvedb.enabled' => false,
        'vulns.mitre.enabled' => false, 'vulns.epss.enabled' => false, 'vulns.kev.enabled' => false]);

    expect(Vulns::getFacadeRoot())->toBeInstanceOf(VulnSearch::class)
        ->and(Vulns::searchPurl('pkg:npm/lodash@4.17.20'))->toBe([]);
    Event::assertDispatched(SearchCompleted::class, fn (SearchCompleted $e) => $e->report->errors === []);

    // The framework-free form: any callable, and a throwing listener is harmless.
    $seen = [];
    $search = (new VulnSearch([(new FakeSource('nvd'))->failing('503')]))->listen(function (object $event) use (&$seen) {
        $seen[] = $event;
        throw new RuntimeException('observer bug');
    });
    expect($search->searchPurl('pkg:npm/lodash@4.17.20'))->toBe([])
        ->and($seen[0])->toBeInstanceOf(SourceFailed::class)
        ->and($seen[0]->source)->toBe('nvd')
        ->and($seen[0]->partial)->toBeFalse()
        ->and($seen[1])->toBeInstanceOf(SearchCompleted::class)
        ->and($search->only('nvd')->listen(null))->toBeInstanceOf(VulnSearch::class);
});
