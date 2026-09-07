<?php

use Gumslone\Vulns\Data\VulnerabilityData;
use Gumslone\Vulns\Testing\FakeSource;
use Gumslone\Vulns\VulnSearch;
use Illuminate\Support\Facades\Artisan;

function bindSearch(array $sources): void
{
    app()->instance(VulnSearch::class, new VulnSearch($sources));
}

it('prints a table for a purl and JSON on request', function () {
    $vuln = new VulnerabilityData(vulnId: 'CVE-2030-60', source: 'osv', severity: 'high', cvssV3Score: 7.5,
        epssScore: 0.123, fixedVersions: ['4.17.21'], sourceUrl: 'https://osv.dev/vulnerability/CVE-2030-60');
    bindSearch([new FakeSource('osv', ['lodash' => [$vuln]])]);

    // Artisan::output() rather than expectsOutputToContain(): the latter
    // consumes one written line per expectation, and a table row is one line.
    expect(Artisan::call('vulns:search', ['query' => 'pkg:npm/lodash@4.17.20']))->toBe(0);
    $table = Artisan::output();
    expect($table)->toContain('CVE-2030-60')->toContain('4.17.21')->toContain('0.123')
        ->toContain('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N');

    expect(Artisan::call('vulns:search', ['query' => 'CVE-2030-60', '--json' => true]))->toBe(0);
    $json = json_decode(Artisan::output(), true);
    expect($json['results'][0]['vuln_id'])->toBe('CVE-2030-60')
        ->and($json['results'][0]['cvss_v3_vector'])->toBe('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N')
        ->and($json['results'][0]['inferred_fields'])->toBe(['cvss_v3_vector'])
        ->and($json['errors'])->toBe([]);
});

it('exits non-zero when a source failed or the query is unrecognisable', function () {
    bindSearch([new FakeSource('osv'), (new FakeSource('nvd'))->failing('503 Service Unavailable')]);

    $this->artisan('vulns:search', ['query' => 'pkg:npm/lodash@4.17.20'])
        ->expectsOutputToContain('inconclusive')
        ->assertFailed();

    // --json stays parseable when a source failed: warnings go to stderr,
    // the failure is embedded in the document.
    expect(Artisan::call('vulns:search', ['query' => 'pkg:npm/lodash@4.17.20', '--json' => true]))->toBe(1);
    $json = json_decode(Artisan::output(), true);
    expect($json)->not->toBeNull()->and($json['errors'])->toBe(['nvd' => '503 Service Unavailable']);

    $this->artisan('vulns:search', ['query' => 'what is this'])
        ->expectsOutputToContain('Unrecognised query')
        ->assertExitCode(2);

    // Unknown --source and a truncated purl are the caller's mistakes, not stack traces.
    $this->artisan('vulns:search', ['query' => 'pkg:npm/lodash@4.17.20', '--source' => ['nonesuch']])
        ->expectsOutputToContain('Unknown vulnerability source')
        ->assertExitCode(2);
    $this->artisan('vulns:search', ['query' => 'pkg:npm'])
        ->expectsOutputToContain('no package name')
        ->assertExitCode(2);
});
