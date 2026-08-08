<?php

use Gumslone\Vulns\Sources\GitHubAdvisorySource;
use Gumslone\Vulns\Sources\NvdSource;
use Gumslone\Vulns\Sources\SnykSource;
use Gumslone\Vulns\VulnsServiceProvider;
use Gumslone\Vulns\VulnSearch;

uses(Gumslone\Vulns\Tests\TestCase::class)->in(__DIR__);

it('resolves VulnSearch with every source, straight out of the box', function () {
    $search = app(VulnSearch::class);

    expect($search)->toBeInstanceOf(VulnSearch::class)
        ->and($search->availableSources())
        ->toBe(['osv', 'github', 'nvd', 'cve_search', 'euvd', 'snyk',
            'oss_index', 'redhat', 'shodan_cvedb', 'mitre', 'vulncheck']);
});

it('feeds config/vulns.php credentials into the sources', function () {
    // What a host app sets in .env → config/vulns.php.
    config([
        'vulns.snyk.enabled' => true,
        'vulns.snyk.api_token' => 'snyk-secret',
        'vulns.snyk.org_id' => 'org-123',
        'vulns.github.token' => 'gh-secret',
    ]);

    // Snyk only reports enabled when BOTH token and org are configured —
    // proof the values reached the source, since a wrong config key would
    // leave it disabled.
    expect(app(SnykSource::class)->isEnabled())->toBeTrue();

    config(['vulns.snyk.api_token' => null]);
    expect(app(SnykSource::class)->isEnabled())->toBeFalse();
});

it('honours the enabled toggles when assembling the search', function () {
    config([
        'vulns.nvd.enabled' => false,
        'vulns.euvd.enabled' => false,
        'vulns.snyk.enabled' => false,
    ]);

    $names = array_map(fn ($s) => $s->name(), app(VulnSearch::class)->sources());

    expect($names)->toContain('osv')
        ->and($names)->not->toContain('nvd')
        ->and($names)->not->toContain('euvd')
        ->and($names)->not->toContain('snyk');
});

it('keeps GitHub usable without a token (repository advisories) and NVD keyless', function () {
    config(['vulns.github.token' => null, 'vulns.nvd.api_key' => null]);

    expect(app(GitHubAdvisorySource::class)->isEnabled())->toBeTrue()
        ->and(app(NvdSource::class)->isEnabled())->toBeTrue();
});

it('publishes the config file under the vulns-config tag', function () {
    $paths = Illuminate\Support\ServiceProvider::pathsToPublish(VulnsServiceProvider::class, 'vulns-config');

    expect($paths)->not->toBeEmpty()
        ->and(array_key_first($paths))->toEndWith('config/vulns.php');
});
