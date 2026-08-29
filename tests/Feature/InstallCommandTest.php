<?php


it('walks through setup and writes entered credentials to .env', function () {
    $envFile = sys_get_temp_dir().'/vulns-install-test-'.uniqid().'.env';
    file_put_contents($envFile, "APP_NAME=demo\nNVD_API_KEY=old-key\n");
    app()->loadEnvironmentFrom(basename($envFile));
    app()->useEnvironmentPath(dirname($envFile));

    $this->artisan('vulns:install')
        ->expectsConfirmation('Configure source credentials now?', 'yes')
        ->expectsQuestion('NVD API key (free at nvd.nist.gov/developers — raises 5 req/30s to 50) [enter to skip]', 'new-nvd-key')
        ->expectsQuestion('GitHub token (classic PAT, no scopes — unlocks the Advisory DB GraphQL feed) [enter to skip]', '')
        ->expectsQuestion('Snyk API token (commercial; leave empty to skip) [enter to skip]', '')
        ->expectsQuestion('Sonatype OSS Index username (free account; required — anonymous access 401s) [enter to skip]', 'oleg')
        ->expectsQuestion('Sonatype OSS Index API token [enter to skip]', 'oss-token')
        ->expectsQuestion('VulnCheck Community token (free — "NVD++" by-id lookups) [enter to skip]', '')
        ->expectsConfirmation('Enable the built-in search UI at /vulns? (enable only behind auth in production)', 'yes')
        ->assertSuccessful();

    $env = file_get_contents($envFile);
    // Existing keys update in place; new ones append; skipped ones don't appear.
    expect($env)->toContain('NVD_API_KEY="new-nvd-key"')
        ->not->toContain('old-key')
        ->and($env)->toContain('OSS_INDEX_USERNAME="oleg"')
        ->and($env)->toContain('OSS_INDEX_API_TOKEN="oss-token"')
        ->and($env)->toContain('VULNS_UI_ENABLED="true"')
        ->and($env)->not->toContain('SNYK_API_TOKEN')
        ->and($env)->toContain('APP_NAME=demo');

    @unlink($envFile);
});

it('runs without touching .env when everything is skipped', function () {
    $envFile = sys_get_temp_dir().'/vulns-install-test-'.uniqid().'.env';
    file_put_contents($envFile, "APP_NAME=demo\n");
    app()->loadEnvironmentFrom(basename($envFile));
    app()->useEnvironmentPath(dirname($envFile));

    $this->artisan('vulns:install')
        ->expectsConfirmation('Configure source credentials now?', 'no')
        ->expectsConfirmation('Enable the built-in search UI at /vulns? (enable only behind auth in production)', 'no')
        ->assertSuccessful();

    expect(file_get_contents($envFile))->toBe("APP_NAME=demo\n");

    @unlink($envFile);
});
