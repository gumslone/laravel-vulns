<?php

/*
 * vulns:audit listed 2018–2022 Laravel CVEs against 12.x: CVE-Search matches
 * by product name and these records carry the MITRE placeholder
 * (vendor/product/version "n/a") where the CNA data should be — while the
 * CISA ADP block or the embedded legacy v4 record does name the versions.
 */

use Gumslone\Vulns\Data\PackageData;
use Gumslone\Vulns\Sources\CveSearchSource;
use Gumslone\Vulns\Support\CpeResolver;
use Gumslone\Vulns\Support\VersionRange;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;

function cveSearchRanges(array $records, array $options = []): CveSearchSource
{
    $client = new Client(['handler' => HandlerStack::create(new MockHandler([
        new Response(200, [], json_encode(['results' => $records, 'total_count' => count($records)])),
    ]))]);

    return new CveSearchSource(new CpeResolver, null, $client, $options);
}

function laravelFramework(string $version): PackageData
{
    return new PackageData(name: 'laravel/framework', version: $version, ecosystem: 'composer', cpe23: "cpe:2.3:a:laravel:framework:{$version}:*:*:*:*:*:*:*");
}

const CNA_PLACEHOLDER = ['affected' => [['vendor' => 'n/a', 'product' => 'n/a', 'versions' => [['version' => 'n/a', 'status' => 'affected']]]]];

function cve5(string $id, array $cna = [], array $adp = []): array
{
    return [
        'cveMetadata' => ['cveId' => $id, 'state' => 'PUBLISHED'],
        'containers' => ['cna' => $cna + ['descriptions' => [['lang' => 'en', 'value' => 'x']]], 'adp' => $adp],
    ];
}

function rangesOf(CveSearchSource $source, PackageData $package): array
{
    $vulns = $source->queryPackage($package);
    expect($vulns)->toHaveCount(1);

    return array_column($vulns[0]->affectedRanges, 'range');
}

it('reads the CISA ADP affected block when the CNA row is the n/a placeholder', function () {
    // CVE-2024-29291 as cve.circl.lu serves it
    $source = cveSearchRanges([cve5('CVE-2024-29291', CNA_PLACEHOLDER, [[
        'title' => 'CISA ADP Vulnrichment',
        'affected' => [['cpes' => ['cpe:2.3:a:laravel:framework:*:*:*:*:*:*:*:*'], 'vendor' => 'laravel', 'product' => 'framework',
            'versions' => [['status' => 'affected', 'version' => '8']], 'defaultStatus' => 'unknown']],
    ]])]);

    $ranges = rangesOf($source, laravelFramework('12.69.2'));

    // "8" on an affected row is the 8.x line, not the single build 8.0.0
    expect($ranges)->toBe(['>= 8, < 9'])
        ->and(VersionRange::isVulnerable('12.69.2', $ranges))->toBeFalse()
        ->and(VersionRange::isVulnerable('8.5.0', $ranges))->toBeTrue();
});

it('keeps a record undeterminable when nothing but the placeholder is there', function () {
    $source = cveSearchRanges([cve5('CVE-2018-6330', CNA_PLACEHOLDER)]);

    $ranges = rangesOf($source, laravelFramework('12.69.2'));

    expect($ranges)->toBe([])
        ->and(VersionRange::isVulnerable('12.69.2', $ranges))->toBeNull();
});

it('reads the legacy v4 record: operator + version, "5.5.x before 5.5.21", and the placeholder as no statement', function () {
    $legacy = fn (array $versionData) => CNA_PLACEHOLDER + ['x_legacyV4Record' => ['affects' => ['vendor' => ['vendor_data' => [[
        'vendor_name' => 'n/a', 'product' => ['product_data' => [['product_name' => 'n/a', 'version' => ['version_data' => $versionData]]]],
    ]]]]]];

    expect(rangesOf(cveSearchRanges([cve5('CVE-2020-19316', $legacy([['version_affected' => '<', 'version_value' => '5.8.17']]))]), laravelFramework('12.69.2')))
        ->toBe(['< 5.8.17'])
        ->and(rangesOf(cveSearchRanges([cve5('CVE-2030-1', $legacy([['version_value' => '5.5.x before 5.5.21']]))]), laravelFramework('12.69.2')))
        ->toBe(['>= 5.5, < 5.5.21'])
        ->and(rangesOf(cveSearchRanges([cve5('CVE-2030-2', $legacy([['version_value' => 'through 8.70.2']]))]), laravelFramework('12.69.2')))
        ->toBe(['<= 8.70.2'])
        ->and(rangesOf(cveSearchRanges([cve5('CVE-2030-3', $legacy([['version_value' => 'n/a']]))]), laravelFramework('12.69.2')))
        ->toBe([])
        // "!<" says what is NOT affected — no bound on what is
        ->and(rangesOf(cveSearchRanges([cve5('CVE-2030-4', $legacy([['version_affected' => '!<', 'version_value' => '5.8.17']]))]), laravelFramework('12.69.2')))
        ->toBe([])
        // freetext we can't read must not clear anything
        ->and(rangesOf(cveSearchRanges([cve5('CVE-2030-5', $legacy([['version_value' => 'all versions']]))]), laravelFramework('12.69.2')))
        ->toBe([]);
});

it('treats a lone version on an affected row as its release line', function () {
    $source = cveSearchRanges([cve5('CVE-2022-2886', ['affected' => [['vendor' => 'laravel', 'product' => 'Laravel', 'versions' => [['status' => 'affected', 'version' => '5.1']]]]])]);

    $ranges = rangesOf($source, laravelFramework('12.69.2'));

    expect($ranges)->toBe(['>= 5.1, < 5.2'])
        ->and(VersionRange::isVulnerable('5.1.40', $ranges))->toBeTrue()
        ->and(VersionRange::isVulnerable('5.2.0', $ranges))->toBeFalse();
});

it('judges by the queried product when the ADP names several, matching through the cpes too', function () {
    $source = cveSearchRanges([cve5('CVE-2030-6', CNA_PLACEHOLDER, [['affected' => [
        ['vendor' => 'laravel', 'product' => 'lumen', 'versions' => [['status' => 'affected', 'version' => '1.0.0']]],
        ['cpes' => ['cpe:2.3:a:laravel:framework:*:*:*:*:*:*:*:*'], 'vendor' => 'laravel', 'product' => 'Laravel Framework',
            'versions' => [['status' => 'affected', 'version' => '< 9.32.0']]],
    ]]])]);

    expect(rangesOf($source, laravelFramework('12.69.2')))->toBe(['< 9.32.0']);
});

it('still fails safe: an affirmative ADP row without a readable bound makes the record undeterminable', function () {
    $source = cveSearchRanges([cve5('CVE-2030-7', CNA_PLACEHOLDER, [['affected' => [
        ['vendor' => 'laravel', 'product' => 'framework', 'versions' => [['status' => 'affected', 'version' => '< 9.32.0'], ['status' => 'affected', 'version' => 'unknown build']]],
    ]]])]);

    expect(rangesOf($source, laravelFramework('12.69.2')))->toBe([]);
});

it('links records to the instance that answered', function () {
    $public = cveSearchRanges([cve5('CVE-2030-8', CNA_PLACEHOLDER)]);
    $mirror = cveSearchRanges([cve5('CVE-2030-8', CNA_PLACEHOLDER)], ['base_url' => 'https://vl.internal/api/']);

    expect($public->queryPackage(laravelFramework('1.0'))[0]->sourceUrl)->toBe('https://cve.circl.lu/cve/CVE-2030-8')
        ->and($mirror->queryPackage(laravelFramework('1.0'))[0]->sourceUrl)->toBe('https://vl.internal/cve/CVE-2030-8');
});
