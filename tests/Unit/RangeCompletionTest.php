<?php

/*
 * A name-matched feed hands back a CVE with no version data; the version
 * filter can't clear it, so it was reported against every release forever.
 * completeRanges() asks NVD / GitHub by id and judges again.
 */

use Gumslone\Vulns\Data\PackageData;
use Gumslone\Vulns\Data\VulnerabilityData;
use Gumslone\Vulns\Sources\GitHubAdvisorySource;
use Gumslone\Vulns\Sources\NvdSource;
use Gumslone\Vulns\Support\CpeResolver;
use Gumslone\Vulns\Testing\FakeSource;
use Gumslone\Vulns\VulnSearch;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;

/**
 * NVD is asked about the package during the search itself (and finds
 * nothing — the CPE lookup for laravel:framework has no such record), so a
 * search spends one empty product page per package before any id lookup.
 */
function rcNvd(array $responses, array &$history = []): NvdSource
{
    $stack = HandlerStack::create(new MockHandler($responses));
    $stack->push(Middleware::history($history));

    return new NvdSource(new CpeResolver, null, new Client(['handler' => $stack]), ['rate_limit_max' => 1000, 'min_interval' => 0]);
}

function rcEmptyPage(): Response
{
    return new Response(200, [], json_encode(['totalResults' => 0, 'vulnerabilities' => []]));
}

/** The id lookups among the requests NVD saw. */
function rcLookups(array $history): array
{
    return array_values(array_filter(array_map(fn (array $h) => (string) $h['request']->getUri(), $history), fn (string $uri) => str_contains($uri, 'cveId=')));
}

function rcNvdRecord(string $id, array $cpeMatches): Response
{
    return new Response(200, [], json_encode(['vulnerabilities' => [['cve' => [
        'id' => $id,
        'descriptions' => [['lang' => 'en', 'value' => 'x']],
        'configurations' => $cpeMatches === [] ? [] : [['nodes' => [['cpeMatch' => $cpeMatches]]]],
    ]]]]));
}

function rcCveSearch(string ...$ids): FakeSource
{
    $vulns = array_map(fn (string $id) => new VulnerabilityData(vulnId: $id, source: 'cve_search', summary: 'Laravel before 5.8.17'), $ids);

    return new FakeSource('cve_search', ['laravel/framework' => $vulns, 'laravel/lumen' => $vulns]);
}

const FRAMEWORK_BEFORE_5_8_17 = [['vulnerable' => true, 'criteria' => 'cpe:2.3:a:laravel:framework:*:*:*:*:*:*:*:*', 'versionEndExcluding' => '5.8.17']];

function framework(string $version = '12.69.2'): PackageData
{
    return new PackageData(name: 'laravel/framework', version: $version, ecosystem: 'composer');
}

it('drops a range-less CVE once NVD proves the version outside its CPE ranges', function () {
    $history = [];
    $off = new VulnSearch([rcCveSearch('CVE-2020-19316'), rcNvd([rcEmptyPage()], $history)]);
    $on = (new VulnSearch([rcCveSearch('CVE-2020-19316'), rcNvd([rcEmptyPage(), rcNvdRecord('CVE-2020-19316', FRAMEWORK_BEFORE_5_8_17)], $history)]))->completeRanges(['nvd']);

    expect($off->search(framework()))->toHaveCount(1)                                  // off: kept, undeterminable
        ->and(rcLookups($history))->toBe([])
        ->and($on->search(framework()))->toBe([])                                      // on: cleared
        ->and(rcLookups($history))->toHaveCount(1)
        ->and(rcLookups($history)[0])->toContain('cveId=CVE-2020-19316');
});

it('keeps the CVE when the lookup proves it vulnerable, or proves nothing', function () {
    $vulnerable = (new VulnSearch([rcCveSearch('CVE-2020-19316'), rcNvd([rcEmptyPage(), rcNvdRecord('CVE-2020-19316', FRAMEWORK_BEFORE_5_8_17)])]))
        ->completeRanges(['nvd'])->search(framework('5.8.16'));
    $unknown = (new VulnSearch([rcCveSearch('CVE-2024-29291'), rcNvd([rcEmptyPage(), rcNvdRecord('CVE-2024-29291', [])])]))
        ->completeRanges(['nvd'])->search(framework());

    expect($vulnerable)->toHaveCount(1)
        ->and($vulnerable[0]->affectedRanges)->not->toBe([])
        ->and($vulnerable[0]->summary)->toBe('Laravel before 5.8.17')                 // the original stays the base
        ->and($unknown)->toHaveCount(1);
});

it('judges each package by its own product: the lookup clears the framework, not lumen', function () {
    $history = [];
    $search = (new VulnSearch([rcCveSearch('CVE-2020-19316'), rcNvd([rcEmptyPage(), rcEmptyPage(), rcNvdRecord('CVE-2020-19316', FRAMEWORK_BEFORE_5_8_17)], $history)]))
        ->completeRanges(['nvd']);

    $results = $search->searchBatch([
        'fw' => framework(),
        'lumen' => new PackageData(name: 'laravel/lumen', version: '12.0.0', ecosystem: 'composer'),
    ]);

    expect($results['fw'])->toBe([])
        ->and($results['lumen'])->toHaveCount(1)
        ->and(rcLookups($history))->toHaveCount(1);                                    // one id, one lookup
});

it('keeps the CVE and records the failure when the lookup source is down', function () {
    $search = (new VulnSearch([rcCveSearch('CVE-2020-19316'), (new FakeSource('nvd'))->failing('503 too many connections')]))
        ->completeRanges(['nvd']);

    expect($search->search(framework()))->toHaveCount(1)
        ->and($search->errors()['nvd'])->toContain('too many connections');
});

it('caps the lookups per search and says so', function () {
    $history = [];
    $search = (new VulnSearch([rcCveSearch('CVE-2030-1', 'CVE-2030-2'), rcNvd([rcEmptyPage(), rcNvdRecord('CVE-2030-1', FRAMEWORK_BEFORE_5_8_17)], $history)]))
        ->completeRanges(['nvd'], max: 1);

    expect($search->search(framework()))->toHaveCount(1)
        ->and(rcLookups($history))->toHaveCount(1)
        ->and($search->errors()['ranges'])->toBe('1 of 2 advisories left without range lookup (max 1 per search)');
});

it('looks nothing up for versionless packages, with the filter off, or on a source that cannot resolve the id', function () {
    $history = [];
    $nvd = rcNvd([rcEmptyPage(), rcEmptyPage()], $history);
    $github = new GitHubAdvisorySource(new Client(['handler' => HandlerStack::create(new MockHandler([]))])); // no token → knowsId() false

    (new VulnSearch([rcCveSearch('CVE-2020-19316'), $nvd, $github]))->completeRanges(['github', 'nvd'])
        ->search(new PackageData(name: 'laravel/framework', version: null, ecosystem: 'composer'));
    (new VulnSearch([rcCveSearch('CVE-2020-19316'), $nvd, $github]))->completeRanges(['github', 'nvd'])->filterByVersion(false)
        ->search(framework());

    expect(rcLookups($history))->toHaveCount(0)
        ->and($history)->toHaveCount(2);                                               // the two product searches only
});

it('is a plain-PHP opt-in that only()/except() and the other copies carry along', function () {
    $search = (new VulnSearch([rcCveSearch('CVE-2020-19316'), rcNvd([rcEmptyPage(), rcNvdRecord('CVE-2020-19316', FRAMEWORK_BEFORE_5_8_17), rcEmptyPage()])]))
        ->completeRanges(['nvd'])->only(['cve_search', 'nvd'])->preferLatest();

    expect($search->search(framework()))->toBe([])
        ->and($search->completeRanges(false)->search(framework()))->toHaveCount(1);
});

it('lets the lookup decide when the record\'s own range is unreadable', function () {
    // CVE-2020-7776 as the Snyk CNA wrote it: "0.0.0 to unspecified" — a
    // bound VersionRange can't read, so the record stays undeterminable and
    // the merge (base's ranges first) would ignore NVD's "< 1.16.0".
    $unreadable = new VulnerabilityData(vulnId: 'CVE-2020-7776', source: 'cve_search', affectedRanges: [['range' => '>= 0.0.0, < unspecified', 'source' => 'cve_search']]);
    $nvd = fn () => rcNvd([rcEmptyPage(), rcNvdRecord('CVE-2020-7776', [['vulnerable' => true, 'criteria' => 'cpe:2.3:a:phpoffice:phpspreadsheet:*:*:*:*:*:*:*:*', 'versionEndExcluding' => '1.16.0']])]);
    $spreadsheet = fn (string $v) => new PackageData(name: 'phpoffice/phpspreadsheet', version: $v, ecosystem: 'composer');

    $cleared = (new VulnSearch([new FakeSource('cve_search', ['phpoffice/phpspreadsheet' => [$unreadable]]), $nvd()]))->completeRanges(['nvd'])->search($spreadsheet('5.10.0'));
    $kept = (new VulnSearch([new FakeSource('cve_search', ['phpoffice/phpspreadsheet' => [$unreadable]]), $nvd()]))->completeRanges(['nvd'])->search($spreadsheet('1.15.0'));

    expect($cleared)->toBe([])
        ->and($kept)->toHaveCount(1)
        ->and(array_column($kept[0]->affectedRanges, 'range'))->toBe(['< 1.16.0'])
        ->and($kept[0]->source)->toBe('cve_search');
});

it('lets the lookup bound an open-ended "affected from 0.0.0" claim, and keeps it when nothing bounds it', function () {
    // The legacy v4 record on CVE-2020-7776: version_affected ">=" 0.0.0 — a
    // disclosure-time "no fix known"; NVD's analysis says "< 1.16.0".
    $openEnded = new VulnerabilityData(vulnId: 'CVE-2020-7776', source: 'cve_search', affectedRanges: [['range' => '>= 0.0.0', 'source' => 'cve_search']]);
    $bounded = fn () => rcNvd([rcEmptyPage(), rcNvdRecord('CVE-2020-7776', [['vulnerable' => true, 'criteria' => 'cpe:2.3:a:phpoffice:phpspreadsheet:*:*:*:*:*:*:*:*', 'versionEndExcluding' => '1.16.0']])]);
    $unbounded = fn () => rcNvd([rcEmptyPage(), rcNvdRecord('CVE-2020-7776', [['vulnerable' => true, 'criteria' => 'cpe:2.3:a:phpoffice:phpspreadsheet:*:*:*:*:*:*:*:*', 'versionStartIncluding' => '0.0.0']])]);
    $search = fn (NvdSource $nvd) => (new VulnSearch([new FakeSource('cve_search', ['phpoffice/phpspreadsheet' => [$openEnded]]), $nvd]))->completeRanges(['nvd']);
    $spreadsheet = fn (string $v) => new PackageData(name: 'phpoffice/phpspreadsheet', version: $v, ecosystem: 'composer');

    // …and as cve.circl.lu really serves it: the CNA's unreadable upper bound
    // next to the legacy record's open-ended lower one — neither bounds it.
    $asServed = new VulnerabilityData(vulnId: 'CVE-2020-7776', source: 'cve_search', affectedRanges: [['range' => '>= 0.0.0, < unspecified', 'source' => 'cve_search'], ['range' => '>= 0.0.0', 'source' => 'cve_search']]);

    expect($search($bounded())->search($spreadsheet('5.10.0')))->toBe([])
        ->and((new VulnSearch([new FakeSource('cve_search', ['phpoffice/phpspreadsheet' => [$asServed]]), $bounded()]))->completeRanges(['nvd'])->search($spreadsheet('5.10.0')))->toBe([])
        ->and($search($bounded())->search($spreadsheet('1.15.0')))->toHaveCount(1)
        ->and($search($unbounded())->search($spreadsheet('5.10.0')))->toHaveCount(1)
        ->and($search($bounded())->completeRanges(false)->search($spreadsheet('5.10.0')))->toHaveCount(1);
});
