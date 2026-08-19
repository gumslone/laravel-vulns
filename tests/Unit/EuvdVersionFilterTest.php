<?php

use Gumslone\Vulns\Data\PackageData;
use Gumslone\Vulns\Sources\EuvdSource;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;

function euvdSource(array $responses): EuvdSource
{
    return new EuvdSource(new Client(['handler' => HandlerStack::create(new MockHandler($responses))]));
}

/** One EUVD search item with the given product_version strings. */
function euvdItem(string $id, array $productVersions, string $product = 'curl'): array
{
    return [
        'id' => $id,
        'description' => "A bug in {$product}.",
        'aliases' => str_replace('EUVD', 'CVE', $id),
        'baseScore' => 7.5,
        'enisaIdProduct' => array_map(fn ($pv) => [
            'product' => ['name' => $product],
            'product_version' => $pv,
        ], $productVersions),
    ];
}

function euvdSearch(array $items): Response
{
    return new Response(200, [], json_encode(['items' => $items]));
}

it('extracts version ranges from the live product_version grammar', function (string $text, string $expected) {
    $source = euvdSource([euvdSearch([euvdItem('EUVD-2030-1', [$text])])]);

    $vuln = $source->queryBatch([
        new PackageData(name: 'curl', version: null, ecosystem: 'generic'),
    ])[0][0];

    expect($vuln->affectedRanges[0]['range'] ?? null)->toBe($expected)
        ->and($vuln->affectedRanges[0]['raw'])->toBe($text);
})->with([
    'start + exclusive end' => ['2.13.1 <2.25.5', '>= 2.13.1, < 2.25.5'],
    'unicode ≤ with zero start' => ['0 ≤1.8.3', '<= 1.8.3'],
    'module-name prefix' => ['log4j-core <2.17.1', '< 2.17.1'],
    'exact version behind prefix' => ['log4j-core 2.13.0', '= 2.13.0'],
    'bounded pre-release' => ['3.0.0-alpha1 ≤3.0.0-beta2', '>= 3.0.0-alpha1, <= 3.0.0-beta2'],
    'x wildcard' => ['Apache Log4j 1.2 1.2.x', '>= 1.2, < 1.3'],
]);

it('drops advisories the queried version provably escapes and keeps the rest', function () {
    $source = euvdSource([euvdSearch([
        euvdItem('EUVD-2030-10', ['0 <7.0.0']),           // fixed long ago
        euvdItem('EUVD-2030-11', ['7.88.0 ≤8.19.0']),     // still affected
        euvdItem('EUVD-2030-12', ['entirely unparseable prose']), // can't tell → keep
    ])]);

    $results = $source->queryBatch([
        new PackageData(name: 'curl', version: '8.4.0', ecosystem: 'generic'),
    ]);

    $ids = array_map(fn ($v) => $v->vulnId, $results[0]);
    expect($ids)->toBe(['CVE-2030-11', 'CVE-2030-12']);
});

it("never lets another product's parseable range clear the queried package", function () {
    // The advisory lists our product with unparseable text AND another
    // product with a clean range our version escapes — fail-safe keeps it.
    $item = [
        'id' => 'EUVD-2030-20',
        'description' => 'Multi-product advisory.',
        'aliases' => 'CVE-2030-20',
        'enisaIdProduct' => [
            ['product' => ['name' => 'curl'], 'product_version' => 'all versions of the legacy branch'],
            ['product' => ['name' => 'other-thing'], 'product_version' => '0 <1.0.0'],
        ],
    ];
    $source = euvdSource([euvdSearch([$item])]);

    $results = $source->queryBatch([
        new PackageData(name: 'curl', version: '8.4.0', ecosystem: 'generic'),
    ]);

    expect(array_map(fn ($v) => $v->vulnId, $results[0]))->toBe(['CVE-2030-20']);
});

it('keeps everything for a versionless package', function () {
    $source = euvdSource([euvdSearch([euvdItem('EUVD-2030-30', ['0 <1.0.0'])])]);

    $results = $source->queryBatch([
        new PackageData(name: 'curl', version: null, ecosystem: 'generic'),
    ]);

    expect($results[0])->toHaveCount(1);
});

it('maps patch: entries to fixed versions, not affected ranges', function () {
    $source = euvdSource([euvdSearch([euvdItem('EUVD-2030-40', ['patch: 2.576', '0 ≤2.575'], 'jenkins')])]);

    $vuln = $source->queryBatch([
        new PackageData(name: 'jenkins', version: '2.500', ecosystem: 'generic'),
    ])[0][0];

    expect($vuln->isFixed)->toBeTrue()
        ->and($vuln->fixedVersions)->toBe(['2.576'])
        ->and($vuln->affectedRanges)->toHaveCount(1);
});

it('handles the old backfilled grammar: n/a placeholders and hyphenated release tags', function () {
    // Real shape of pre-2018 records: enumerated "openssl-<tag>" entries
    // (letter-suffixed) plus an "n/a" placeholder alongside.
    $item = euvdItem('EUVD-2016-1', ['openssl-1.0.2a', 'openssl-1.0.2j', 'openssl-1.1.0a', 'n/a'], 'openssl');
    $affected = euvdSource([euvdSearch([$item])])->queryBatch([
        new PackageData(name: 'openssl', version: '1.0.2j', ecosystem: 'generic'),
    ]);
    $safe = euvdSource([euvdSearch([$item])])->queryBatch([
        new PackageData(name: 'openssl', version: '3.0.0', ecosystem: 'generic'),
    ]);

    // The enumerated tag matches by equality despite the letter suffix…
    expect($affected[0])->toHaveCount(1)
        // …and a version outside the enumeration is provably clear: the n/a
        // placeholder is noise, not an unknown constraint blocking filtering.
        ->and($safe[0])->toHaveCount(0);
});

it('treats a 200 with an HTML body as a failed request, not zero vulnerabilities', function () {
    $source = euvdSource([new Response(200, [], '<!doctype html><html>SPA shell</html>')]);

    $source->queryBatch([new PackageData(name: 'curl', version: '8.4.0', ecosystem: 'generic')]);
})->throws(RuntimeException::class, 'malformed response body');
