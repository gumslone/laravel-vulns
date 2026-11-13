<?php

use Gumslone\Vulns\Contracts\CpeLookup;
use Gumslone\Vulns\Data\PackageData;
use Gumslone\Vulns\Sources\EuvdSource;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
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

it('keeps multi-product patch entries out of fixedVersions — the fix claim would be ambiguous', function () {
    $item = [
        'id' => 'EUVD-2030-50',
        'description' => 'Multi-product advisory with a patch for only one of them.',
        'aliases' => 'CVE-2030-50',
        'enisaIdProduct' => [
            ['product' => ['name' => 'jenkins'], 'product_version' => '0 ≤2.575'],
            ['product' => ['name' => 'some-plugin'], 'product_version' => 'patch: 99.0'],
        ],
    ];
    $vuln = euvdSource([euvdSearch([$item])])->queryBatch([
        new PackageData(name: 'jenkins', version: '2.500', ecosystem: 'generic'),
    ])[0][0];

    // The foreign patch must not feed isPastAllFixes for jenkins.
    expect($vuln->fixedVersions)->toBe([])
        ->and($vuln->isFixed)->toBeFalse();
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

it('treats an advisory with unnamed product entries as ambiguous for patch claims', function () {
    $item = [
        'id' => 'EUVD-2030-60',
        'description' => 'Backfilled record without product names.',
        'aliases' => 'CVE-2030-60',
        'enisaIdProduct' => [
            ['product' => ['name' => ''], 'product_version' => 'patch: 9.9'],
            ['product' => ['name' => ''], 'product_version' => '0 ≤2.0'],
        ],
    ];
    $vuln = euvdSource([euvdSearch([$item])])->queryBatch([
        new PackageData(name: 'whatever', version: '1.0', ecosystem: 'generic'),
    ])[0][0];

    expect($vuln->fixedVersions)->toBe([])
        ->and($vuln->isFixed)->toBeFalse();
});

/*
 * EUVD's search is a "contains" match on the product name. Before the product
 * and vendor were checked, every hit landed on the package: a live fetch put
 * Jenkins and Intel configuration tools on league/config and 685 records on
 * the npm package "he".
 */

/** One search hit with a product name, a vendor and a version text. */
function euvdHit(string $id, string $product, ?string $vendor, string $productVersion = '0 <99.0.0'): array
{
    return [
        'id' => $id,
        'description' => "A bug in {$product}.",
        'aliases' => str_replace('EUVD', 'CVE', $id),
        'baseScore' => 7.5,
        'enisaIdProduct' => [['product' => ['name' => $product], 'product_version' => $productVersion]],
        'enisaIdVendor' => $vendor === null ? [] : [['vendor' => ['name' => $vendor]]],
    ];
}

it('keeps only the hits that are about the package, not everything whose name contains the term', function () {
    $source = euvdSource([euvdSearch([
        euvdHit('EUVD-2031-1', 'Microsoft Configuration Manager 2603', 'Microsoft'),
        euvdHit('EUVD-2031-2', 'AWS Global Configuration Plugin', 'Jenkins'),
        euvdHit('EUVD-2031-3', 'Config::IniFiles', 'SHLOMIF'),
        euvdHit('EUVD-2031-4', 'config', 'node-config'),      // same name, another vendor's package
        euvdHit('EUVD-2031-5', 'config', 'The PHP League'),   // ours
    ])]);

    $results = $source->queryBatch([
        new PackageData(name: 'config', version: '1.2.0', ecosystem: 'composer', namespace: 'league'),
    ]);

    expect(array_map(fn ($v) => $v->vulnId, $results[0]))->toBe(['CVE-2031-5']);
});

it('looks packages that share a bare name up separately and gives each only its own advisories', function () {
    $hits = [
        euvdHit('EUVD-2031-10', 'core', 'vueuse'),
        euvdHit('EUVD-2031-11', 'core', 'inertiajs'),
        euvdHit('EUVD-2031-12', 'Drupal core', 'Drupal'),
    ];
    $history = [];
    $stack = HandlerStack::create(new MockHandler([euvdSearch($hits), euvdSearch($hits)]));
    $stack->push(Middleware::history($history));
    $source = new EuvdSource(new Client(['handler' => $stack]));

    $results = $source->queryBatch([
        'vueuse' => new PackageData(name: 'core', version: '11.3.0', ecosystem: 'npm', namespace: '@vueuse'),
        'inertia' => new PackageData(name: 'core', version: '2.3.27', ecosystem: 'npm', namespace: '@inertiajs'),
        'vueuse-old' => new PackageData(name: 'core', version: '10.0.0', ecosystem: 'npm', namespace: '@vueuse'),
    ]);

    expect($history)->toHaveCount(2) // one search per identity; the two @vueuse versions share theirs
        ->and(array_map(fn ($v) => $v->vulnId, $results['vueuse']))->toBe(['CVE-2031-10'])
        ->and(array_map(fn ($v) => $v->vulnId, $results['vueuse-old']))->toBe(['CVE-2031-10'])
        ->and(array_map(fn ($v) => $v->vulnId, $results['inertia']))->toBe(['CVE-2031-11']);
});

it('searches by the bare name and pages by records read, not by records kept', function () {
    // 150 records in all; the first page holds nothing about the package.
    $page = fn (array $items) => new Response(200, [], json_encode(['items' => $items, 'total' => 150]));
    $noise = array_map(fn (int $i) => euvdHit("EUVD-2031-{$i}", "Framework Tool {$i}", 'Someone'), range(100, 199));
    $rest = array_map(fn (int $i) => euvdHit("EUVD-2031-{$i}", "Framework Tool {$i}", 'Someone'), range(200, 248));
    $rest[] = euvdHit('EUVD-2031-999', 'framework', 'Laravel');

    $history = [];
    $stack = HandlerStack::create(new MockHandler([$page($noise), $page($rest)]));
    $stack->push(Middleware::history($history));
    $source = new EuvdSource(new Client(['handler' => $stack]));

    $results = $source->queryBatch([
        new PackageData(name: 'laravel/framework', version: '11.55.0', ecosystem: 'composer'),
    ]);

    parse_str($history[0]['request']->getUri()->getQuery(), $first);
    parse_str($history[1]['request']->getUri()->getQuery(), $second);
    expect($history)->toHaveCount(2)
        ->and($first['product'])->toBe('framework')
        ->and($second['page'])->toBe('1')
        ->and(array_map(fn ($v) => $v->vulnId, $results[0]))->toBe(['CVE-2031-999']);
});

it('rejects an exact name from an unrelated vendor unless told to match by name alone', function () {
    $hits = [euvdHit('EUVD-2031-20', 'express', 'Ubiquiti Inc'), euvdHit('EUVD-2031-21', 'express', 'expressjs')];
    $package = [new PackageData(name: 'express', version: '4.18.2', ecosystem: 'npm')];
    $client = fn () => new Client(['handler' => HandlerStack::create(new MockHandler([euvdSearch($hits)]))]);

    expect(array_map(fn ($v) => $v->vulnId, (new EuvdSource($client()))->queryBatch($package)[0]))->toBe(['CVE-2031-21'])
        ->and(array_map(fn ($v) => $v->vulnId, (new EuvdSource($client(), ['match' => 'name']))->queryBatch($package)[0]))
        ->toBe(['CVE-2031-20', 'CVE-2031-21']);
});

it('keeps a hit that names no product — it cannot be judged', function () {
    $item = ['id' => 'EUVD-2031-30', 'description' => 'Old backfilled record.', 'aliases' => 'CVE-2031-30', 'enisaIdProduct' => []];

    $results = euvdSource([euvdSearch([$item])])->queryBatch([
        new PackageData(name: 'config', version: '1.2.0', ecosystem: 'composer', namespace: 'league'),
    ]);

    expect($results[0])->toHaveCount(1);
});

it("uses the curated CPE's vendor to tell same-named products apart", function () {
    // OpenSSL's CVEs must not land on the Rust crate that binds to it.
    $hits = [euvdHit('EUVD-2031-40', 'OpenSSL', 'OpenSSL', '0 <1.1.1'), euvdHit('EUVD-2031-41', 'openssl', 'sfackler', '0 <0.10.90')];
    $catalog = new class implements CpeLookup
    {
        public function bestCpe23(?string $purl, ?string $version): ?string
        {
            return $purl === 'pkg:cargo/openssl@0.10.81' ? 'cpe:2.3:a:sfackler:openssl:*:*:*:*:*:*:*:*' : null;
        }
    };
    $crate = [new PackageData(name: 'openssl', version: '0.10.81', ecosystem: 'cargo', purl: 'pkg:cargo/openssl@0.10.81')];
    $client = fn () => new Client(['handler' => HandlerStack::create(new MockHandler([euvdSearch($hits)]))]);

    $with = (new EuvdSource($client(), [], null, null, $catalog))->queryBatch($crate)[0];
    $without = (new EuvdSource($client()))->queryBatch($crate)[0];

    expect(array_map(fn ($v) => $v->vulnId, $with))->toBe(['CVE-2031-41'])
        ->and(array_map(fn ($v) => $v->vulnId, $without))->toBe(['CVE-2031-40']); // name alone: only the self-named vendor passes
});
