<?php

/*
 * v1.17 review: every case here used to make a vulnerable package read as
 * clean (or one advisory show up several times). Pinned so they stay fixed.
 */

use Gumslone\Vulns\Data\PackageData;
use Gumslone\Vulns\Data\VulnerabilityData;
use Gumslone\Vulns\ExploitMaturity;
use Gumslone\Vulns\Sources\CveSearchSource;
use Gumslone\Vulns\Sources\EuvdSource;
use Gumslone\Vulns\Sources\GitHubAdvisorySource;
use Gumslone\Vulns\Sources\NvdSource;
use Gumslone\Vulns\Sources\OsvSource;
use Gumslone\Vulns\Sources\RedHatSource;
use Gumslone\Vulns\Sources\ShodanCvedbSource;
use Gumslone\Vulns\Support\CpeResolver;
use Gumslone\Vulns\Support\VersionRange;
use Gumslone\Vulns\Testing\FakeSource;
use Gumslone\Vulns\VulnSearch;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;

function fnClient(array $responses, array &$history = []): Client
{
    $stack = HandlerStack::create(new MockHandler($responses));
    $stack->push(Middleware::history($history));

    return new Client(['handler' => $stack]);
}

function fnJson(mixed $body, int $status = 200): Response
{
    return new Response($status, [], json_encode($body));
}

function fnNvdCve(string $id, array $cpeMatches): array
{
    return ['cve' => [
        'id' => $id,
        'descriptions' => [['lang' => 'en', 'value' => 'x']],
        'configurations' => [['nodes' => [['cpeMatch' => $cpeMatches]]]],
    ]];
}

// ------------------------------------------------------------ VersionRange

it('compares versions of different segment counts as equal when zero-padded', function () {
    expect(VersionRange::isVulnerable('1.0', ['>= 1.0.0, < 1.5.0']))->toBeTrue()
        ->and(VersionRange::isVulnerable('1.0.0', ['<= 1.0']))->toBeTrue()
        ->and(VersionRange::isVulnerable('2.0', ['= 2.0.0']))->toBeTrue()
        ->and(VersionRange::isVulnerable('4.0.0.0', ['= 4.0.0']))->toBeTrue()   // NuGet four-part
        ->and(VersionRange::isVulnerable('1.5', ['>= 1.0.0, < 1.5.0']))->toBeFalse()
        ->and(VersionRange::isPastAllFixes('2.0', ['2.0.0']))->toBeTrue();
});

it('never answers "not affected" while any range is unreadable', function () {
    // The unparseable range may be the one that covers this version.
    expect(VersionRange::isVulnerable('5.3.2', ['>= 5.3.0.RELEASE, < 5.3.5', '< 4.0']))->toBeNull()
        ->and(VersionRange::isVulnerable('1.5', ['>= 1.0-rc1, < 2.0', '< 0.5']))->toBeNull()
        ->and(VersionRange::isVulnerable('3.0.5', ['< 2.0 || >= 3.0 < 3.1', '= 1.0']))->toBeNull()
        // OSV event lists carry no constraint string at all
        ->and(VersionRange::isVulnerable('3.0.5', [['type' => 'SEMVER', 'events' => [['introduced' => '0']]], '< 1.0']))->toBeNull()
        // …but a match still decides, and all-readable ranges still clear
        ->and(VersionRange::isVulnerable('0.4', ['>= 1.0-rc1, < 2.0', '< 0.5']))->toBeTrue()
        ->and(VersionRange::isVulnerable('5.0.0', ['< 1.0', '>= 2.0, < 3.0']))->toBeFalse()
        // "*" is every version
        ->and(VersionRange::isVulnerable('5.0.0', ['*', '= 1.0']))->toBeTrue();
});

it('treats an unorderable fix as possibly above the installed version, and epochs as part of the version', function () {
    expect(VersionRange::isPastAllFixes('2.0.5', ['1.2.5', '2.0.3', '3.0.0-rc1']))->toBeFalse()
        ->and(VersionRange::isPastAllFixes('1.0.0', ['1:0.9']))->toBeFalse()
        ->and(VersionRange::isPastAllFixes('1.9.0', ['Packagist:1.8.0']))->toBeTrue()
        ->and(VersionRange::recommendedFix('1.2.0', ['Packagist:1.2.5']))->toBe('1.2.5');
});

it('scopes ranges to the package they speak about', function () {
    $ranges = [
        ['range' => '< 1.0.0', 'product' => 'acme:widget'],
        ['range' => '< 9.0.0', 'product' => 'other:bigapp'],
    ];

    expect(VersionRange::relevantTo($ranges, 'widget'))->toBe([$ranges[0]])
        ->and(VersionRange::relevantTo($ranges, 'unrelated'))->toBe([])          // can't tell
        ->and(VersionRange::relevantTo(['< 2.0'], 'anything'))->toBe(['< 2.0'])  // untagged always count
        ->and(VersionRange::sameProduct('Apache Log4j', 'org.apache.logging.log4j:log4j-core'))->toBeFalse()
        ->and(VersionRange::sameProduct('log4j', 'org.apache.logging.log4j:log4j-core'))->toBeTrue()
        ->and(VersionRange::sameProduct('ExpressVPN', 'express'))->toBeFalse()
        ->and(VersionRange::sameProduct('express', 'express'))->toBeTrue();
});

// ------------------------------------------------------------------ Maven

it('names Maven packages group:artifact, which is what OSV and GitHub look up', function () {
    $package = PackageData::fromPurl('pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1');

    expect($package->name)->toBe('org.apache.logging.log4j:log4j-core')
        ->and($package->registryName())->toBe('org.apache.logging.log4j:log4j-core')
        ->and($package->toPurl())->toBe('pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1')
        ->and((new CpeResolver)->resolveCpe23($package))->toContain(':log4j-core:2.14.1')
        // a hand-built slash spelling is tolerated at query time
        ->and((new PackageData(name: 'org.x/art', version: '1', ecosystem: 'maven'))->registryName())->toBe('org.x:art')
        ->and((new PackageData(name: 'vendor/pkg', version: '1', ecosystem: 'composer'))->registryName())->toBe('vendor/pkg');

    $history = [];
    $osv = new OsvSource(fnClient([fnJson(['vulns' => []])], $history));
    $osv->queryPackage($package);
    $sent = json_decode((string) $history[0]['request']->getBody(), true);
    expect($sent['package'])->toBe(['name' => 'org.apache.logging.log4j:log4j-core', 'ecosystem' => 'Maven']);
});

// -------------------------------------------------------------------- NVD

it('NVD keeps CVEs whose range it cannot order, judges by the queried product, and honours an unbounded match', function () {
    $openssl = new PackageData(name: 'openssl', version: '1.1.1k', ecosystem: 'generic', cpe23: 'cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*');
    $widget = new PackageData(name: 'widget', version: '5.0.0', ecosystem: 'generic', cpe23: 'cpe:2.3:a:acme:widget:5.0.0:*:*:*:*:*:*:*');

    $history = [];
    $nvd = new NvdSource(new CpeResolver, null, fnClient([
        fnJson(['totalResults' => 1, 'vulnerabilities' => [fnNvdCve('CVE-2030-100', [
            ['vulnerable' => true, 'criteria' => 'cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*', 'versionStartIncluding' => '1.1.1', 'versionEndExcluding' => '1.1.1l'],
        ])]]),
        fnJson(['totalResults' => 2, 'vulnerabilities' => [
            // widget's own range excludes 5.0.0; a sibling product's must not flag it
            fnNvdCve('CVE-2030-101', [
                ['vulnerable' => true, 'criteria' => 'cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*', 'versionEndExcluding' => '1.0.0'],
                ['vulnerable' => true, 'criteria' => 'cpe:2.3:a:other:bigapp:*:*:*:*:*:*:*:*', 'versionEndExcluding' => '9.0.0'],
            ]),
            // "all versions" next to a pin must not be reduced to the pin
            fnNvdCve('CVE-2030-102', [
                ['vulnerable' => true, 'criteria' => 'cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*'],
                ['vulnerable' => true, 'criteria' => 'cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*'],
            ]),
        ]]),
    ], $history), ['rate_limit_max' => 1000]);

    expect(array_map(fn ($v) => $v->vulnId, $nvd->queryPackage($openssl)))->toBe(['CVE-2030-100']);

    $found = $nvd->queryPackage($widget);
    expect(array_map(fn ($v) => $v->vulnId, $found))->toBe(['CVE-2030-102'])
        ->and(array_column($found[0]->affectedRanges, 'range'))->toBe(['*', '= 1.0'])
        ->and(VersionRange::isVulnerable('5.0.0', $found[0]->affectedRanges))->toBeTrue();
});

// ------------------------------------------------- fetchById: down ≠ unknown

it('throws from fetchById when the feed is down, and answers null only for a real "no such record"', function (string $name) {
    $make = fn (array $r) => match ($name) {
        'osv' => new OsvSource(fnClient($r)),
        'nvd' => new NvdSource(new CpeResolver, null, fnClient($r), ['rate_limit_max' => 1000]),
        'euvd' => new EuvdSource(fnClient($r)),
        'cve_search' => new CveSearchSource(new CpeResolver, null, fnClient($r)),
    };

    expect(fn () => $make([new Response(500, [], 'down')])->fetchById('CVE-2030-1'))->toThrow(RuntimeException::class)
        ->and($make([new Response(404, [], '{}')])->fetchById('CVE-2030-1'))->toBeNull()
        // a 200 that is not JSON (proxy error page) is a failure too
        ->and(fn () => $make([new Response(200, [], '<html>Bad gateway</html>')])->fetchById('CVE-2030-1'))->toThrow(RuntimeException::class);
})->with(['osv', 'nvd', 'euvd', 'cve_search']);

it('GitHub fetchById throws on an outage or GraphQL error, and is simply not covered without a token', function () {
    $make = fn (array $r, array $o = ['token' => 't']) => new GitHubAdvisorySource(fnClient($r), $o);

    expect(fn () => $make([new Response(502, [], 'down')])->fetchById('GHSA-aaaa-bbbb-cccc'))->toThrow(RuntimeException::class)
        ->and(fn () => $make([fnJson(['errors' => [['type' => 'RATE_LIMITED']]])])->fetchById('GHSA-aaaa-bbbb-cccc'))->toThrow(RuntimeException::class, 'RATE_LIMITED')
        ->and($make([fnJson(['data' => ['securityAdvisory' => null], 'errors' => [['type' => 'NOT_FOUND']]])])->fetchById('GHSA-aaaa-bbbb-cccc'))->toBeNull()
        ->and($make([], [])->fetchById('GHSA-aaaa-bbbb-cccc'))->toBeNull();
});

// ----------------------------------------------------------------- GitHub

it('GitHub attributes a GraphQL error to its package instead of reporting it clean', function () {
    $page = fn (string $ghsa) => fnJson(['data' => ['securityVulnerabilities' => [
        'pageInfo' => ['hasNextPage' => false, 'endCursor' => null],
        'nodes' => [[
            'vulnerableVersionRange' => '< 2.0.0', 'firstPatchedVersion' => ['identifier' => '2.0.0'],
            'advisory' => ['ghsaId' => $ghsa, 'summary' => 's', 'severity' => 'HIGH', 'identifiers' => [['type' => 'GHSA', 'value' => $ghsa]],
                'references' => [], 'cwes' => ['nodes' => []]],
        ]],
    ]]]);

    $github = new GitHubAdvisorySource(fnClient([$page('GHSA-aaaa-aaaa-aaaa'), fnJson(['errors' => [['type' => 'RATE_LIMITED']]])]), ['token' => 't', 'max_concurrency' => 1]);
    $search = new VulnSearch([$github]);

    $results = $search->searchBatch([
        'a' => new PackageData(name: 'alpha', version: '1.0.0', ecosystem: 'npm'),
        'b' => new PackageData(name: 'beta', version: '1.0.0', ecosystem: 'npm'),
    ]);

    expect($results['a'])->toHaveCount(1)
        ->and($results['b'])->toBe([])
        ->and($search->errors()['github'])->toContain('RATE_LIMITED')
        ->and($search->coverage()['a'])->toBe(['queried' => ['github'], 'skipped' => [], 'failed' => []])
        ->and($search->coverage()['b'])->toBe(['queried' => [], 'skipped' => [], 'failed' => ['github']]);
});

it('GitHub treats a rate-limited repository-advisory lookup as a failure, a missing repo as nothing', function () {
    $repo = new PackageData(name: 'acme/widget', version: '1.0.0', ecosystem: 'github');

    expect(fn () => (new GitHubAdvisorySource(fnClient([new Response(403, [], '{"message":"API rate limit exceeded"}')]), ['retry' => 0]))->queryBatch([$repo]))
        ->toThrow(RuntimeException::class, 'acme/widget')
        ->and((new GitHubAdvisorySource(fnClient([new Response(404, [], '{}')])))->queryBatch([$repo]))->toBe([[]]);
});

// ------------------------------------------------------------- pagination

it('CVE-Search walks every page, encodes the lookup path, and fails on a non-JSON body', function () {
    $row = fn (int $i) => ['id' => "CVE-2030-{$i}", 'summary' => 'x'];
    $package = new PackageData(name: 'openssl', version: null, ecosystem: 'generic', cpe23: 'cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*');

    $history = [];
    $source = new CveSearchSource(new CpeResolver, null, fnClient([
        fnJson(['results' => array_map($row, range(1, 100)), 'total_count' => 130]),
        fnJson(['results' => array_map($row, range(101, 130)), 'total_count' => 130]),
    ], $history));

    expect($source->queryBatch([$package])[0])->toHaveCount(130)
        ->and((string) $history[1]['request']->getUri())->toContain('page=2')
        ->and($source->warnings())->toBe([]);

    // A crafted CPE can't climb out of search/ or append a query string.
    $history = [];
    $evil = new PackageData(name: 'x', version: null, ecosystem: 'generic', cpe23: 'cpe:2.3:a:..%2fadmin?x=1#:prod:*:*:*:*:*:*:*:*');
    (new CveSearchSource(new CpeResolver, null, fnClient([fnJson(['results' => []])], $history)))->queryBatch([$evil]);
    expect($history[0]['request']->getUri()->getPath())->toStartWith('search/')
        ->and((string) $history[0]['request']->getUri())->not->toContain('?x=1');

    expect(fn () => (new CveSearchSource(new CpeResolver, null, fnClient([new Response(200, [], '<html>maintenance</html>')])))->queryBatch([$package]))
        ->toThrow(RuntimeException::class, 'not valid JSON');
});

it('Shodan CVEDB pages with skip until a short page', function () {
    $row = fn (int $i) => ['cve_id' => "CVE-2030-{$i}", 'summary' => 'x'];

    $history = [];
    $source = new ShodanCvedbSource(fnClient([
        fnJson(['cves' => array_map($row, range(1, 50))]),
        fnJson(['cves' => array_map($row, range(51, 60))]),
    ], $history));

    $results = $source->queryBatch([new PackageData(name: 'openssl', version: '1.0.2', ecosystem: 'generic')]);

    parse_str($history[1]['request']->getUri()->getQuery(), $second);
    expect($results[0])->toHaveCount(60)->and($second['skip'])->toBe('50');
});

// ---------------------------------------------------------------- Red Hat

it('Red Hat is asked about OS packages only, by bare RPM name', function () {
    $history = [];
    $source = new RedHatSource(fnClient([fnJson([])], $history));

    expect($source->supports(new PackageData(name: 'tar', version: '6.0.0', ecosystem: 'npm')))->toBeFalse()
        ->and($source->supports(new PackageData(name: 'tar', version: '1.34', ecosystem: 'rpm')))->toBeTrue()
        ->and((new RedHatSource(null, ['ecosystems' => ['*']]))->supports(new PackageData(name: 'tar', version: '6', ecosystem: 'npm')))->toBeTrue();

    $source->queryBatch([
        PackageData::fromPurl('pkg:rpm/redhat/openssl@3.0.7'),
        new PackageData(name: 'tar', version: '6.0.0', ecosystem: 'npm'),
    ]);

    parse_str($history[0]['request']->getUri()->getQuery(), $query);
    expect($history)->toHaveCount(1)->and($query['package'])->toBe('openssl');
});

// -------------------------------------------------------------- VulnSearch

it('merges records that share any id, transitively, and pools what each feed knows', function () {
    $package = new PackageData(name: 'x', version: '1.0', ecosystem: 'npm');

    $osv = new VulnerabilityData(vulnId: 'GHSA-aaaa-bbbb-cccc', source: 'osv', aliases: ['CVE-2030-1'], cvssV3Score: 7.5,
        references: [['type' => null, 'url' => 'https://a.test/advisory']], cwes: ['CWE-79'], fixedVersions: ['npm:1.2.0']);
    $github = new VulnerabilityData(vulnId: 'ghsa-AAAA-bbbb-cccc ', source: 'github', summary: 'same advisory', fixedVersions: ['1.2.0', '2.0.1']);
    $snyk = new VulnerabilityData(vulnId: 'SNYK-JS-X-1', source: 'snyk', aliases: ['GHSA-aaaa-bbbb-cccc']);
    $nvd = new VulnerabilityData(vulnId: 'cve-2030-1', source: 'nvd', cwes: ['CWE-80'],
        references: [['type' => 'EXPLOIT', 'url' => 'https://b.test/poc'], ['type' => 'WEB', 'url' => 'https://a.test/advisory/']]);

    $merged = (new VulnSearch([
        new FakeSource('osv', ['x' => [$osv]]), new FakeSource('github', ['x' => [$github]]),
        new FakeSource('snyk', ['x' => [$snyk]]), new FakeSource('nvd', ['x' => [$nvd]]),
    ]))->search($package);

    expect($merged)->toHaveCount(1)
        ->and($merged[0]->vulnId)->toBe('CVE-2030-1')
        ->and($merged[0]->aliases)->toEqualCanonicalizing(['GHSA-aaaa-bbbb-cccc', 'SNYK-JS-X-1'])
        ->and($merged[0]->summary)->toBe('same advisory')
        ->and($merged[0]->cwes)->toBe(['CWE-79', 'CWE-80'])
        ->and($merged[0]->fixedVersions)->toBe(['npm:1.2.0', '2.0.1'])
        // the typed duplicate of a.test wins; the EXPLOIT link survives OSV being the base
        ->and(array_column($merged[0]->references, 'type'))->toBe(['WEB', 'EXPLOIT'])
        ->and($merged[0]->exploitMaturity())->not->toBe(ExploitMaturity::None);
});

it('drops only advisories the version provably escapes, whichever source delivered them', function () {
    $patched = new PackageData(name: 'lodash', version: '5.0.0', ecosystem: 'npm');
    $old = new VulnerabilityData(vulnId: 'CVE-2030-10', source: 'github', affectedRanges: [['range' => '< 1.0.0']]);
    $current = new VulnerabilityData(vulnId: 'CVE-2030-11', source: 'github', affectedRanges: [['range' => '>= 4.0.0, < 5.1.0']]);
    $unreadable = new VulnerabilityData(vulnId: 'CVE-2030-12', source: 'github', affectedRanges: [['range' => '< 6.0.0-beta.1']]);
    $noRanges = new VulnerabilityData(vulnId: 'CVE-2030-13', source: 'redhat');
    $otherProduct = new VulnerabilityData(vulnId: 'CVE-2030-14', source: 'nvd', affectedRanges: [['range' => '< 1.0', 'product' => 'acme:somethingelse']]);

    $search = new VulnSearch([new FakeSource('github', ['lodash' => [$old, $current, $unreadable, $noRanges, $otherProduct]])]);

    $ids = fn (array $vulns) => array_map(fn ($v) => $v->vulnId, $vulns);
    expect($ids($search->search($patched)))->toEqualCanonicalizing(['CVE-2030-11', 'CVE-2030-12', 'CVE-2030-13', 'CVE-2030-14'])
        ->and($ids($search->filterByVersion(false)->search($patched)))->toContain('CVE-2030-10')
        // no version → nothing to judge by
        ->and($search->search(new PackageData(name: 'lodash', version: null, ecosystem: 'npm')))->toHaveCount(5);
});

it('normalises advisory ids so casing, whitespace and repeats cannot split a record', function () {
    $vuln = new VulnerabilityData(vulnId: ' cve-2030-9 ', source: 'osv', aliases: ['CVE-2030-9', 'ghsa-AAAA-bbbb-cccc', '', 'GHSA-aaaa-bbbb-cccc', 'PYSEC-2030-1']);

    expect($vuln->vulnId)->toBe('CVE-2030-9')
        ->and($vuln->aliases)->toBe(['GHSA-aaaa-bbbb-cccc', 'PYSEC-2030-1'])
        ->and(VulnerabilityData::fromArray($vuln->toArray())->toArray())->toBe($vuln->toArray());
});

it('resets coverage() on fetchById so a previous batch cannot leak into it', function () {
    $search = new VulnSearch([new FakeSource('osv')]);
    $search->searchBatch(['a' => new PackageData(name: 'x', version: '1', ecosystem: 'npm')]);
    $search->fetchById('CVE-2030-1');

    expect($search->coverage())->toBe([]);
});
