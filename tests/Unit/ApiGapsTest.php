<?php

/*
 * v1.19: per-call search reports, the wider advisory-id vocabulary, record
 * helpers, purl conformance and upstream state the sources used to drop.
 */

use Gumslone\Vulns\Data\PackageData;
use Gumslone\Vulns\Data\VulnerabilityData;
use Gumslone\Vulns\SearchReport;
use Gumslone\Vulns\Sources\CveSearchSource;
use Gumslone\Vulns\Sources\EuvdSource;
use Gumslone\Vulns\Sources\MitreCveSource;
use Gumslone\Vulns\Sources\NvdSource;
use Gumslone\Vulns\Support\CpeResolver;
use Gumslone\Vulns\Support\PurlBuilder;
use Gumslone\Vulns\Testing\FakeSource;
use Gumslone\Vulns\VulnSearch;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;

function gapClient(array $responses, array &$history = []): Client
{
    $stack = HandlerStack::create(new MockHandler($responses));
    $stack->push(Middleware::history($history));

    return new Client(['handler' => $stack]);
}

it('hands back a report that belongs to its call', function () {
    $vuln = new VulnerabilityData(vulnId: 'CVE-2030-1', source: 'osv', cvssV3Score: 7.5);
    $search = new VulnSearch([new FakeSource('osv', ['lodash' => [$vuln]]), (new FakeSource('nvd'))->failing('503')]);

    $report = $search->report([
        'a' => new PackageData(name: 'lodash', version: '4.17.20', ecosystem: 'npm'),
        'b' => new PackageData(name: 'left-pad', version: '1.3.0', ecosystem: 'npm'),
    ]);
    $search->fetchById('CVE-2030-2'); // a later call on the shared instance…

    expect($report)->toBeInstanceOf(SearchReport::class)   // …cannot rewrite the report
        ->and($report->for('a'))->toHaveCount(1)
        ->and($report->for('missing'))->toBe([])
        ->and($report->errors)->toBe(['nvd' => '503'])
        ->and($report->isComplete())->toBeFalse()
        ->and($report->isConclusive('b'))->toBeFalse()       // empty, but NVD failed: not a clean bill
        ->and($report->inconclusiveKeys())->toBe(['a', 'b'])
        ->and($report->vulnerableKeys())->toBe(['a'])
        ->and(count($report))->toBe(1)
        ->and(json_decode(json_encode($report), true)['results']['a'][0]['vuln_id'])->toBe('CVE-2030-1');

    $clean = (new VulnSearch([new FakeSource('osv')]))->report(['x' => new PackageData(name: 'x', version: '1', ecosystem: 'npm')]);
    expect($clean->isConclusive('x'))->toBeTrue()->and($clean->isComplete())->toBeTrue();
});

it('recognises the OSV-family and distro advisory ids, and nothing that is a package name', function () {
    foreach (['PYSEC-2021-19', 'rustsec-2021-0001', 'GO-2022-0001', 'MAL-2024-1', 'SNYK-JS-LODASH-1', 'RHSA-2024:1234',
        'DSA-5000-1', 'USN-6000-1', 'OSV-2020-111', 'ALSA-2024:1', 'SUSE-SU-2024:0001-1', 'sonatype-2020-1214', 'CVE-2021-44228'] as $id) {
        expect(VulnerabilityData::looksLikeAdvisoryId($id))->toBeTrue("{$id} should be an advisory id");
    }
    foreach (['left-pad', 'go-redis', 'vue-router', 'mal-formed', 'GO-', 'pkg:npm/x', 'what is this'] as $notAnId) {
        expect(VulnerabilityData::looksLikeAdvisoryId($notAnId))->toBeFalse("{$notAnId} is not an advisory id");
    }

    expect(VulnerabilityData::normaliseId('rustsec-2021-0001'))->toBe('RUSTSEC-2021-0001')
        ->and(VulnerabilityData::normaliseId('sonatype-2020-1214'))->toBe('sonatype-2020-1214')
        ->and(VulnerabilityData::normaliseId('snyk-js-lodash-1'))->toBe('SNYK-JS-LODASH-1')
        ->and(VulnerabilityData::normaliseId('GHSA-AAAA-bbbb-CCCC'))->toBe('GHSA-aaaa-bbbb-cccc');

    $pysec = new VulnerabilityData(vulnId: 'PYSEC-2021-19', source: 'osv');
    $search = new VulnSearch([new FakeSource('osv', ['x' => [$pysec]])]);
    expect($search->searchAny('pysec-2021-19'))->toHaveCount(1)
        ->and(fn () => $search->searchAny('left-pad'))->toThrow(InvalidArgumentException::class);
});

it('skips sources that cannot look an id up instead of recording their 400 as an outage', function () {
    $history = [];
    $nvd = new NvdSource(new CpeResolver, null, gapClient([], $history), ['rate_limit_max' => 1000]);
    $search = new VulnSearch([$nvd, new FakeSource('osv')]);

    expect($search->fetchById('GHSA-aaaa-bbbb-cccc'))->toBeNull()
        ->and($history)->toBe([])
        ->and($search->errors())->toBe([])
        ->and($search->coverage())->toBe(['GHSA-aaaa-bbbb-cccc' => ['queried' => ['osv'], 'skipped' => ['nvd'], 'failed' => []]]);
});

it('answers affects() / recommendedFix() on the record and serialises as toArray()', function () {
    $vuln = new VulnerabilityData(vulnId: 'CVE-2030-3', source: 'nvd', fixedVersions: ['4.17.21', '5.0.1'], affectedRanges: [
        ['range' => '>= 4.0.0, < 4.17.21', 'product' => 'lodash:lodash'],
        ['range' => '< 9.0.0', 'product' => 'other:bigapp'],
    ]);

    expect($vuln->affects('4.17.20', 'lodash'))->toBeTrue()
        ->and($vuln->affects('4.17.21', 'lodash'))->toBeFalse()
        ->and($vuln->affects('4.17.21'))->toBeTrue()            // unscoped: the sibling product's range counts
        ->and($vuln->affects(null, 'lodash'))->toBeNull()
        ->and($vuln->affects('1.0', 'unrelated'))->toBeNull()
        ->and($vuln->recommendedFix('4.17.20'))->toBe('4.17.21')
        ->and(json_decode(json_encode($vuln), true))->toBe(json_decode(json_encode($vuln->toArray()), true))
        ->and(json_decode(json_encode(new PackageData(name: 'x', version: '1', ecosystem: 'npm')), true)['name'])->toBe('x');
});

it('builds and parses purls to the specification', function () {
    $purl = new PurlBuilder;

    // Go module paths: the name is the last segment, and the round trip is stable.
    $go = $purl->parse('pkg:golang/github.com/gin-gonic/gin@v1.10.0');
    expect($go['namespace'])->toBe('github.com/gin-gonic')->and($go['name'])->toBe('gin')
        ->and($purl->build($go['type'], $go['name'], $go['version'], $go['namespace']))->toBe('pkg:golang/github.com/gin-gonic/gin@v1.10.0')
        ->and((new PackageData(name: 'golang.org/x/net/http2', version: 'v0.1.0', ecosystem: 'go'))->toPurl())->toBe('pkg:golang/golang.org/x/net/http2@v0.1.0')
        ->and(PackageData::fromPurl('pkg:golang/github.com/gin-gonic/gin@v1.10.0')->name)->toBe('github.com/gin-gonic/gin');

    expect($purl->build('generic', 'foo', '0'))->toBe('pkg:generic/foo@0')                        // "0" is a version
        ->and($purl->build('pypi', 'Django_Rest.Framework', '1.0'))->toBe('pkg:pypi/django-rest.framework@1.0')
        ->and($purl->build('github', 'Repo', '1', 'Owner'))->toBe('pkg:github/owner/repo@1')
        ->and($purl->build('npm', 'core', '7.25.0', '@babel'))->toBe('pkg:npm/%40babel/core@7.25.0')
        ->and($purl->build('deb', 'curl', '1:7.88.1-10', 'debian', ['distro' => 'debian-12', 'arch' => '', 'Vcs.Url' => 'git+https://x.test/a']))
        ->toBe('pkg:deb/debian/curl@1:7.88.1-10?distro=debian-12&vcs.url=git%2Bhttps:%2F%2Fx.test%2Fa')
        ->and($purl->build('npm', 'x', '1', null, [], '/src/../lib/./index.js'))->toBe('pkg:npm/x@1#src/lib/index.js');

    $parsed = $purl->parse('pkg://npm/foo@?Vcs.Url=git%2Bhttps%3A%2F%2Fx.test%2Fa&a[]=1&empty=');
    expect($parsed['version'])->toBeNull()
        ->and($parsed['qualifiers'])->toBe(['a[]' => '1', 'vcs.url' => 'git+https://x.test/a']);

    foreach (['pkg:n&pm/foo', 'pkg:/foo', 'pkg:npm', 'npm/foo'] as $invalid) {
        expect(fn () => $purl->parse($invalid))->toThrow(InvalidArgumentException::class);
    }
    expect(fn () => $purl->build('npm', ''))->toThrow(InvalidArgumentException::class)
        ->and((new PackageData(name: 'foo', version: '1', ecosystem: 'Debian:12'))->toPurl())->toBeNull()
        // case folds only where the type says so
        ->and($purl->checksum('pkg:pypi/Django@1.0'))->toBe($purl->checksum('pkg:pypi/django@1.0'))
        ->and($purl->checksum('pkg:maven/Org.X/Art@1.0'))->not->toBe($purl->checksum('pkg:maven/org.x/art@1.0'));
});

it('keeps the exploitation and withdrawal state the feeds publish', function () {
    $nvd = new NvdSource(new CpeResolver, null, gapClient([new Response(200, [], json_encode(['vulnerabilities' => [['cve' => [
        'id' => 'CVE-2030-4', 'descriptions' => [['lang' => 'en', 'value' => 'x']],
        'cisaExploitAdd' => '2030-02-01', 'cisaActionDue' => '2030-02-22',
    ]]]]))]), ['rate_limit_max' => 1000]);
    $fromNvd = $nvd->fetchById('CVE-2030-4');

    $mitre = new MitreCveSource(gapClient([new Response(200, [], json_encode([
        'cveMetadata' => ['cveId' => 'CVE-2030-5', 'state' => 'PUBLISHED'],
        'containers' => ['cna' => ['descriptions' => [['lang' => 'en', 'value' => 'x']]], 'adp' => [[
            'title' => 'CISA ADP Vulnrichment',
            'metrics' => [['other' => ['type' => 'kev', 'content' => ['dateAdded' => '2030-03-01', 'reference' => 'https://www.cisa.gov/kev']]]],
        ]]],
    ]))]));
    $fromMitre = $mitre->fetchById('CVE-2030-5');

    $circl = new CveSearchSource(new CpeResolver, null, gapClient([new Response(200, [], json_encode([
        'cveMetadata' => ['cveId' => 'CVE-2030-6', 'state' => 'REJECTED'], 'containers' => ['cna' => []],
    ]))]));

    $euvd = new EuvdSource(gapClient([new Response(200, [], json_encode([
        'id' => 'EUVD-2030-7', 'description' => 'x', 'aliases' => "CVE-2030-7\n", 'exploitedSince' => 'Apr 2, 2030, 12:00:00 AM',
    ]))]));
    $fromEuvd = $euvd->fetchById('EUVD-2030-7');

    expect($fromNvd->isKnownExploited)->toBeTrue()
        ->and($fromNvd->kevSince?->format('Y-m-d'))->toBe('2030-02-01')
        ->and($fromNvd->kevDueDate?->format('Y-m-d'))->toBe('2030-02-22')
        ->and($fromMitre->isKnownExploited)->toBeTrue()
        ->and($fromMitre->kevSince?->format('Y-m-d'))->toBe('2030-03-01')
        ->and($circl->fetchById('CVE-2030-6')?->isWithdrawn)->toBeTrue()
        ->and($fromEuvd->isKnownExploited)->toBeTrue()
        ->and($fromEuvd->kevSince?->format('Y-m-d'))->toBe('2030-04-02');
});
