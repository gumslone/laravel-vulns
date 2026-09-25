<?php

/*
 * A CVE reported by NVD / CVE-Search arrives without its GHSA / GO- aliases;
 * when OSV and GitHub had no package-level answer (a pkg:github/… purl) those
 * ids never come. completeAliases() looks each such CVE up once by id.
 */

use Gumslone\Vulns\Data\PackageData;
use Gumslone\Vulns\Data\VulnerabilityData;
use Gumslone\Vulns\Sources\GitHubAdvisorySource;
use Gumslone\Vulns\Sources\OsvSource;
use Gumslone\Vulns\Support\ArrayCache;
use Gumslone\Vulns\Testing\FakeSource;
use Gumslone\Vulns\VulnSearch;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;

function acClient(array $responses, array &$history = []): Client
{
    $stack = HandlerStack::create(new MockHandler($responses));
    $stack->push(Middleware::history($history));

    return new Client(['handler' => $stack]);
}

it('completes CVE-only records with the aliases OSV knows, once per CVE, keeping the original as base', function () {
    $grpc = new PackageData(name: 'grpc/grpc', version: 'v1.76.0', ecosystem: 'github');
    $fromNvd = new VulnerabilityData(vulnId: 'CVE-2026-33186', source: 'nvd', summary: 'NVD wording', cvssV3Score: 7.5);
    $fromNvdToo = new VulnerabilityData(vulnId: 'CVE-2026-33187', source: 'nvd', aliases: ['GHSA-xxxx-xxxx-xxxx']); // already has aliases

    $history = [];
    $osv = new OsvSource(acClient([
        new Response(200, [], json_encode([
            'id' => 'GHSA-p77j-4mvh-x3m3', 'summary' => 'OSV wording', 'aliases' => ['CVE-2026-33186', 'GO-2026-4762'],
            'affected' => [['package' => ['ecosystem' => 'Go', 'name' => 'google.golang.org/grpc'], 'ranges' => [['type' => 'SEMVER', 'events' => [['introduced' => '0'], ['fixed' => '1.76.1']]]]]],
            'references' => [['type' => 'FIX', 'url' => 'https://x.test/fix']],
        ])),
    ], $history), [], null, new ArrayCache);

    $search = (new VulnSearch([new FakeSource('nvd', ['grpc/grpc' => [$fromNvd, $fromNvdToo]]), $osv]))->completeAliases(['osv']);

    $results = $search->search($grpc);
    $again = $search->search($grpc);

    $cve = $results[0];
    expect($cve->vulnId)->toBe('CVE-2026-33186')
        ->and($cve->aliases)->toEqualCanonicalizing(['GHSA-p77j-4mvh-x3m3', 'GO-2026-4762'])
        ->and($cve->altId())->toBe('GHSA-p77j-4mvh-x3m3')
        ->and($cve->ghsaId())->toBe('GHSA-p77j-4mvh-x3m3')
        ->and($cve->summary)->toBe('NVD wording')                  // the original's opinion wins…
        ->and($cve->cvssV3Score)->toBe(7.5)
        ->and($cve->fixedVersions)->toBe(['Go:1.76.1'])              // …the lookup fills gaps
        ->and($cve->references)->toBe([['type' => 'FIX', 'url' => 'https://x.test/fix']])
        ->and($results[1]->aliases)->toBe(['GHSA-xxxx-xxxx-xxxx'])
        ->and($history)->toHaveCount(1)                              // one request: the aliased CVE wasn't looked up, the second search hit the cache
        ->and($again[0]->aliases)->toEqualCanonicalizing(['GHSA-p77j-4mvh-x3m3', 'GO-2026-4762'])
        ->and($search->errors())->toBe([]);

    // Off by default, and a failing lookup is an error, never a lost result.
    expect((new VulnSearch([new FakeSource('nvd', ['grpc/grpc' => [$fromNvd]]), $osv]))->search($grpc)[0]->aliases)->toBe([]);
    $down = (new VulnSearch([new FakeSource('nvd', ['grpc/grpc' => [$fromNvd]]), new OsvSource(acClient([new Response(503, [], 'down')]), ['retry' => 0])]))->completeAliases();
    expect($down->search($grpc)[0]->vulnId)->toBe('CVE-2026-33186')
        ->and($down->errors()['osv'])->toContain('alias lookup');
});

it('looks a CVE up on GitHub through its identifier, and bounds the lookups per search', function () {
    $history = [];
    $github = new GitHubAdvisorySource(acClient([
        new Response(200, [], json_encode(['data' => ['securityAdvisories' => ['nodes' => [[
            'ghsaId' => 'GHSA-p77j-4mvh-x3m3', 'summary' => 's', 'severity' => 'HIGH',
            'identifiers' => [['type' => 'GHSA', 'value' => 'GHSA-p77j-4mvh-x3m3'], ['type' => 'CVE', 'value' => 'CVE-2026-33186']],
            'references' => [], 'cwes' => ['nodes' => []],
        ]]]]])),
    ], $history), ['token' => 't'], null, new ArrayCache);

    $found = $github->fetchById('cve-2026-33186');
    $sent = json_decode((string) $history[0]['request']->getBody(), true);
    expect($found->vulnId)->toBe('CVE-2026-33186')
        ->and($found->aliases)->toBe(['GHSA-p77j-4mvh-x3m3'])
        ->and($sent['variables'])->toBe(['cve' => 'CVE-2026-33186'])
        ->and($sent['query'])->toContain('identifier: {type: CVE')
        ->and($github->knowsId('CVE-2026-33186'))->toBeTrue()
        ->and((new GitHubAdvisorySource(null, []))->knowsId('CVE-2026-33186'))->toBeFalse()
        ->and($github->fetchById('CVE-2026-33186'))->not->toBeNull()
        ->and($history)->toHaveCount(1);

    $vulns = array_map(fn (int $i) => new VulnerabilityData(vulnId: "CVE-2030-{$i}", source: 'nvd'), range(1, 3));
    $search = (new VulnSearch([new FakeSource('nvd', ['x' => $vulns]), new FakeSource('osv')]))->completeAliases(['osv'], max: 2);
    $search->search(new PackageData(name: 'x', version: '1', ecosystem: 'npm'));
    expect($search->errors()['aliases'])->toContain('1 of 3 CVEs left');
});

it('picks the GHSA id as the alternative id, else the first other alias', function () {
    expect((new VulnerabilityData(vulnId: 'CVE-2030-1', source: 'nvd', aliases: ['GO-2030-1', 'GHSA-aaaa-bbbb-cccc']))->altId())->toBe('GHSA-aaaa-bbbb-cccc')
        ->and((new VulnerabilityData(vulnId: 'GHSA-aaaa-bbbb-cccc', source: 'osv', aliases: ['CVE-2030-1']))->altId())->toBe('GHSA-aaaa-bbbb-cccc')
        ->and((new VulnerabilityData(vulnId: 'CVE-2030-1', source: 'nvd', aliases: ['PYSEC-2030-1']))->altId())->toBe('PYSEC-2030-1')
        ->and((new VulnerabilityData(vulnId: 'CVE-2030-1', source: 'nvd'))->altId())->toBeNull()
        ->and((new VulnerabilityData(vulnId: 'GHSA-aaaa-bbbb-cccc', source: 'osv'))->altId())->toBeNull();
});
