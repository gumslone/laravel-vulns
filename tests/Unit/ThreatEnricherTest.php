<?php

use Gumslone\Vulns\ChangeImpact;
use Gumslone\Vulns\ChangeType;
use Gumslone\Vulns\Data\PackageData;
use Gumslone\Vulns\Data\VulnerabilityData;
use Gumslone\Vulns\Enrichment\ThreatEnricher;
use Gumslone\Vulns\VulnSearch;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;

function makeEnricher(array $responses, array &$history, array $options = []): ThreatEnricher
{
    $mock = new MockHandler($responses);
    $stack = HandlerStack::create($mock);
    $stack->push(Middleware::history($history));

    return new ThreatEnricher(new Client(['handler' => $stack]), $options);
}

function epssResponse(array $rows): Response
{
    return new Response(200, [], json_encode(['data' => $rows]));
}

function kevResponse(array $cveIds): Response
{
    return new Response(200, [], json_encode([
        'vulnerabilities' => array_map(fn ($id) => ['cveID' => $id], $cveIds),
    ]));
}

it('stamps EPSS scores and KEV listing onto merged results by canonical CVE id', function () {
    $history = [];
    $enricher = makeEnricher([
        epssResponse([['cve' => 'CVE-2030-1', 'epss' => '0.9432', 'percentile' => '0.999']]),
        kevResponse(['CVE-2030-1']),
    ], $history);

    // A GHSA-keyed record whose canonical id is the CVE alias must enrich too.
    $ghsa = new VulnerabilityData(vulnId: 'GHSA-xxxx-yyyy-zzzz', source: 'osv', aliases: ['CVE-2030-1']);

    $enriched = $enricher->apply([[$ghsa]]);

    expect($enriched[0][0]->epssScore)->toBe(0.9432)
        ->and($enriched[0][0]->epssPercentile)->toBe(0.999)
        ->and($enriched[0][0]->isKnownExploited)->toBeTrue()
        ->and($enricher->errors())->toBe([]);
});

it('leaves results un-enriched and records the failure when a feed is down', function () {
    $history = [];
    $enricher = makeEnricher([
        new Response(503, [], 'unavailable'),   // EPSS down
        kevResponse(['CVE-2030-2']),            // KEV still answers
    ], $history);

    $vuln = new VulnerabilityData(vulnId: 'CVE-2030-2', source: 'nvd');
    $enriched = $enricher->apply([[$vuln]]);

    expect($enriched[0][0]->epssScore)->toBeNull()
        ->and($enriched[0][0]->isKnownExploited)->toBeTrue()
        ->and($enricher->errors())->toHaveKey('epss');
});

it('skips both feeds entirely when no result has a CVE id', function () {
    $history = [];
    $enricher = makeEnricher([], $history);

    $enricher->apply([[new VulnerabilityData(vulnId: 'GHSA-only-no-cve', source: 'osv')]]);

    expect($history)->toHaveCount(0);
});

it('enriches through the VulnSearch pipeline and surfaces feed failures via errors()', function () {
    $history = [];
    $enricher = makeEnricher([
        epssResponse([['cve' => 'CVE-2030-3', 'epss' => '0.02', 'percentile' => '0.5']]),
        kevResponse([]),
    ], $history);

    $search = (new VulnSearch([
        fakeSource('osv', ['lodash' => [new VulnerabilityData(vulnId: 'CVE-2030-3', source: 'osv')]]),
    ]))->withEnricher($enricher);

    $result = $search->search(new PackageData(name: 'lodash', version: '1.0', ecosystem: 'npm'))[0];

    expect($result->epssScore)->toBe(0.02)
        ->and($result->isKnownExploited)->toBeFalse()
        ->and($search->errors())->toBe([]);
});

it('classifies threat-signal changes: KEV listing and the 0.1 EPSS crossing are major', function () {
    $before = new VulnerabilityData(vulnId: 'CVE-2030-4', source: 'osv', epssScore: 0.03);

    $listed = new VulnerabilityData(vulnId: 'CVE-2030-4', source: 'osv', epssScore: 0.03, isKnownExploited: true);
    expect($listed->changesSince($before)->has(ChangeType::KnownExploited))->toBeTrue()
        ->and($listed->changesSince($before)->impact())->toBe(ChangeImpact::Major);

    $spiked = new VulnerabilityData(vulnId: 'CVE-2030-4', source: 'osv', epssScore: 0.4);
    expect($spiked->changesSince($before)->has(ChangeType::ExploitationLikely))->toBeTrue()
        ->and($spiked->changesSince($before)->impact())->toBe(ChangeImpact::Major);

    $drifted = new VulnerabilityData(vulnId: 'CVE-2030-4', source: 'osv', epssScore: 0.05);
    expect($drifted->changesSince($before)->has(ChangeType::EpssChanged))->toBeTrue()
        ->and($drifted->changesSince($before)->impact())->toBe(ChangeImpact::Minor);
});
