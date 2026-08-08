<?php

use Gumslone\Vulns\Data\PackageData;
use Gumslone\Vulns\Severity;
use Gumslone\Vulns\Sources\ShodanCvedbSource;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;

function makeShodanCvedbSource(array $responses, array &$history, array $options = []): ShodanCvedbSource
{
    $mock = new MockHandler($responses);
    $stack = HandlerStack::create($mock);
    $stack->push(Middleware::history($history));

    return new ShodanCvedbSource(new Client(['handler' => $stack]), $options);
}

function shodanCvedbRecord(): array
{
    return [
        'cve_id' => 'CVE-2024-3094',
        'summary' => 'Malicious code was discovered in the upstream tarballs of xz.',
        'cvss_version' => 3,
        'cvss' => 10.0,
        'cvss_v2' => 7.5,
        'cvss_v3' => 10.0,
        'epss' => 0.97,
        'ranked_epss' => 0.999,
        'kev' => true,
        'propose_action' => 'Upgrade immediately.',
        'ransomware_campaign' => null,
        'references' => ['https://nvd.nist.gov/vuln/detail/CVE-2024-3094'],
        'published_time' => '2024-03-29T17:15:00',
        'cpes' => ['cpe:2.3:a:tukaani:xz:5.6.0:*:*:*:*:*:*:*'],
    ];
}

it('pools one product search per distinct package name and maps threat signals', function () {
    $history = [];
    $source = makeShodanCvedbSource([
        new Response(200, [], json_encode(['cves' => [shodanCvedbRecord()]])),
    ], $history);

    // Two versions of the same package must share a single product request
    $results = $source->queryBatch([
        'a' => new PackageData(name: 'xz', version: '5.6.0', ecosystem: 'generic'),
        'b' => new PackageData(name: 'xz', version: '5.6.1', ecosystem: 'generic'),
    ]);

    expect($history)->toHaveCount(1);

    $uri = $history[0]['request']->getUri();
    parse_str($uri->getQuery(), $query);
    expect($uri->getPath())->toBe('cves')
        ->and($query['product'])->toBe('xz')
        ->and($query['limit'])->toBe('50');

    $vuln = $results['a'][0];
    expect($vuln->vulnId)->toBe('CVE-2024-3094')
        ->and($vuln->source)->toBe('shodan_cvedb')
        ->and($vuln->severity)->toBe(Severity::Critical)
        ->and($vuln->cvssV3Score)->toBe(10.0)
        ->and($vuln->cvssV2Score)->toBe(7.5)
        ->and($vuln->epssScore)->toBe(0.97)
        ->and($vuln->epssPercentile)->toBe(0.999)
        ->and($vuln->isKnownExploited)->toBeTrue()
        // CVEDB has no version bounds — cpes stay evidence in extra, never ranges
        ->and($vuln->affectedRanges)->toBe([])
        ->and($vuln->extra['cpes'])->toBe(['cpe:2.3:a:tukaani:xz:5.6.0:*:*:*:*:*:*:*'])
        ->and($results['b'][0]->vulnId)->toBe('CVE-2024-3094');
});

it('fetches a single record by id, percent-encoding the id in the path', function () {
    $history = [];
    $source = makeShodanCvedbSource([
        new Response(200, [], json_encode(shodanCvedbRecord())),
    ], $history);

    $vuln = $source->fetchById('CVE-2024/3094');

    expect($history[0]['request']->getUri()->getPath())->toBe('cve/CVE-2024%2F3094')
        ->and($vuln->summary)->toContain('xz')
        ->and($vuln->isKnownExploited)->toBeTrue()
        ->and($vuln->sourcePublishedAt->format('Y-m-d'))->toBe('2024-03-29')
        ->and($vuln->sourceUrl)->toBe('https://cvedb.shodan.io/cve/CVE-2024-3094')
        ->and($vuln->references)->toBe([['type' => null, 'url' => 'https://nvd.nist.gov/vuln/detail/CVE-2024-3094']]);
});

it('treats a 404 on fetchById as an unknown id, not an outage', function () {
    $history = [];
    $source = makeShodanCvedbSource([new Response(404, [], '{"detail":"Not Found"}')], $history);

    expect($source->fetchById('CVE-1999-0000'))->toBeNull();
});

it('throws when fetchById hits a non-404 transport failure', function () {
    $history = [];
    $source = makeShodanCvedbSource([new Response(500, [], 'upstream down')], $history);

    $source->fetchById('CVE-2024-3094');
})->throws(RuntimeException::class, 'Shodan CVEDB');

it('throws when a pooled request is rejected so the outage is recorded, not read as clean', function () {
    $history = [];
    $source = makeShodanCvedbSource([new Response(500, [], 'upstream down')], $history);

    $source->queryBatch([new PackageData(name: 'xz', version: '5.6.0', ecosystem: 'generic')]);
})->throws(RuntimeException::class, '1 of 1 requests failed');
