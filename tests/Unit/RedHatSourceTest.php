<?php

use Gumslone\Vulns\Data\PackageData;
use Gumslone\Vulns\Sources\RedHatSource;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;

/**
 * Built through the handler config seam (not an injected Client) so the
 * source's own base_uri handling is what the history middleware records.
 */
function makeRedHatSource(array $responses, array &$history, array $options = []): RedHatSource
{
    $mock = new MockHandler($responses);
    $stack = HandlerStack::create($mock);
    $stack->push(Middleware::history($history));

    return new RedHatSource(null, ['handler' => $stack] + $options);
}

function redHatEntry(string $cve): array
{
    return [
        'CVE' => $cve,
        'severity' => 'important',
        'public_date' => '2024-02-01T00:00:00Z',
        'bugzilla_description' => "{$cve} kernel: out-of-bounds write",
        'cvss3_score' => '8.1',
        'cvss3_scoring_vector' => 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H',
        'CWE' => 'CWE-787',
        'resource_url' => "https://access.redhat.com/hydra/rest/securitydata/cve/{$cve}.json",
        'affected_packages' => ['kernel-0:5.14.0-362.el9'],
    ];
}

it('pools one cve.json request per distinct package name', function () {
    $history = [];
    $source = makeRedHatSource([
        new Response(200, [], '[]'),
        new Response(200, [], '[]'),
    ], $history);

    // Two openssl versions share one request; curl gets its own.
    $results = $source->queryBatch([
        new PackageData(name: 'openssl', version: '3.0.7', ecosystem: 'rpm'),
        new PackageData(name: 'openssl', version: '1.1.1k', ecosystem: 'rpm'),
        new PackageData(name: 'curl', version: '7.88.1', ecosystem: 'rpm'),
    ]);

    expect($history)->toHaveCount(2)
        ->and($results)->toHaveCount(3);

    $queried = array_map(function ($entry) {
        parse_str($entry['request']->getUri()->getQuery(), $query);

        return $query['package'];
    }, $history);
    sort($queried);

    expect($queried)->toBe(['curl', 'openssl'])
        ->and($history[0]['request']->getUri()->getPath())->toBe('/hydra/rest/securitydata/cve.json');
});

it('maps a cve.json entry to the normalised DTO', function () {
    $history = [];
    $source = makeRedHatSource([
        new Response(200, [], json_encode([redHatEntry('CVE-2024-1234')])),
    ], $history);

    $results = $source->queryBatch([
        new PackageData(name: 'kernel', version: '5.14.0', ecosystem: 'rpm'),
    ]);

    expect($results[0])->toHaveCount(1);

    $vuln = $results[0][0];
    expect($vuln->vulnId)->toBe('CVE-2024-1234')
        ->and($vuln->source)->toBe('redhat')
        ->and($vuln->severity)->toBe(Gumslone\Vulns\Severity::High) // Red Hat "important"
        ->and($vuln->cvssV3Score)->toBe(8.1)
        ->and($vuln->cvssV3Vector)->toBe('CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H')
        ->and($vuln->summary)->toBe('CVE-2024-1234 kernel: out-of-bounds write')
        ->and($vuln->cwes)->toBe(['CWE-787'])
        ->and($vuln->sourceUrl)->toBe('https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2024-1234.json')
        // NEVRA strings are evidence, not version ranges — they must ride in
        // extra so downstream range-matching stays undeterminable.
        ->and($vuln->affectedRanges)->toBe([])
        ->and($vuln->extra['affected_packages'])->toBe(['kernel-0:5.14.0-362.el9'])
        ->and($vuln->sourcePublishedAt?->format('Y-m-d'))->toBe('2024-02-01');
});

it('fetches a CVE detail document by id, uppercased and percent-encoded', function () {
    $history = [];
    $source = makeRedHatSource([
        new Response(200, [], json_encode([
            'name' => 'CVE-2024-1234',
            'threat_severity' => 'Moderate',
            'public_date' => '2024-02-01T00:00:00Z',
            'bugzilla' => ['description' => 'CVE-2024-1234 kernel: out-of-bounds write'],
            'cvss3' => [
                'cvss3_base_score' => '6.5',
                'cvss3_scoring_vector' => 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H',
            ],
        ])),
    ], $history);

    $vuln = $source->fetchById('cve-2024-1234');

    expect($history[0]['request']->getUri()->getPath())->toBe('/hydra/rest/securitydata/cve/CVE-2024-1234.json')
        ->and($vuln?->vulnId)->toBe('CVE-2024-1234')
        ->and($vuln->severity)->toBe(Gumslone\Vulns\Severity::Medium)
        ->and($vuln->cvssV3Score)->toBe(6.5)
        ->and($vuln->summary)->toBe('CVE-2024-1234 kernel: out-of-bounds write');
});

it('treats a 404 on fetchById as an unknown id, not a failure', function () {
    $history = [];
    $source = makeRedHatSource([
        new Response(404, [], '{"message":"Not Found"}'),
    ], $history);

    expect($source->fetchById('CVE-1999-0000'))->toBeNull();
});

it('throws when a pooled request is rejected so the outage is recorded, not read as clean', function () {
    $history = [];
    $source = makeRedHatSource([
        new Response(500, [], 'upstream down'),
    ], $history);

    $source->queryBatch([
        new PackageData(name: 'openssl', version: '3.0.7', ecosystem: 'rpm'),
    ]);
})->throws(RuntimeException::class, 'Red Hat: 1 of 1 requests failed');
