<?php

use Gumslone\Vulns\Data\PackageData;
use Gumslone\Vulns\Sources\OssIndexSource;
use Gumslone\Vulns\Support\PurlBuilder;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;

/**
 * Built through the handler config seam (not an injected Client) so the
 * source's own base_uri and header construction — the auth header in
 * particular — is what the history middleware records.
 */
function makeOssIndexSource(array $responses, array &$history, array $options = []): OssIndexSource
{
    $mock = new MockHandler($responses);
    $stack = HandlerStack::create($mock);
    $stack->push(Middleware::history($history));

    return new OssIndexSource(new PurlBuilder, null, ['handler' => $stack] + $options);
}

function ossIndexReport(string $coordinate, array $vulnerabilities = []): array
{
    return [
        'coordinates' => $coordinate,
        'description' => 'A package',
        'reference' => 'https://ossindex.sonatype.org/component/'.$coordinate,
        'vulnerabilities' => $vulnerabilities,
    ];
}

it('chunks batches above 128 coordinates into multiple component-report requests', function () {
    $packages = [];
    foreach (range(1, 129) as $i) {
        $packages[] = new PackageData(name: "pkg-{$i}", version: '1.0.0', ecosystem: 'npm');
    }

    $history = [];
    $source = makeOssIndexSource([
        new Response(200, [], '[]'),
        new Response(200, [], '[]'),
    ], $history);

    $results = $source->queryBatch($packages);

    expect($history)->toHaveCount(2)
        ->and($results)->toHaveCount(129);

    $firstBody = json_decode((string) $history[0]['request']->getBody(), true);
    $secondBody = json_decode((string) $history[1]['request']->getBody(), true);
    expect($history[0]['request']->getMethod())->toBe('POST')
        ->and($history[0]['request']->getUri()->getPath())->toBe('/api/v3/component-report')
        ->and($firstBody['coordinates'])->toHaveCount(128)
        ->and($secondBody['coordinates'])->toHaveCount(1);
});

it('maps a report vulnerability with a CVE and a CVSS:3.1 vector', function () {
    $history = [];
    $source = makeOssIndexSource([
        new Response(200, [], json_encode([
            ossIndexReport('pkg:npm/lodash@4.17.20', [[
                'id' => '39d74cc8-457a-4e57-89ef-a258420138c5',
                'displayName' => 'CVE-2021-23337',
                'title' => '[CVE-2021-23337] Command Injection in lodash',
                'description' => 'lodash versions prior to 4.17.21 are vulnerable.',
                'cvssScore' => 9.8,
                'cvssVector' => 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                'cve' => 'CVE-2021-23337',
                'reference' => 'https://ossindex.sonatype.org/vulnerability/CVE-2021-23337',
                'externalReferences' => ['https://nvd.nist.gov/vuln/detail/CVE-2021-23337'],
            ]]),
        ])),
    ], $history);

    $results = $source->queryBatch([
        new PackageData(name: 'lodash', version: '4.17.20', ecosystem: 'npm', purl: 'pkg:npm/lodash@4.17.20'),
    ]);

    expect($results[0])->toHaveCount(1);

    $vuln = $results[0][0];
    expect($vuln->vulnId)->toBe('CVE-2021-23337')
        ->and($vuln->source)->toBe('oss_index')
        ->and($vuln->severity)->toBe(Gumslone\Vulns\Severity::Critical)
        ->and($vuln->cvssV3Score)->toBe(9.8)
        ->and($vuln->cvssV3Vector)->toBe('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')
        ->and($vuln->summary)->toBe('[CVE-2021-23337] Command Injection in lodash')
        ->and($vuln->sourceUrl)->toBe('https://ossindex.sonatype.org/vulnerability/CVE-2021-23337')
        ->and(array_column($vuln->references, 'url'))->toBe([
            'https://ossindex.sonatype.org/vulnerability/CVE-2021-23337',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-23337',
        ])
        ->and($vuln->extra['oss_index_id'])->toBe('39d74cc8-457a-4e57-89ef-a258420138c5')
        ->and($vuln->rawDataChecksum)->not->toBeNull();
});

it('skips versionless packages without issuing a request for them', function () {
    $history = [];
    $source = makeOssIndexSource([
        new Response(200, [], json_encode([ossIndexReport('pkg:npm/lodash@4.17.20')])),
    ], $history);

    $results = $source->queryBatch([
        'no-version' => new PackageData(name: 'left-pad', version: null, ecosystem: 'npm'),
        'versioned' => new PackageData(name: 'lodash', version: '4.17.20', ecosystem: 'npm', purl: 'pkg:npm/lodash@4.17.20'),
    ]);

    // One request, carrying only the versioned coordinate; the versionless
    // package still resolves to an (empty) entry in the result.
    expect($history)->toHaveCount(1)
        ->and(json_decode((string) $history[0]['request']->getBody(), true)['coordinates'])->toBe(['pkg:npm/lodash@4.17.20'])
        ->and($results['no-version'])->toBe([])
        ->and($results['versioned'])->toBe([]);
});

it('throws when a component-report request is rejected so the outage is recorded, not read as clean', function () {
    $history = [];
    $source = makeOssIndexSource([
        new Response(500, [], '{"error":"boom"}'),
    ], $history);

    $source->queryBatch([
        new PackageData(name: 'lodash', version: '4.17.20', ecosystem: 'npm', purl: 'pkg:npm/lodash@4.17.20'),
    ]);
})->throws(RuntimeException::class, 'OSS Index: 1 of 1 requests failed');

it('sends basic auth only when both username and api_token are configured', function () {
    $package = new PackageData(name: 'lodash', version: '4.17.20', ecosystem: 'npm', purl: 'pkg:npm/lodash@4.17.20');

    $history = [];
    $source = makeOssIndexSource([new Response(200, [], '[]')], $history, [
        'username' => 'oleg@example.com',
        'api_token' => 'secret-token',
    ]);
    $source->queryBatch([$package]);

    expect($history[0]['request']->getHeaderLine('Authorization'))
        ->toBe('Basic '.base64_encode('oleg@example.com:secret-token'));

    // Half-configured credentials would only earn a 401 — no header at all.
    $history = [];
    $source = makeOssIndexSource([new Response(200, [], '[]')], $history, [
        'username' => 'oleg@example.com',
    ]);
    $source->queryBatch([$package]);

    expect($history[0]['request']->hasHeader('Authorization'))->toBeFalse();
});
