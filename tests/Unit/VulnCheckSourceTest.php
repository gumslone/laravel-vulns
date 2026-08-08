<?php

use Gumslone\Vulns\Data\PackageData;
use Gumslone\Vulns\Severity;
use Gumslone\Vulns\Sources\VulnCheckSource;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;

function makeVulnCheckSource(array $responses, array &$history, array $options = []): VulnCheckSource
{
    $mock = new MockHandler($responses);
    $stack = HandlerStack::create($mock);
    $stack->push(Middleware::history($history));

    return new VulnCheckSource(new Client(['handler' => $stack]), $options + [
        'enabled' => true,
        'api_token' => 'test-token',
    ]);
}

function vulnCheckNvd2Record(): array
{
    return [
        'id' => 'CVE-2021-44228',
        'descriptions' => [
            ['lang' => 'es', 'value' => 'Una vulnerabilidad.'],
            ['lang' => 'en', 'value' => 'Apache Log4j2 JNDI features do not protect against attacker controlled LDAP.'],
        ],
        'metrics' => [
            'cvssMetricV31' => [['cvssData' => ['baseScore' => 10.0, 'vectorString' => 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', 'baseSeverity' => 'CRITICAL']]],
            'cvssMetricV2' => [['cvssData' => ['baseScore' => 9.3, 'vectorString' => 'AV:N/AC:M/Au:N/C:C/I:C/A:C']]],
        ],
        'weaknesses' => [['description' => [['lang' => 'en', 'value' => 'CWE-502']]]],
        'references' => [['url' => 'https://logging.apache.org/log4j/2.x/security.html', 'tags' => ['Vendor Advisory']]],
        'configurations' => [[
            'nodes' => [[
                'cpeMatch' => [[
                    'vulnerable' => true,
                    'criteria' => 'cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*',
                    'versionStartIncluding' => '2.0.1',
                    'versionEndExcluding' => '2.15.0',
                ]],
            ]],
        ]],
        'published' => '2021-12-10T10:15:09.143',
        'lastModified' => '2023-11-07T04:21:03.117',
        'vulnStatus' => 'Analyzed',
    ];
}

it('is disabled unless both the toggle and an api token are configured', function () {
    expect((new VulnCheckSource(options: []))->isEnabled())->toBeFalse()
        ->and((new VulnCheckSource(options: ['enabled' => true]))->isEnabled())->toBeFalse()
        ->and((new VulnCheckSource(options: ['api_token' => 'tok']))->isEnabled())->toBeFalse()
        ->and((new VulnCheckSource(options: ['enabled' => true, 'api_token' => 'tok']))->isEnabled())->toBeTrue();
});

it('queries the nist-nvd2 index by CVE id with a Bearer token and maps the record', function () {
    $history = [];
    $source = makeVulnCheckSource([
        new Response(200, [], json_encode(['data' => [vulnCheckNvd2Record()]])),
    ], $history);

    $vuln = $source->fetchById('CVE-2021-44228');

    $request = $history[0]['request'];
    parse_str($request->getUri()->getQuery(), $query);
    expect($request->getUri()->getPath())->toBe('index/nist-nvd2')
        ->and($query['cve'])->toBe('CVE-2021-44228')
        ->and($request->getHeaderLine('Authorization'))->toBe('Bearer test-token');

    expect($vuln->vulnId)->toBe('CVE-2021-44228')
        ->and($vuln->source)->toBe('vulncheck')
        ->and($vuln->summary)->toContain('Log4j2')
        ->and($vuln->cvssV3Score)->toBe(10.0)
        ->and($vuln->cvssV3Vector)->toStartWith('CVSS:3.1/')
        ->and($vuln->cvssV2Score)->toBe(9.3)
        ->and($vuln->severity)->toBe(Severity::Critical)
        ->and($vuln->cwes)->toBe(['CWE-502'])
        ->and($vuln->affectedRanges)->toBe([['range' => '>= 2.0.1, < 2.15.0', 'source' => 'vulncheck']])
        ->and($vuln->sourcePublishedAt->format('Y-m-d'))->toBe('2021-12-10')
        ->and($vuln->extra['vuln_status'])->toBe('Analyzed');
});

it('maps a cvssMetricV40 metric into the v4 fields like NvdSource does', function () {
    $record = vulnCheckNvd2Record();
    $record['metrics']['cvssMetricV40'] = [['cvssData' => ['baseScore' => 9.2, 'vectorString' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N']]];

    $history = [];
    $source = makeVulnCheckSource([
        new Response(200, [], json_encode(['data' => [$record]])),
    ], $history);

    $vuln = $source->fetchById('CVE-2021-44228');

    expect($vuln->cvssV4Score)->toBe(9.2)
        ->and($vuln->cvssV4Vector)->toStartWith('CVSS:4.0/');
});

it('treats a 404 or an empty data array as an unknown id, not an outage', function () {
    $history = [];
    $source = makeVulnCheckSource([
        new Response(404, [], '{"errors":["not found"]}'),
        new Response(200, [], json_encode(['data' => []])),
    ], $history);

    expect($source->fetchById('CVE-1999-0000'))->toBeNull()
        ->and($source->fetchById('CVE-1999-0001'))->toBeNull();
});

it('throws when fetchById hits a non-404 transport failure', function () {
    $history = [];
    $source = makeVulnCheckSource([new Response(500, [], 'upstream down')], $history);

    $source->fetchById('CVE-2021-44228');
})->throws(RuntimeException::class, 'VulnCheck');

it('answers package queries with empty results without making any HTTP request', function () {
    $history = [];
    // No queued responses: any request would blow up the MockHandler
    $source = makeVulnCheckSource([], $history);

    $results = $source->queryBatch([
        0 => new PackageData(name: 'log4j-core', version: '2.14.1', ecosystem: 'maven'),
    ]);

    expect($results)->toBe([0 => []])
        ->and($history)->toBeEmpty();
});
