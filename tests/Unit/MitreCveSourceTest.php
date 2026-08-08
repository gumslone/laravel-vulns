<?php

use Gumslone\Vulns\Data\PackageData;
use Gumslone\Vulns\Severity;
use Gumslone\Vulns\Sources\MitreCveSource;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;

function makeMitreCveSource(array $responses, array &$history, array $options = []): MitreCveSource
{
    $mock = new MockHandler($responses);
    $stack = HandlerStack::create($mock);
    $stack->push(Middleware::history($history));

    return new MitreCveSource(new Client(['handler' => $stack]), $options);
}

function mitreCveRecord(array $cnaOverrides = [], array $adp = []): array
{
    return [
        'cveMetadata' => [
            'cveId' => 'CVE-2024-12345',
            'state' => 'PUBLISHED',
            'datePublished' => '2024-06-01T10:00:00.000Z',
            'dateUpdated' => '2024-06-15T12:00:00.000Z',
        ],
        'containers' => [
            'cna' => $cnaOverrides + [
                'descriptions' => [
                    ['lang' => 'de', 'value' => 'Ein Fehler.'],
                    ['lang' => 'en', 'value' => 'A flaw allows remote code execution.'],
                ],
                'affected' => [
                    ['vendor' => 'acme', 'product' => 'widget', 'versions' => [['version' => '1.0', 'status' => 'affected']]],
                ],
                'references' => [['url' => 'https://example.com/advisory', 'tags' => ['vendor-advisory']]],
                'problemTypes' => [['descriptions' => [['lang' => 'en', 'cweId' => 'CWE-787', 'description' => 'Out-of-bounds Write']]]],
            ],
            'adp' => $adp,
        ],
    ];
}

it('maps a v5 record with a CNA cvssV4_0 metric to the v4 fields and severity', function () {
    $history = [];
    $source = makeMitreCveSource([
        new Response(200, [], json_encode(mitreCveRecord([
            'metrics' => [['cvssV4_0' => ['baseScore' => 9.3, 'vectorString' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N']]],
        ]))),
    ], $history);

    $vuln = $source->fetchById('CVE-2024-12345');

    expect($history[0]['request']->getUri()->getPath())->toBe('cve/CVE-2024-12345')
        ->and($vuln->vulnId)->toBe('CVE-2024-12345')
        ->and($vuln->source)->toBe('mitre')
        ->and($vuln->summary)->toBe('A flaw allows remote code execution.')
        ->and($vuln->cvssV4Score)->toBe(9.3)
        ->and($vuln->cvssV4Vector)->toStartWith('CVSS:4.0/')
        ->and($vuln->severity)->toBe(Severity::Critical)
        ->and($vuln->cwes)->toBe(['CWE-787'])
        ->and($vuln->references)->toBe([['type' => 'vendor-advisory', 'url' => 'https://example.com/advisory']])
        ->and($vuln->sourcePublishedAt->format('Y-m-d'))->toBe('2024-06-01')
        ->and($vuln->sourceModifiedAt->format('Y-m-d'))->toBe('2024-06-15')
        ->and($vuln->sourceUrl)->toBe('https://www.cve.org/CVERecord?id=CVE-2024-12345')
        ->and($vuln->extra['state'])->toBe('PUBLISHED')
        // Raw CNA affects stay evidence in extra, never affectedRanges
        ->and($vuln->extra['affected'][0]['product'])->toBe('widget')
        ->and($vuln->affectedRanges)->toBe([]);
});

it('falls back to ADP metrics when the CNA container carries none', function () {
    $history = [];
    $source = makeMitreCveSource([
        new Response(200, [], json_encode(mitreCveRecord([], [[
            'title' => 'NVD enrichment',
            'metrics' => [['cvssV3_1' => ['baseScore' => 7.5, 'vectorString' => 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N']]],
        ]]))),
    ], $history);

    $vuln = $source->fetchById('CVE-2024-12345');

    expect($vuln->cvssV3Score)->toBe(7.5)
        ->and($vuln->cvssV3Vector)->toStartWith('CVSS:3.1/')
        ->and($vuln->severity)->toBe(Severity::High);
});

it('treats a 404 as an unpublished/unknown id, not an outage', function () {
    $history = [];
    $source = makeMitreCveSource([new Response(404, [], '{"error":"CVE_RECORD_DNE"}')], $history);

    expect($source->fetchById('CVE-1999-99999'))->toBeNull();
});

it('answers package queries with empty results without making any HTTP request', function () {
    $history = [];
    // No queued responses: any request would blow up the MockHandler
    $source = makeMitreCveSource([], $history);

    $results = $source->queryBatch([
        'a' => new PackageData(name: 'lodash', version: '4.17.20', ecosystem: 'npm'),
        'b' => new PackageData(name: 'left-pad', version: '1.3.0', ecosystem: 'npm'),
    ]);

    expect($results)->toBe(['a' => [], 'b' => []])
        ->and($history)->toBeEmpty();
});
