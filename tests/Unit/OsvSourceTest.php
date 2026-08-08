<?php

use Gumslone\Vulns\Data\PackageData;
use Gumslone\Vulns\Sources\OsvSource;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;

function makeOsvSource(array $responses, array &$history): OsvSource
{
    $mock = new MockHandler($responses);
    $stack = HandlerStack::create($mock);
    $stack->push(Middleware::history($history));

    return new OsvSource(new Client(['handler' => $stack]), cache: new Gumslone\Vulns\Support\ArrayCache);
}

function osvVulnResponse(string $id, string $summary = 'A vulnerability'): Response
{
    return new Response(200, [], json_encode([
        'id' => $id,
        'summary' => $summary,
        'aliases' => [],
    ]));
}

it('queries OS packages (deb/apk) by PURL so OSV resolves the distro release', function () {
    $history = [];
    $source = makeOsvSource([
        new Response(200, [], json_encode(['vulns' => [['id' => 'CVE-2023-1', 'summary' => 'curl', 'aliases' => []]]])),
    ], $history);

    $result = $source->queryPackage(PackageData::fromArray([
        'name' => 'curl', 'version' => '7.88.1-10', 'ecosystem' => 'deb',
        'purl' => 'pkg:deb/debian/curl@7.88.1-10?arch=amd64&distro=debian-12',
    ]));

    $body = json_decode((string) $history[0]['request']->getBody(), true);

    expect($body)->toBe(['package' => ['purl' => 'pkg:deb/debian/curl@7.88.1-10?arch=amd64&distro=debian-12']])
        ->and($result)->toHaveCount(1);
});

it('still queries language packages by name + ecosystem + version', function () {
    $history = [];
    $source = makeOsvSource([
        new Response(200, [], json_encode(['vulns' => []])),
    ], $history);

    $source->queryPackage(PackageData::fromArray(['name' => 'lodash', 'version' => '4.17.20', 'ecosystem' => 'npm']));

    $body = json_decode((string) $history[0]['request']->getBody(), true);
    expect($body['package'])->toBe(['name' => 'lodash', 'ecosystem' => 'npm'])
        ->and($body['version'])->toBe('4.17.20');
});

it('keys querybatch results by package index and preserves attribution', function () {
    $history = [];
    $source = makeOsvSource([
        // querybatch: minimal {id, modified} records per query, in query order
        new Response(200, [], json_encode(['results' => [
            ['vulns' => [['id' => 'OSV-A', 'modified' => '2024-01-01T00:00:00Z'], ['id' => 'OSV-B', 'modified' => '2024-01-01T00:00:00Z']]],
            ['vulns' => []],
            ['vulns' => [['id' => 'OSV-A', 'modified' => '2024-01-01T00:00:00Z']]],
        ]])),
        // hydration of the two distinct ids
        osvVulnResponse('OSV-A'),
        osvVulnResponse('OSV-B'),
    ], $history);

    $packages = [
        new PackageData(name: 'symfony/http-kernel', version: '5.4.0', ecosystem: 'composer'),
        new PackageData(name: 'left-pad', version: '1.3.0', ecosystem: 'npm'),
        new PackageData(name: 'lodash', version: '4.17.20', ecosystem: 'npm'),
    ];

    $results = $source->queryBatch($packages);

    expect($results)->toHaveKeys([0, 1, 2])
        ->and(array_map(fn ($v) => $v->vulnId, $results[0]))->toBe(['OSV-A', 'OSV-B'])
        ->and($results[1])->toBe([])
        ->and(array_map(fn ($v) => $v->vulnId, $results[2]))->toBe(['OSV-A']);

    // 1 querybatch + 2 hydrations: OSV-A is shared but fetched only once
    expect($history)->toHaveCount(3);

    $batchBody = json_decode((string) $history[0]['request']->getBody(), true);
    expect($batchBody['queries'])->toHaveCount(3)
        ->and($batchBody['queries'][0]['package']['ecosystem'])->toBe('Packagist')
        ->and($batchBody['queries'][1]['package']['ecosystem'])->toBe('npm')
        ->and($batchBody['queries'][2]['version'])->toBe('4.17.20');
});

it('preserves array keys of the input packages', function () {
    $history = [];
    $source = makeOsvSource([
        new Response(200, [], json_encode(['results' => [
            ['vulns' => [['id' => 'OSV-A', 'modified' => '2024-01-01T00:00:00Z']]],
            ['vulns' => []],
        ]])),
        osvVulnResponse('OSV-A'),
    ], $history);

    $results = $source->queryBatch([
        42 => new PackageData(name: 'left-pad', version: '1.3.0', ecosystem: 'npm'),
        77 => new PackageData(name: 'lodash', version: '4.17.21', ecosystem: 'npm'),
    ]);

    expect($results)->toHaveKeys([42, 77])
        ->and($results[42][0]->vulnId)->toBe('OSV-A')
        ->and($results[77])->toBe([]);
});

it('derives severity and CVSS score from an OSV CVSS vector string', function () {
    $history = [];
    $source = makeOsvSource([
        new Response(200, [], json_encode(['results' => [
            ['vulns' => [['id' => 'OSV-CVSS', 'modified' => '2024-01-01T00:00:00Z']]],
        ]])),
        // Hydration with a real OSV severity node: score is a VECTOR string.
        new Response(200, [], json_encode([
            'id' => 'OSV-CVSS',
            'summary' => 'Critical bug',
            'aliases' => ['CVE-2099-9999'],
            'severity' => [
                ['type' => 'CVSS_V3', 'score' => 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'],
            ],
        ])),
    ], $history);

    $results = $source->queryBatch([
        new PackageData(name: 'left-pad', version: '1.3.0', ecosystem: 'npm'),
    ]);

    $vuln = $results[0][0];
    expect($vuln->severity)->toBe(Gumslone\Vulns\Severity::Critical)
        ->and((float) $vuln->cvssV3Score)->toBe(9.8);
});

it('scores a v4-only advisory from its CVSS:4.0 vector', function () {
    $history = [];
    $source = makeOsvSource([
        new Response(200, [], json_encode(['results' => [
            ['vulns' => [['id' => 'OSV-CVSS4', 'modified' => '2025-01-01T00:00:00Z']]],
        ]])),
        // Increasingly common: only a CVSS_V4 severity entry, vector-only.
        new Response(200, [], json_encode([
            'id' => 'OSV-CVSS4',
            'summary' => 'v4-scored bug',
            'severity' => [
                ['type' => 'CVSS_V4', 'score' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N'],
            ],
        ])),
    ], $history);

    $results = $source->queryBatch([
        new PackageData(name: 'left-pad', version: '1.3.0', ecosystem: 'npm'),
    ]);

    $vuln = $results[0][0];
    expect($vuln->cvssV4Score)->toBe(9.3)
        ->and($vuln->cvssV4Vector)->toContain('CVSS:4.0')
        ->and($vuln->cvssV3Score)->toBeNull()
        ->and($vuln->severity)->toBe(Gumslone\Vulns\Severity::Critical)
        ->and($vuln->effectiveCvssScore())->toBe(9.3);
});

it('throws when the batch request fails so the outage is recorded, not read as clean', function () {
    $history = [];
    $source = makeOsvSource([
        new RequestException('boom', new Request('POST', 'v1/querybatch')),
    ], $history);

    $source->queryBatch([
        new PackageData(name: 'left-pad', version: '1.3.0', ecosystem: 'npm'),
        new PackageData(name: 'lodash', version: '4.17.20', ecosystem: 'npm'),
    ]);
})->throws(RuntimeException::class, 'OSV batch query failed');

it('throws when the single-package query fails so the outage is recorded, not read as clean', function () {
    $history = [];
    $source = makeOsvSource([
        new RequestException('boom', new Request('POST', 'v1/query')),
    ], $history);

    $source->queryPackage(PackageData::fromArray([
        'name' => 'curl', 'version' => '7.88.1-10', 'ecosystem' => 'deb',
        'purl' => 'pkg:deb/debian/curl@7.88.1-10?distro=debian-12',
    ]));
})->throws(RuntimeException::class, 'OSV query failed for curl');

it('follows next_page_token on the single-package query path', function () {
    $history = [];
    $source = makeOsvSource([
        new Response(200, [], json_encode([
            'vulns' => [['id' => 'CVE-2023-1', 'summary' => 'page one', 'aliases' => []]],
            'next_page_token' => 'TOK',
        ])),
        new Response(200, [], json_encode([
            'vulns' => [['id' => 'CVE-2023-2', 'summary' => 'page two', 'aliases' => []]],
        ])),
    ], $history);

    $result = $source->queryPackage(PackageData::fromArray([
        'name' => 'curl', 'version' => '7.88.1-10', 'ecosystem' => 'deb',
        'purl' => 'pkg:deb/debian/curl@7.88.1-10?distro=debian-12',
    ]));

    expect(array_map(fn ($v) => $v->vulnId, $result))->toBe(['CVE-2023-1', 'CVE-2023-2'])
        ->and($history)->toHaveCount(2);

    $pageTwoBody = json_decode((string) $history[1]['request']->getBody(), true);
    expect($pageTwoBody['page_token'])->toBe('TOK');
});

it('resolves requests against a mirrored base_url without losing its path prefix', function () {
    $history = [];
    $mock = new MockHandler([new Response(200, [], json_encode(['results' => []]))]);
    $stack = HandlerStack::create($mock);
    $stack->push(Middleware::history($history));

    // No injected client: the source must build its own so the configured
    // base_url actually flows into base_uri (the 'handler' option is a seam).
    $source = new OsvSource(null, ['base_url' => 'https://mirror.internal/osv', 'handler' => $stack]);

    $source->queryBatch([new PackageData(name: 'lodash', version: '4.17.20', ecosystem: 'npm')]);

    expect((string) $history[0]['request']->getUri())->toBe('https://mirror.internal/osv/v1/querybatch');
});

it('tolerates a legacy /v1 suffix in the configured base_url', function () {
    $history = [];
    $mock = new MockHandler([new Response(200, [], json_encode(['results' => []]))]);
    $stack = HandlerStack::create($mock);
    $stack->push(Middleware::history($history));

    $source = new OsvSource(null, ['base_url' => 'https://api.osv.dev/v1', 'handler' => $stack]);

    $source->queryBatch([new PackageData(name: 'lodash', version: '4.17.20', ecosystem: 'npm')]);

    expect((string) $history[0]['request']->getUri())->toBe('https://api.osv.dev/v1/querybatch');
});

it('percent-encodes the vulnerability id in by-id lookups', function () {
    $history = [];
    $source = makeOsvSource([osvVulnResponse('WEIRD-1')], $history);

    $source->fetchById('WEIRD/1?x');

    expect($history[0]['request']->getUri()->getPath())->toBe('v1/vulns/WEIRD%2F1%3Fx');
});

it('follows querybatch pagination tokens per query', function () {
    $history = [];
    $source = makeOsvSource([
        // page 1: first query has more pages, second is complete
        new Response(200, [], json_encode(['results' => [
            ['vulns' => [['id' => 'OSV-A', 'modified' => '2024-01-01T00:00:00Z']], 'next_page_token' => 'TOK'],
            ['vulns' => [['id' => 'OSV-B', 'modified' => '2024-01-01T00:00:00Z']]],
        ]])),
        // page 2: only the first query is resent
        new Response(200, [], json_encode(['results' => [
            ['vulns' => [['id' => 'OSV-C', 'modified' => '2024-01-01T00:00:00Z']]],
        ]])),
        osvVulnResponse('OSV-A'),
        osvVulnResponse('OSV-B'),
        osvVulnResponse('OSV-C'),
    ], $history);

    $results = $source->queryBatch([
        new PackageData(name: 'left-pad', version: '1.3.0', ecosystem: 'npm'),
        new PackageData(name: 'lodash', version: '4.17.20', ecosystem: 'npm'),
    ]);

    expect(array_map(fn ($v) => $v->vulnId, $results[0]))->toBe(['OSV-A', 'OSV-C'])
        ->and(array_map(fn ($v) => $v->vulnId, $results[1]))->toBe(['OSV-B']);

    expect($history)->toHaveCount(5);
    $pageTwoBody = json_decode((string) $history[1]['request']->getBody(), true);
    expect($pageTwoBody['queries'])->toHaveCount(1)
        ->and($pageTwoBody['queries'][0]['package']['name'])->toBe('left-pad')
        ->and($pageTwoBody['queries'][0]['page_token'])->toBe('TOK');
});

it('serves unchanged vulnerabilities from cache on subsequent batches', function () {
    $batchResponse = fn () => new Response(200, [], json_encode(['results' => [
        ['vulns' => [['id' => 'OSV-A', 'modified' => '2024-01-01T00:00:00Z']]],
    ]]));

    $history = [];
    $source = makeOsvSource([
        $batchResponse(),
        osvVulnResponse('OSV-A'),
        $batchResponse(), // second batch: no hydration request expected
    ], $history);

    $packages = [new PackageData(name: 'left-pad', version: '1.3.0', ecosystem: 'npm')];

    $first = $source->queryBatch($packages);
    $second = $source->queryBatch($packages);

    expect($history)->toHaveCount(3)
        ->and($history[2]['request']->getUri()->getPath())->toContain('querybatch');
    expect(array_map(fn ($v) => $v->vulnId, $second[0]))->toBe(['OSV-A'])
        ->and($second[0][0]->summary)->toBe($first[0][0]->summary);
});

it('refetches a vulnerability when its modified stamp changes', function () {
    $batchResponse = fn (string $modified) => new Response(200, [], json_encode(['results' => [
        ['vulns' => [['id' => 'OSV-A', 'modified' => $modified]]],
    ]]));

    $history = [];
    $source = makeOsvSource([
        $batchResponse('2024-01-01T00:00:00Z'),
        osvVulnResponse('OSV-A', 'Original summary'),
        $batchResponse('2024-06-01T00:00:00Z'),
        osvVulnResponse('OSV-A', 'Updated summary'),
    ], $history);

    $packages = [new PackageData(name: 'left-pad', version: '1.3.0', ecosystem: 'npm')];

    $source->queryBatch($packages);
    $second = $source->queryBatch($packages);

    expect($history)->toHaveCount(4);
    expect($second[0][0]->summary)->toBe('Updated summary');
});

it('skips vulnerabilities whose hydration fails but keeps the rest', function () {
    $history = [];
    $source = makeOsvSource([
        new Response(200, [], json_encode(['results' => [
            ['vulns' => [['id' => 'OSV-A', 'modified' => '2024-01-01T00:00:00Z'], ['id' => 'OSV-B', 'modified' => '2024-01-01T00:00:00Z']]],
        ]])),
        new RequestException('boom', new Request('GET', '/v1/vulns/OSV-A')),
        osvVulnResponse('OSV-B'),
    ], $history);

    $results = $source->queryBatch([
        new PackageData(name: 'left-pad', version: '1.3.0', ecosystem: 'npm'),
    ]);

    expect(array_map(fn ($v) => $v->vulnId, $results[0]))->toBe(['OSV-B']);
});

it('queries commit-pinned packages (git submodules) by commit', function () {
    $history = [];
    $source = makeOsvSource([
        new Response(200, [], json_encode(['vulns' => [['id' => 'GHSA-x2fr-222x-x22x', 'summary' => 'Adminer SSRF', 'aliases' => []]]])),
    ], $history);

    $result = $source->queryPackage(PackageData::fromArray([
        'name' => 'vrana/adminer', 'version' => null, 'ecosystem' => 'github',
        'git_commit_hash' => 'aaaabbbbccccddddeeeeffff0000111122223333',
    ]));

    $body = json_decode((string) $history[0]['request']->getBody(), true);
    expect($body)->toBe(['commit' => 'aaaabbbbccccddddeeeeffff0000111122223333'])
        ->and($result)->toHaveCount(1);
});

it('prefers version coordinates over a commit when both are known', function () {
    $history = [];
    $source = makeOsvSource([new Response(200, [], json_encode(['vulns' => []]))], $history);

    $source->queryPackage(PackageData::fromArray([
        'name' => 'lodash', 'version' => '4.17.20', 'ecosystem' => 'npm',
        'git_commit_hash' => 'aaaabbbbccccddddeeeeffff0000111122223333',
    ]));

    $body = json_decode((string) $history[0]['request']->getBody(), true);
    expect($body['package'])->toBe(['name' => 'lodash', 'ecosystem' => 'npm'])
        ->and($body)->not->toHaveKey('commit');
});


it('skips unmapped-ecosystem packages instead of 400ing the whole querybatch', function () {
    $history = [];
    $source = makeOsvSource([
        new Response(200, [], json_encode(['results' => [['vulns' => []]]])),
    ], $history);

    $results = $source->queryBatch([
        'ok' => new PackageData(name: 'lodash', version: '4.17.20', ecosystem: 'npm'),
        // No commit, no registry ecosystem — OSV has no coordinate for this.
        'skip' => new PackageData(name: 'gumslone/GumCP', version: '2.7.0', ecosystem: 'github'),
    ]);

    $body = json_decode((string) $history[0]['request']->getBody(), true);
    expect($body['queries'])->toHaveCount(1)
        ->and($body['queries'][0]['package']['name'])->toBe('lodash')
        ->and($results['skip'])->toBe([]);
});

it('queries a VERSIONED unmapped-ecosystem package by commit when one is pinned', function () {
    $history = [];
    $source = makeOsvSource([new Response(200, [], json_encode(['results' => [['vulns' => []]]]))], $history);

    $source->queryBatch([
        0 => new PackageData(name: 'gumslone/GumCP', version: '2.7.0', ecosystem: 'github',
            gitCommitHash: 'aaaabbbbccccddddeeeeffff0000111122223333'),
    ]);

    $body = json_decode((string) $history[0]['request']->getBody(), true);
    expect($body['queries'][0])->toBe(['commit' => 'aaaabbbbccccddddeeeeffff0000111122223333']);
});
