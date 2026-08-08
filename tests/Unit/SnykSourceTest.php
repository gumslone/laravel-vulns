<?php

use Gumslone\Vulns\Data\PackageData;
use Gumslone\Vulns\Sources\SnykSource;
use Gumslone\Vulns\Support\PurlBuilder;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;

function makeSnykSource(array $responses, array &$history, array $options = []): SnykSource
{
    $mock = new MockHandler($responses);
    $stack = HandlerStack::create($mock);
    $stack->push(Middleware::history($history));

    return new SnykSource(new PurlBuilder, new Client(['handler' => $stack]), $options + [
        'enabled' => true,
        'api_token' => 'test-token',
        'org_id' => 'org-1',
    ]);
}

function snykIssue(string $key): array
{
    return [
        'id' => $key,
        'attributes' => [
            'key' => $key,
            'title' => "Issue {$key}",
            'effective_severity_level' => 'high',
            'problems' => [['id' => $key, 'source' => 'SNYK']],
        ],
    ];
}

function snykPage(array $issues, ?string $next = null): Response
{
    $body = ['data' => $issues];
    if ($next !== null) {
        $body['links'] = ['next' => $next];
    }

    return new Response(200, [], json_encode($body));
}

it('follows JSON:API links.next until the issue list is exhausted', function () {
    $history = [];
    $source = makeSnykSource([
        snykPage([snykIssue('SNYK-JS-LODASH-1')], next: '/rest/orgs/org-1/packages/x/issues?version=2024-10-15&limit=100&starting_after=abc'),
        snykPage([snykIssue('SNYK-JS-LODASH-2')]),
    ], $history);

    $results = $source->queryBatch([
        new PackageData(name: 'lodash', version: '4.17.20', ecosystem: 'npm', purl: 'pkg:npm/lodash@4.17.20'),
    ]);

    expect(array_map(fn ($v) => $v->vulnId, $results[0]))->toBe(['SNYK-JS-LODASH-1', 'SNYK-JS-LODASH-2'])
        ->and($history)->toHaveCount(2);

    // Page 1 asks for the full page size; page 2 is the links.next URL verbatim.
    parse_str($history[0]['request']->getUri()->getQuery(), $firstQuery);
    parse_str($history[1]['request']->getUri()->getQuery(), $secondQuery);
    expect($firstQuery['limit'])->toBe('100')
        ->and($secondQuery['starting_after'])->toBe('abc');
});

it('stops at the pagination safety cap instead of chasing links.next forever', function () {
    $history = [];
    $loop = fn () => snykPage([snykIssue('SNYK-LOOP')], next: '/rest/orgs/org-1/packages/x/issues?starting_after=again');
    $source = makeSnykSource([$loop(), $loop(), $loop()], $history, ['max_pages' => 2]);

    $results = $source->queryBatch([
        new PackageData(name: 'lodash', version: '4.17.20', ecosystem: 'npm', purl: 'pkg:npm/lodash@4.17.20'),
    ]);

    expect($history)->toHaveCount(2)
        ->and($results[0])->toHaveCount(2);
});

it('throws when a pooled request is rejected so the outage is recorded, not read as clean', function () {
    $history = [];
    $source = makeSnykSource([
        new Response(500, [], '{"errors":[{"detail":"server error"}]}'),
    ], $history);

    $source->queryBatch([
        new PackageData(name: 'lodash', version: '4.17.20', ecosystem: 'npm', purl: 'pkg:npm/lodash@4.17.20'),
    ]);
})->throws(RuntimeException::class, '1 of 1 requests failed');
