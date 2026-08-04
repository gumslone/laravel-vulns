<?php

use Gumslone\Vulns\Data\PackageData;
use Gumslone\Vulns\Sources\GitHubAdvisorySource;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;

function makeGitHubSource(array $responses, array &$history): GitHubAdvisorySource
{

    $mock = new MockHandler($responses);
    $stack = HandlerStack::create($mock);
    $stack->push(Middleware::history($history));

    return new GitHubAdvisorySource(new Client(['handler' => $stack]), ['token' => 'test-token']);
}

function ghAdvisoryPage(array $ghsaIds, bool $hasNextPage = false, ?string $endCursor = null): Response
{
    $nodes = array_map(fn (string $ghsaId) => [
        'vulnerableVersionRange' => '< 2.0.0',
        'firstPatchedVersion' => ['identifier' => '2.0.0'],
        'advisory' => [
            'ghsaId' => $ghsaId,
            'summary' => "Advisory {$ghsaId}",
            'description' => 'Details',
            'severity' => 'HIGH',
            'publishedAt' => '2024-01-01T00:00:00Z',
            'updatedAt' => '2024-01-02T00:00:00Z',
            'permalink' => "https://github.com/advisories/{$ghsaId}",
            'identifiers' => [['type' => 'GHSA', 'value' => $ghsaId]],
            'references' => [],
            'cwes' => ['nodes' => []],
            'cvss' => ['score' => 7.5, 'vectorString' => 'CVSS:3.1/AV:N'],
        ],
    ], $ghsaIds);

    return new Response(200, [], json_encode(['data' => ['securityVulnerabilities' => [
        'pageInfo' => ['hasNextPage' => $hasNextPage, 'endCursor' => $endCursor],
        'nodes' => $nodes,
    ]]]));
}

it('queries packages concurrently and keys results by package index', function () {
    $history = [];
    $source = makeGitHubSource([
        ghAdvisoryPage(['GHSA-aaaa']),
        ghAdvisoryPage([]),
        ghAdvisoryPage(['GHSA-bbbb', 'GHSA-cccc']),
    ], $history);

    $results = $source->queryBatch([
        new PackageData(name: 'left-pad', version: '1.3.0', ecosystem: 'npm'),
        new PackageData(name: 'lodash', version: '4.17.21', ecosystem: 'npm'),
        new PackageData(name: 'symfony/http-kernel', version: '5.4.0', ecosystem: 'composer'),
    ]);

    expect($results)->toHaveKeys([0, 1, 2])
        ->and(array_map(fn ($v) => $v->extra['ghsa_id'], $results[0]))->toBe(['GHSA-aaaa'])
        ->and($results[1])->toBe([])
        ->and(array_map(fn ($v) => $v->extra['ghsa_id'], $results[2]))->toBe(['GHSA-bbbb', 'GHSA-cccc']);

    expect($history)->toHaveCount(3);

    // Requests are dispatched in package order with the right variables
    $firstBody = json_decode((string) $history[0]['request']->getBody(), true);
    $thirdBody = json_decode((string) $history[2]['request']->getBody(), true);
    expect($firstBody['variables'])->toMatchArray(['ecosystem' => 'NPM', 'package' => 'left-pad', 'cursor' => null])
        ->and($thirdBody['variables'])->toMatchArray(['ecosystem' => 'COMPOSER', 'package' => 'symfony/http-kernel']);
});

it('follows pagination cursors in subsequent rounds without losing attribution', function () {
    $history = [];
    $source = makeGitHubSource([
        // round 1: page 1 for each package, in order
        ghAdvisoryPage(['GHSA-aaaa'], hasNextPage: true, endCursor: 'CURSOR-1'),
        ghAdvisoryPage(['GHSA-dddd']),
        // round 2: only package 0 has a next page
        ghAdvisoryPage(['GHSA-bbbb']),
    ], $history);

    $results = $source->queryBatch([
        new PackageData(name: 'left-pad', version: '1.3.0', ecosystem: 'npm'),
        new PackageData(name: 'lodash', version: '4.17.21', ecosystem: 'npm'),
    ]);

    expect(array_map(fn ($v) => $v->extra['ghsa_id'], $results[0]))->toBe(['GHSA-aaaa', 'GHSA-bbbb'])
        ->and(array_map(fn ($v) => $v->extra['ghsa_id'], $results[1]))->toBe(['GHSA-dddd']);

    expect($history)->toHaveCount(3);
    $pageTwoBody = json_decode((string) $history[2]['request']->getBody(), true);
    expect($pageTwoBody['variables'])->toMatchArray(['package' => 'left-pad', 'cursor' => 'CURSOR-1']);
});

it('answers single-package queries through the batch path', function () {
    $history = [];
    $source = makeGitHubSource([
        ghAdvisoryPage(['GHSA-aaaa'], hasNextPage: true, endCursor: 'CURSOR-1'),
        ghAdvisoryPage(['GHSA-bbbb']),
    ], $history);

    $vulns = $source->queryPackage(new PackageData(name: 'left-pad', version: '1.3.0', ecosystem: 'npm'));

    expect(array_map(fn ($v) => $v->extra['ghsa_id'], $vulns))->toBe(['GHSA-aaaa', 'GHSA-bbbb']);
    expect($history)->toHaveCount(2);
});

it('returns empty results without any request for unsupported ecosystems', function () {
    $history = [];
    $source = makeGitHubSource([
        ghAdvisoryPage(['GHSA-aaaa']),
    ], $history);

    $results = $source->queryBatch([
        new PackageData(name: 'some-conan-lib', version: '1.0.0', ecosystem: 'conan'),
        new PackageData(name: 'left-pad', version: '1.3.0', ecosystem: 'npm'),
    ]);

    expect($results[0])->toBe([])
        ->and(array_map(fn ($v) => $v->extra['ghsa_id'], $results[1]))->toBe(['GHSA-aaaa']);

    expect($history)->toHaveCount(1); // only the npm package was queried
});

it('finds repository-level advisories for github-ecosystem packages via REST', function () {
    $history = [];
    $source = makeGithubSource([
        new Response(200, [], json_encode([[
            'ghsa_id' => 'GHSA-c2wp-qw9x-94g7',
            'state' => 'published',
            'summary' => 'Unauthenticated remote command execution in GumCP',
            'description' => 'RCE details…',
            'severity' => 'critical',
            'published_at' => '2026-07-01T00:00:00Z',
            'updated_at' => '2026-07-02T00:00:00Z',
            'html_url' => 'https://github.com/gumslone/GumCP/security/advisories/GHSA-c2wp-qw9x-94g7',
            'identifiers' => [['type' => 'GHSA', 'value' => 'GHSA-c2wp-qw9x-94g7']],
            'cwes' => [['cwe_id' => 'CWE-78']],
            'cvss' => ['score' => 9.8, 'vector_string' => 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'],
            'vulnerabilities' => [[
                'package' => ['ecosystem' => '', 'name' => 'gumslone/GumCP'],
                'vulnerable_version_range' => '< 2.5.2',
                'patched_versions' => '2.5.2',
            ]],
        ], [
            'ghsa_id' => 'GHSA-draft-0000-0000',
            'state' => 'draft', // unpublished — must be skipped
            'summary' => 'wip',
        ]])),
    ], $history);

    $results = $source->queryBatch([
        0 => Gumslone\Vulns\Data\PackageData::fromArray(['name' => 'gumslone/GumCP', 'version' => '2.5.0', 'ecosystem' => 'github']),
    ]);

    expect($history[0]['request']->getUri()->getPath())->toBe('/repos/gumslone/GumCP/security-advisories')
        ->and($results[0])->toHaveCount(1);

    $vuln = $results[0][0];
    expect($vuln->vulnId)->toBe('GHSA-c2wp-qw9x-94g7')
        ->and($vuln->severity->value)->toBe('critical')
        ->and($vuln->cvssV3Score)->toBe(9.8)
        ->and($vuln->fixedVersions)->toBe(['2.5.2'])
        ->and($vuln->affectedRanges[0]['range'])->toBe('< 2.5.2')
        ->and($vuln->cwes)->toBe(['CWE-78']);
});

it('treats a repo-advisory request failure as empty, not fatal', function () {
    $history = [];
    $source = makeGithubSource([
        new Response(404, [], '{"message":"Not Found"}'),
    ], $history);

    // 4xx surfaces as a Guzzle exception with http_errors on — must yield [].
    $results = $source->queryBatch([
        0 => Gumslone\Vulns\Data\PackageData::fromArray(['name' => 'ghost/none', 'version' => null, 'ecosystem' => 'github']),
    ]);

    expect($results[0])->toBe([]);
});
