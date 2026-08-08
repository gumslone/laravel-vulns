<?php

use Gumslone\Vulns\Data\PackageData;
use Gumslone\Vulns\Sources\CveSearchSource;
use Gumslone\Vulns\Sources\EuvdSource;
use Gumslone\Vulns\Sources\GitHubAdvisorySource;
use Gumslone\Vulns\Support\CpeResolver;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use Psr\Log\AbstractLogger;

function failSafeStack(array $responses, array &$history): HandlerStack
{
    $mock = new MockHandler($responses);
    $stack = HandlerStack::create($mock);
    $stack->push(Middleware::history($history));

    return $stack;
}

function spyLogger(): AbstractLogger
{
    return new class extends AbstractLogger
    {
        public array $records = [];

        public function log($level, string|\Stringable $message, array $context = []): void
        {
            $this->records[] = ['level' => $level, 'message' => (string) $message, 'context' => $context];
        }
    };
}

// ---------------------------------------------------------------- EUVD

it('EUVD throws when a pooled request is rejected so the outage is recorded, not read as clean', function () {
    $history = [];
    $source = new EuvdSource(new Client(['handler' => failSafeStack([
        new Response(500, [], '{"error":"boom"}'),
    ], $history)]));

    $source->queryBatch([new PackageData(name: 'curl', version: '7.88.1', ecosystem: 'deb')]);
})->throws(RuntimeException::class, '1 of 1 requests failed');

it('EUVD requests the maximum page size and flags a full page as possible truncation', function () {
    $items = array_map(fn (int $i) => ['id' => "EUVD-2024-{$i}", 'description' => 'x'], range(1, 100));

    $history = [];
    $logger = spyLogger();
    $source = new EuvdSource(new Client(['handler' => failSafeStack([
        new Response(200, [], json_encode(['items' => $items])),
    ], $history)]), [], $logger);

    $results = $source->queryBatch([new PackageData(name: 'curl', version: '7.88.1', ecosystem: 'deb')]);

    parse_str($history[0]['request']->getUri()->getQuery(), $query);
    expect($query['size'])->toBe('100')
        ->and($results[0])->toHaveCount(100);

    $warnings = array_column($logger->records, 'message');
    expect(implode(' ', $warnings))->toContain('truncated');
});

// ---------------------------------------------------------- CVE-Search

it('CVE-Search throws when a pooled request is rejected so the outage is recorded, not read as clean', function () {
    $history = [];
    $source = new CveSearchSource(new CpeResolver, null, new Client(['handler' => failSafeStack([
        new Response(500, [], 'upstream down'),
    ], $history)]));

    $source->queryBatch([new PackageData(name: 'symfony/http-kernel', version: '5.4.0', ecosystem: 'composer')]);
})->throws(RuntimeException::class, '1 of 1 requests failed');

it('CVE-Search percent-encodes the vulnerability id in by-id lookups', function () {
    $history = [];
    $source = new CveSearchSource(new CpeResolver, null, new Client(['handler' => failSafeStack([
        new Response(200, [], json_encode(['id' => 'CVE-2024-0001'])),
    ], $history)]));

    $source->fetchById('CVE-2024/../evil');

    expect($history[0]['request']->getUri()->getPath())->toBe('cve/CVE-2024%2F..%2Fevil');
});

// -------------------------------------------------------------- GitHub

it('GitHub throws when a pooled GraphQL request is rejected so the outage is recorded, not read as clean', function () {
    $history = [];
    $source = new GitHubAdvisorySource(new Client(['handler' => failSafeStack([
        new Response(500, [], '{"message":"boom"}'),
    ], $history)]), ['token' => 'test-token']);

    $source->queryBatch([new PackageData(name: 'left-pad', version: '1.3.0', ecosystem: 'npm')]);
})->throws(RuntimeException::class, '1 of 1 requests failed');

it('GitHub repo-advisory lookups encode path segments and request full pages', function () {
    $history = [];
    $source = new GitHubAdvisorySource(new Client(['handler' => failSafeStack([
        new Response(200, [], '[]'),
    ], $history)]), ['token' => 'test-token']);

    $source->queryBatch([
        0 => PackageData::fromArray(['name' => 'bad guy/re po', 'version' => null, 'ecosystem' => 'github']),
    ]);

    $uri = $history[0]['request']->getUri();
    parse_str($uri->getQuery(), $query);
    expect($uri->getPath())->toBe('/repos/bad%20guy/re%20po/security-advisories')
        ->and($query['per_page'])->toBe('100');
});

it('GitHub repo-advisory lookups follow the Link header to further pages', function () {
    $advisory = fn (string $ghsaId) => [
        'ghsa_id' => $ghsaId,
        'state' => 'published',
        'summary' => "Advisory {$ghsaId}",
        'vulnerabilities' => [],
    ];

    $history = [];
    $source = new GitHubAdvisorySource(new Client(['handler' => failSafeStack([
        new Response(200, [
            'Link' => '</repos/gumslone/GumCP/security-advisories?per_page=100&page=2>; rel="next"',
        ], json_encode([$advisory('GHSA-1111-1111-1111')])),
        new Response(200, [], json_encode([$advisory('GHSA-2222-2222-2222')])),
    ], $history)]), ['token' => 'test-token']);

    $results = $source->queryBatch([
        0 => PackageData::fromArray(['name' => 'gumslone/GumCP', 'version' => null, 'ecosystem' => 'github']),
    ]);

    expect(array_map(fn ($v) => $v->extra['ghsa_id'], $results[0]))->toBe(['GHSA-1111-1111-1111', 'GHSA-2222-2222-2222'])
        ->and($history)->toHaveCount(2);

    parse_str($history[1]['request']->getUri()->getQuery(), $pageTwoQuery);
    expect($pageTwoQuery['page'])->toBe('2');
});
