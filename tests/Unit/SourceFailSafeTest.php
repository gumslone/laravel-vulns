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

        public function log($level, string|Stringable $message, array $context = []): void
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

it('EUVD walks every page (size 100, page N, total) and warns only when the page cap cuts it short', function () {
    $page = fn (int $from, int $count, int $total) => new Response(200, [], json_encode([
        'items' => array_map(fn (int $i) => ['id' => "EUVD-2024-{$i}", 'description' => 'x'], range($from, $from + $count - 1)),
        'total' => $total,
    ]));

    $history = [];
    $source = new EuvdSource(new Client(['handler' => failSafeStack([$page(1, 100, 227), $page(101, 100, 227), $page(201, 27, 227)], $history)]));
    $results = $source->queryBatch([new PackageData(name: 'curl', version: '7.88.1', ecosystem: 'deb')]);

    $queries = array_map(function (array $h) {
        parse_str($h['request']->getUri()->getQuery(), $q);

        return $q;
    }, $history);
    expect($results[0])->toHaveCount(227)
        ->and($queries[0]['size'])->toBe('100')
        ->and($queries[0])->not->toHaveKey('page')
        ->and($queries[1]['page'])->toBe('1')
        ->and($queries[2]['page'])->toBe('2')
        ->and($source->warnings())->toBe([]);

    // Cut short by max_pages: results kept, but flagged against the package.
    $history = [];
    $capped = new EuvdSource(new Client(['handler' => failSafeStack([$page(1, 100, 227)], $history)]), ['max_pages' => 1]);
    $results = $capped->queryBatch(['pkg' => new PackageData(name: 'curl', version: '7.88.1', ecosystem: 'deb')]);
    expect($results['pkg'])->toHaveCount(100)
        ->and($capped->warnings()[0])->toContain('truncated at 100 of 227')
        ->and($capped->incompleteKeys())->toBe(['pkg']);
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
