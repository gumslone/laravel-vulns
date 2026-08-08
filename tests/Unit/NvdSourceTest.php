<?php

use Gumslone\Vulns\Data\PackageData;
use Gumslone\Vulns\Sources\NvdSource;
use Gumslone\Vulns\Support\CpeResolver;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;

function makeNvdSource(array $responses, array &$history, array $options = []): NvdSource
{
    $mock = new MockHandler($responses);
    $stack = HandlerStack::create($mock);
    $stack->push(Middleware::history($history));

    // rate_limit_max is raised so the throttle's per-process counter never
    // sleeps the suite when many NVD tests share one 30s window.
    return new NvdSource(new CpeResolver, null, new Client(['handler' => $stack]), $options + ['rate_limit_max' => 1000]);
}

function nvdPage(array $cveIds, int $total): Response
{
    return new Response(200, [], json_encode([
        'totalResults' => $total,
        'vulnerabilities' => array_map(fn (string $id) => ['cve' => ['id' => $id]], $cveIds),
    ]));
}

it('follows NVD 2.0 paging until totalResults is exhausted', function () {
    $history = [];
    $source = makeNvdSource([
        nvdPage(['CVE-2024-0001', 'CVE-2024-0002'], total: 3),
        nvdPage(['CVE-2024-0003'], total: 3),
    ], $history);

    $vulns = $source->queryPackage(new PackageData(name: 'symfony/http-kernel', version: '5.4.0', ecosystem: 'composer'));

    expect(array_map(fn ($v) => $v->vulnId, $vulns))->toBe(['CVE-2024-0001', 'CVE-2024-0002', 'CVE-2024-0003'])
        ->and($history)->toHaveCount(2);

    parse_str($history[0]['request']->getUri()->getQuery(), $firstQuery);
    parse_str($history[1]['request']->getUri()->getQuery(), $secondQuery);
    expect($firstQuery['startIndex'])->toBe('0')
        ->and($secondQuery['startIndex'])->toBe('2')
        ->and($secondQuery['virtualMatchString'])->toBe($firstQuery['virtualMatchString']);
});

it('stops at the pagination safety cap instead of walking a huge result forever', function () {
    $history = [];
    $source = makeNvdSource([
        nvdPage(['CVE-2024-0001'], total: 1000),
        nvdPage(['CVE-2024-0002'], total: 1000),
    ], $history, ['max_pages' => 2]);

    $vulns = $source->queryPackage(new PackageData(name: 'symfony/http-kernel', version: '5.4.0', ecosystem: 'composer'));

    expect($vulns)->toHaveCount(2)
        ->and($history)->toHaveCount(2); // capped — no third request
});

it('throws when the NVD request fails so the outage is recorded, not read as clean', function () {
    $history = [];
    $source = makeNvdSource([
        new RequestException('boom', new Request('GET', 'cves/2.0')),
    ], $history);

    $source->queryPackage(new PackageData(name: 'symfony/http-kernel', version: '5.4.0', ecosystem: 'composer'));
})->throws(RuntimeException::class, 'NVD query failed for symfony/http-kernel');
