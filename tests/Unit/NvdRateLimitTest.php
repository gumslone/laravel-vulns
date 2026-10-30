<?php

/*
 * NVD enforces a ROLLING window (5 requests / 30 s anonymous, 50 with a key)
 * and asks for six seconds between anonymous requests. The old pacer counted
 * per calendar window, so ten requests could land within seconds across a
 * boundary — NVD answers that with 403 / "too many connections", and
 * vulns:audit died on it.
 */

use Gumslone\Vulns\Sources\NvdSource;
use Gumslone\Vulns\Support\ArrayCache;
use Gumslone\Vulns\Support\CpeResolver;
use Gumslone\Vulns\Support\RetryHandlerFactory;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use Psr\SimpleCache\CacheInterface;

/** A fake clock the pacer's sleeps advance, so no test really waits. */
function nvdClock(): object
{
    return new class
    {
        public float $now = 1_000.0;

        /** @var float[] */
        public array $slept = [];

        public function options(): array
        {
            return [
                'clock' => fn (): float => $this->now,
                'sleep' => function (float $seconds): void {
                    $this->slept[] = round($seconds, 3);
                    $this->now += $seconds;
                },
            ];
        }
    };
}

/** Each test gets its own budget store (the process-wide fallback is shared by design). */
function pacedNvd(object $clock, int $responses, array $options = [], ?CacheInterface $cache = null): NvdSource
{
    $cache ??= new ArrayCache;
    $mock = new MockHandler(array_fill(0, $responses, new Response(200, [], json_encode([
        'vulnerabilities' => [['cve' => ['id' => 'CVE-2024-0001']]],
    ]))));

    return new NvdSource(new CpeResolver, null, new Client(['handler' => HandlerStack::create($mock)]), $options + $clock->options(), null, $cache);
}

it('spaces anonymous requests six seconds apart, as NVD asks', function () {
    $clock = nvdClock();
    $nvd = pacedNvd($clock, 6);

    foreach (range(1, 6) as $i) {
        $nvd->fetchById('CVE-2024-0001');
    }

    // Six seconds between each pair; by the sixth the first has just left
    // the 30 s window, so the spacing is all it waits for.
    expect($clock->slept)->toBe([6.0, 6.0, 6.0, 6.0, 6.0])
        ->and($clock->now)->toBe(1_030.0);
});

it('never exceeds the rolling-window budget, even with no spacing', function () {
    $clock = nvdClock();
    $nvd = pacedNvd($clock, 4, ['api_key' => 'k', 'rate_limit_max' => 3, 'min_interval' => 0]);

    foreach (range(1, 4) as $i) {
        $nvd->fetchById('CVE-2024-0001');
    }

    // Three go out at once; the fourth waits until the FIRST is 30 s old —
    // not until a calendar boundary that might be a second away.
    expect($clock->slept)->toBe([30.0]);
});

it('shares one budget between instances (and workers) through the cache', function () {
    $clock = nvdClock();
    $cache = new ArrayCache;
    $a = pacedNvd($clock, 1, [], $cache);
    $b = pacedNvd($clock, 1, [], $cache);

    $a->fetchById('CVE-2024-0001');
    $b->fetchById('CVE-2024-0001');

    expect($clock->slept)->toBe([6.0]);
});

it('retries a throttled 403 after a full window, and gives a hard 404 straight back', function () {
    $history = [];
    $mock = new MockHandler([new Response(403, [], 'Request forbidden'), new Response(200, [], '{"ok":true}')]);
    $stack = RetryHandlerFactory::stack(2, 100, [403, 429], 200);
    $stack->setHandler($mock);
    $stack->push(Middleware::history($history));
    $client = new Client(['handler' => $stack, 'http_errors' => false]);

    $started = microtime(true);
    expect($client->get('https://nvd.test/cves/2.0')->getStatusCode())->toBe(200)
        ->and($history)->toHaveCount(2)
        ->and(microtime(true) - $started)->toBeGreaterThan(0.09);

    $mock = new MockHandler([new Response(404, [], 'Invalid apiKey')]);
    $stack = RetryHandlerFactory::stack(2, 100, [403, 429], 200);
    $stack->setHandler($mock);
    expect((new Client(['handler' => $stack, 'http_errors' => false]))->get('https://nvd.test/x')->getStatusCode())->toBe(404);
});
