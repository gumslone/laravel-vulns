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
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Promise\Create;
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

/*
 * NVD fails in two ways. A 403 is a blown rate limit and has to be waited
 * out; a 5xx ("503 No server is available", in bursts of a few seconds) is
 * the service flapping. Waiting a full window on every 503 made a batch
 * spend half its run asleep.
 */

/**
 * The back-off (ms) NVD's retry stack asks for before each retry of a request
 * answered with the given statuses. A recording handler stands in for the
 * network, so nothing really waits.
 *
 * @param  array<int, int|string>  $answers  HTTP statuses, or 'drop' for a dropped connection
 * @return int[]
 */
function nvdBackoffs(array $answers, float $spacing = 0.6, ?float $retryDelay = null, int $retries = 3): array
{
    $delays = [];
    $stack = NvdSource::retryStack($retries, 30, $spacing, $retryDelay);
    $stack->setHandler(function ($request, array $options) use (&$answers, &$delays) {
        $delays[] = (int) ($options['delay'] ?? 0);
        $answer = array_shift($answers);

        return $answer === 'drop'
            ? Create::rejectionFor(new ConnectException('reset', $request))
            : Create::promiseFor(new Response((int) $answer));
    });

    try {
        (new Client(['handler' => $stack, 'http_errors' => false]))->get('https://nvd.test/cves/2.0');
    } catch (ConnectException) {
        // retries exhausted on a dropped connection
    }

    return array_slice($delays, 1); // the first attempt is not a retry
}

it('retries a 503 within seconds instead of sitting out a rate-limit window', function () {
    expect(nvdBackoffs([503, 503, 503, 200]))->toBe([2000, 4000, 8000]);
});

it('retries a dropped connection as quickly as a 503', function () {
    expect(nvdBackoffs(['drop', 'drop', 200]))->toBe([2000, 4000]);
});

it('still waits out a full window on a 403 or 429', function () {
    expect(nvdBackoffs([403, 429, 403, 200]))->toBe([30000, 60000, 60000]);
});

it('paces each failure by its own kind when they alternate', function () {
    // The second 503 is the third retry, so it is on the 8 s step — but still
    // nowhere near the 30 s a throttle costs.
    expect(nvdBackoffs([503, 403, 503, 200]))->toBe([2000, 60000, 8000]);
});

it('never retries sooner than the request spacing — a retry is a request too', function () {
    // Keyless NVD: six seconds between requests.
    expect(nvdBackoffs([503, 503, 503, 200], spacing: 6.0))->toBe([6000, 12000, 12000]);
});

it('honours a configured retry delay', function () {
    expect(nvdBackoffs([503, 503, 200], retryDelay: 0.5))->toBe([600, 1200])   // floored at the 0.6 s spacing
        ->and(nvdBackoffs([503, 503, 200], retryDelay: 5.0))->toBe([5000, 10000]);
});

it('gives up after the configured number of retries and hands back the 503', function () {
    expect(nvdBackoffs([503, 503, 503], retries: 2))->toBe([2000, 4000]);
});

it('leaves other callers of the retry factory on a single back-off', function () {
    // Without throttle delays every retryable failure uses the base delay, as before.
    $delays = [];
    $answers = [429, 503, 200];
    $stack = RetryHandlerFactory::stack(3, 500);
    $stack->setHandler(function ($request, array $options) use (&$answers, &$delays) {
        $delays[] = (int) ($options['delay'] ?? 0);

        return Create::promiseFor(new Response((int) array_shift($answers)));
    });
    (new Client(['handler' => $stack, 'http_errors' => false]))->get('https://api.test/x');

    expect(array_slice($delays, 1))->toBe([500, 1000]);
});
