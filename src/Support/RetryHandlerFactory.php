<?php

declare(strict_types=1);

namespace Gumslone\Vulns\Support;

use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * Guzzle handler stack with exponential-backoff retries for the transient
 * failures vulnerability APIs return under batch load (connection drops,
 * 429 rate limiting, 5xx). Honours Retry-After when the server sends one.
 *
 * Two kinds of failure, two paces: a throttle status ("slow down") may be
 * given its own, longer back-off than a dropped connection or a 5xx, which
 * usually clears within seconds.
 *
 * All source requests are idempotent reads, so retrying POSTs (OSV
 * querybatch, GitHub GraphQL) is safe.
 */
final class RetryHandlerFactory
{
    private const MAX_DELAY_MS = 10_000;

    /**
     * @param  int[]  $throttleStatuses  4xx codes that mean "slow down" for this API
     *                                   (NVD answers a blown rate limit with 403, not 429)
     * @param  int|null  $maxDelayMs  cap on one back-off pause; null = 10 s
     * @param  int|null  $throttleDelayMs  first back-off after a throttle status; null = $baseDelayMs
     * @param  int|null  $throttleMaxDelayMs  cap on a throttle back-off; null = the larger of
     *                                        $maxDelayMs and twice $throttleDelayMs, or
     *                                        $maxDelayMs when $throttleDelayMs is unset
     * @param  int|null  $throttleMaxRetries  a throttle status is retried only while fewer than
     *                                        this many retries have been made; null = $maxRetries
     */
    public static function stack(int $maxRetries, int $baseDelayMs = 500, array $throttleStatuses = [429], ?int $maxDelayMs = null, ?int $throttleDelayMs = null, ?int $throttleMaxDelayMs = null, ?int $throttleMaxRetries = null): HandlerStack
    {
        $stack = HandlerStack::create();
        // Pushed after the defaults, so it runs inside http_errors and sees
        // the raw 4xx/5xx response before an exception is thrown.
        $stack->push(self::middleware($maxRetries, $baseDelayMs, $throttleStatuses, $maxDelayMs, $throttleDelayMs, $throttleMaxDelayMs, $throttleMaxRetries), 'retry');

        return $stack;
    }

    /**
     * @param  int[]  $throttleStatuses
     */
    public static function middleware(int $maxRetries, int $baseDelayMs = 500, array $throttleStatuses = [429], ?int $maxDelayMs = null, ?int $throttleDelayMs = null, ?int $throttleMaxDelayMs = null, ?int $throttleMaxRetries = null): callable
    {
        $throttleMaxRetries ??= $maxRetries;
        $maxDelayMs ??= self::MAX_DELAY_MS;
        $throttleMaxDelayMs ??= $throttleDelayMs !== null ? max($maxDelayMs, $throttleDelayMs * 2) : $maxDelayMs;
        $throttleDelayMs ??= $baseDelayMs;

        return Middleware::retry(
            function (int $retries, RequestInterface $request, ?ResponseInterface $response = null, ?\Throwable $exception = null) use ($maxRetries, $throttleStatuses, $throttleMaxRetries): bool {
                if ($retries >= $maxRetries) {
                    return false;
                }

                if ($exception instanceof ConnectException) {
                    return true;
                }

                $status = $response?->getStatusCode() ?? 0;
                // "Slow down" has its own, usually smaller, budget: a client
                // that is throttled again and again should give up sooner
                // than one riding out a flapping server.
                if (in_array($status, $throttleStatuses, true)) {
                    return $retries < $throttleMaxRetries;
                }

                return $status >= 500;
            },
            function (int $retries, ?ResponseInterface $response = null) use ($baseDelayMs, $maxDelayMs, $throttleStatuses, $throttleDelayMs, $throttleMaxDelayMs): int {
                // "Slow down" and "something broke" are paced separately: a
                // throttled client has to sit out the limit, a 5xx or a
                // dropped connection (no response) is worth a quick retry.
                $throttled = $response !== null && in_array($response->getStatusCode(), $throttleStatuses, true);
                [$base, $cap] = $throttled ? [$throttleDelayMs, $throttleMaxDelayMs] : [$baseDelayMs, $maxDelayMs];

                // Never negative: a "Retry-After: -5" would reach the HTTP
                // handler's usleep() and throw.
                $retryAfter = $response?->getHeaderLine('Retry-After');
                if (is_numeric($retryAfter)) {
                    return (int) max(0, min((int) $retryAfter * 1000, $cap));
                }

                return (int) max(0, min($base * (2 ** ($retries - 1)), $cap));
            },
        );
    }
}
