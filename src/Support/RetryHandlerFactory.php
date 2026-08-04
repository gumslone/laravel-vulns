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
 * All source requests are idempotent reads, so retrying POSTs (OSV
 * querybatch, GitHub GraphQL) is safe.
 */
final class RetryHandlerFactory
{
    private const MAX_DELAY_MS = 10_000;

    public static function stack(int $maxRetries, int $baseDelayMs = 500): HandlerStack
    {
        $stack = HandlerStack::create();
        // Pushed after the defaults, so it runs inside http_errors and sees
        // the raw 4xx/5xx response before an exception is thrown.
        $stack->push(self::middleware($maxRetries, $baseDelayMs), 'retry');

        return $stack;
    }

    public static function middleware(int $maxRetries, int $baseDelayMs = 500): callable
    {
        return Middleware::retry(
            function (int $retries, RequestInterface $request, ?ResponseInterface $response = null, ?\Throwable $exception = null) use ($maxRetries): bool {
                if ($retries >= $maxRetries) {
                    return false;
                }

                if ($exception instanceof ConnectException) {
                    return true;
                }

                $status = $response?->getStatusCode() ?? 0;

                return $status === 429 || $status >= 500;
            },
            function (int $retries, ?ResponseInterface $response = null) use ($baseDelayMs): int {
                $retryAfter = $response?->getHeaderLine('Retry-After');
                if (is_numeric($retryAfter)) {
                    return (int) min((int) $retryAfter * 1000, self::MAX_DELAY_MS);
                }

                return (int) min($baseDelayMs * (2 ** ($retries - 1)), self::MAX_DELAY_MS);
            },
        );
    }
}
