<?php

declare(strict_types=1);

namespace Gumslone\Vulns\Sources;

use Gumslone\Vulns\Contracts\Source;
use Gumslone\Vulns\Data\PackageData;
use Gumslone\Vulns\Support\RetryHandlerFactory;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\RequestException;
use Psr\Http\Message\ResponseInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Psr\SimpleCache\CacheInterface;

/**
 * Shared plumbing for vulnerability sources: config-driven Guzzle client
 * construction, the default enabled toggle, single-package delegation to the
 * batch path, and payload checksumming.
 *
 * Framework-free: configuration is a plain array (keys documented per
 * source), logging is PSR-3.
 */
abstract class AbstractSource implements Source
{
    protected const USER_AGENT = 'laravel-vulns/1.0 (https://github.com/gumslone/laravel-vulns)';

    protected Client $http;

    protected LoggerInterface $logger;

    protected ?CacheInterface $cache = null;

    /** @var array<string, mixed> */
    protected array $options = [];

    /** @var string[] non-fatal problems from the current query — results kept, but incomplete */
    private array $warnings = [];

    /** @var array<int|string, true> */
    private array $incompleteKeys = [];

    abstract public function name(): string;

    /**
     * Non-fatal problems since the last resetWarnings(): a result cap hit, one
     * advisory whose details couldn't be fetched. The results returned are
     * real but may be incomplete — VulnSearch folds these into errors().
     *
     * @return string[]
     */
    public function warnings(): array
    {
        return $this->warnings;
    }

    /**
     * Input keys (as passed to queryBatch) whose lookup failed or was cut
     * short while the rest of the batch succeeded — their results are
     * incomplete and must not read as "clean".
     *
     * @return array<int, int|string>
     */
    public function incompleteKeys(): array
    {
        return array_keys($this->incompleteKeys);
    }

    public function resetWarnings(): void
    {
        $this->warnings = [];
        $this->incompleteKeys = [];
    }

    /**
     * Record (and log) a non-fatal problem that leaves results incomplete.
     *
     * @param  array<int, int|string>  $keys  the queryBatch input keys it concerns, when known
     */
    protected function warn(string $message, array $context = [], array $keys = []): void
    {
        if (! in_array($message, $this->warnings, true)) {
            $this->warnings[] = $message;
        }
        foreach ($keys as $key) {
            $this->incompleteKeys[$key] = true;
        }
        $this->log('warning', "[vulns] {$this->name()}: {$message}", $context);
    }

    public function isEnabled(): bool
    {
        return (bool) $this->config('enabled', true);
    }

    public function queryPackage(PackageData $package): array
    {
        return $this->queryBatch([$package])[0] ?? [];
    }

    /**
     * Whether this source can look the package up at all — the coordinates
     * it keys on are present and mapped. queryBatch() still skips silently;
     * VulnSearch::coverage() uses this to tell "not covered" from "clean".
     */
    public function supports(PackageData $package): bool
    {
        return true;
    }

    /** Read a key from this source's config array. */
    protected function config(string $key, mixed $default = null): mixed
    {
        return $this->options[$key] ?? $default;
    }

    protected function log(string $level, string $message, array $context = []): void
    {
        $this->logger->log($level, $message, $context);
    }

    /**
     * Build the source's HTTP client: retrying handler, configured timeout,
     * JSON accept + user agent. $headers win over the defaults (e.g. Snyk's
     * vnd.api+json accept); $options adds client-level extras (verify, etc.).
     */
    protected function makeClient(string $baseUri, array $headers = [], int $defaultRetry = 2, array $options = []): Client
    {
        return new Client($options + [
            'base_uri' => $baseUri,
            // The 'handler' config key is a test seam: injecting a whole
            // Client would bypass the source's own base_uri handling, which
            // is exactly what base-URL tests need to exercise.
            'handler' => $this->config('handler') ?? RetryHandlerFactory::stack((int) $this->config('retry', $defaultRetry)),
            'timeout' => $this->config('timeout', 30),
            'headers' => $headers + [
                'Accept' => 'application/json',
                'User-Agent' => self::USER_AGENT,
            ],
        ]);
    }

    /**
     * Decode a JSON response body, or throw: a 200 that isn't JSON (a proxy's
     * HTML error page, a truncated body) is a failed lookup, and reading it
     * as an empty result would report the package clean.
     *
     * @param  bool  $allowNull  accept a literal JSON `null` as "no record" (returns [])
     * @return array<array-key, mixed>
     */
    protected function decode(ResponseInterface $response, string $what, bool $allowNull = false): array
    {
        $body = (string) $response->getBody();
        $data = json_decode($body, true);

        if (is_array($data)) {
            return $data;
        }
        if ($allowNull && $data === null && strtolower(trim($body)) === 'null') {
            return [];
        }

        throw new \RuntimeException("{$what}: the response was not valid JSON");
    }

    /** A 404 is the upstream answering "no such record"; everything else is a failure. */
    protected static function isNotFound(\Throwable $e): bool
    {
        return $e instanceof RequestException
            && $e->getResponse()?->getStatusCode() === 404;
    }

    /** Stable content checksum for change-detection on raw source payloads. */
    protected function checksum(mixed $raw): string
    {
        return hash('sha256', (string) json_encode($raw));
    }

    /** Shared constructor plumbing for subclasses. */
    protected function boot(array $options, ?LoggerInterface $logger, ?CacheInterface $cache = null): void
    {
        $this->options = $options;
        $this->logger = $logger ?? new NullLogger;
        $this->cache = $cache;
    }
}
