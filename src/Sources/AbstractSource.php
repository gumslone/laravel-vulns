<?php

declare(strict_types=1);

namespace Gumslone\Vulns\Sources;

use Gumslone\Vulns\Contracts\Source;
use Gumslone\Vulns\Data\PackageData;
use Gumslone\Vulns\Support\RetryHandlerFactory;
use GuzzleHttp\Client;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

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

    protected ?\Psr\SimpleCache\CacheInterface $cache = null;

    /** @var array<string, mixed> */
    protected array $options = [];

    abstract public function name(): string;

    public function isEnabled(): bool
    {
        return (bool) $this->config('enabled', true);
    }

    public function queryPackage(PackageData $package): array
    {
        return $this->queryBatch([$package])[0] ?? [];
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
            'handler' => RetryHandlerFactory::stack((int) $this->config('retry', $defaultRetry)),
            'timeout' => $this->config('timeout', 30),
            'headers' => $headers + [
                'Accept' => 'application/json',
                'User-Agent' => self::USER_AGENT,
            ],
        ]);
    }

    /** Stable content checksum for change-detection on raw source payloads. */
    protected function checksum(mixed $raw): string
    {
        return hash('sha256', (string) json_encode($raw));
    }

    /** Shared constructor plumbing for subclasses. */
    protected function boot(array $options, ?LoggerInterface $logger, ?\Psr\SimpleCache\CacheInterface $cache = null): void
    {
        $this->options = $options;
        $this->logger = $logger ?? new NullLogger;
        $this->cache = $cache;
    }
}
