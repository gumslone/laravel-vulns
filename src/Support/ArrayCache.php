<?php

declare(strict_types=1);

namespace Gumslone\Vulns\Support;

use Psr\SimpleCache\CacheInterface;

/**
 * Minimal in-memory PSR-16 cache: per-process payload caching for CLI runs
 * and tests. TTLs are honoured loosely (expiry checked on read).
 */
class ArrayCache implements CacheInterface
{
    /** @var array<string, array{value: mixed, expires: ?float}> */
    private array $items = [];

    public function get(string $key, mixed $default = null): mixed
    {
        $item = $this->items[$key] ?? null;
        if ($item === null || ($item['expires'] !== null && $item['expires'] < microtime(true))) {
            unset($this->items[$key]);

            return $default;
        }

        return $item['value'];
    }

    public function set(string $key, mixed $value, null|int|\DateInterval $ttl = null): bool
    {
        $seconds = $ttl instanceof \DateInterval
            ? (float) $ttl->days * 86400 + $ttl->h * 3600 + $ttl->i * 60 + $ttl->s
            : $ttl;
        $this->items[$key] = ['value' => $value, 'expires' => $seconds !== null ? microtime(true) + $seconds : null];

        return true;
    }

    public function delete(string $key): bool
    {
        unset($this->items[$key]);

        return true;
    }

    public function clear(): bool
    {
        $this->items = [];

        return true;
    }

    public function getMultiple(iterable $keys, mixed $default = null): iterable
    {
        $out = [];
        foreach ($keys as $key) {
            $out[$key] = $this->get($key, $default);
        }

        return $out;
    }

    public function setMultiple(iterable $values, null|int|\DateInterval $ttl = null): bool
    {
        foreach ($values as $key => $value) {
            $this->set((string) $key, $value, $ttl);
        }

        return true;
    }

    public function deleteMultiple(iterable $keys): bool
    {
        foreach ($keys as $key) {
            $this->delete((string) $key);
        }

        return true;
    }

    public function has(string $key): bool
    {
        return $this->get($key, $this) !== $this;
    }
}
