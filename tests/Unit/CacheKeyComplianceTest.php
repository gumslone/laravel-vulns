<?php

use Gumslone\Vulns\Data\PackageData;
use Gumslone\Vulns\Sources\NvdSource;
use Gumslone\Vulns\Sources\OsvSource;
use Gumslone\Vulns\Support\ArrayCache;
use Gumslone\Vulns\Support\CpeResolver;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;

/**
 * PSR-16 stub as strict as Symfony's Psr16Cache: any key containing a
 * reserved character ({}()/\@:) throws instead of being stored.
 */
function strictPsr16(): Psr\SimpleCache\CacheInterface
{
    return new class extends ArrayCache
    {
        public function get(string $key, mixed $default = null): mixed
        {
            $this->assertLegalKey($key);

            return parent::get($key, $default);
        }

        public function set(string $key, mixed $value, null|int|\DateInterval $ttl = null): bool
        {
            $this->assertLegalKey($key);

            return parent::set($key, $value, $ttl);
        }

        public function delete(string $key): bool
        {
            $this->assertLegalKey($key);

            return parent::delete($key);
        }

        public function has(string $key): bool
        {
            $this->assertLegalKey($key);

            return parent::has($key);
        }

        private function assertLegalKey(string $key): void
        {
            if (preg_match('#[{}()/\\\\@:]#', $key)) {
                throw new class("PSR-16 reserved character in cache key: {$key}") extends \InvalidArgumentException implements \Psr\SimpleCache\InvalidArgumentException {};
            }
        }
    };
}

it('OSV hydration cache traffic uses only PSR-16-legal keys', function () {
    $batchResponse = fn () => new Response(200, [], json_encode(['results' => [
        ['vulns' => [['id' => 'OSV-A', 'modified' => '2024-01-01T00:00:00Z']]],
    ]]));

    $mock = new MockHandler([
        $batchResponse(),
        new Response(200, [], json_encode(['id' => 'OSV-A', 'summary' => 'A vulnerability', 'aliases' => []])),
        $batchResponse(), // second batch must be served from cache — no hydration
    ]);

    $source = new OsvSource(
        new Client(['handler' => HandlerStack::create($mock)]),
        cache: strictPsr16(),
    );

    $packages = [new PackageData(name: 'left-pad', version: '1.3.0', ecosystem: 'npm')];

    // Exercises both the cache write (first batch) and the cache read
    // (second batch); a reserved character in the key would throw here.
    $source->queryBatch($packages);
    $second = $source->queryBatch($packages);

    expect(array_map(fn ($v) => $v->vulnId, $second[0]))->toBe(['OSV-A']);
});

it('NVD rate-limit cache traffic uses only PSR-16-legal keys', function () {
    $mock = new MockHandler([
        new Response(200, [], json_encode(['vulnerabilities' => [['cve' => ['id' => 'CVE-2024-0001']]]])),
    ]);

    $source = new NvdSource(
        new CpeResolver,
        null,
        new Client(['handler' => HandlerStack::create($mock)]),
        ['rate_limit_max' => 1000],
        null,
        strictPsr16(),
    );

    // fetchById passes through throttle(), whose counter key hits the cache.
    expect($source->fetchById('CVE-2024-0001')?->vulnId)->toBe('CVE-2024-0001');
});
