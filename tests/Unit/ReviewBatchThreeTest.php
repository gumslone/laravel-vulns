<?php

/*
 * Regressions found by an independent review of 1.22.1 – 1.22.4.
 */

use Gumslone\Vulns\Contracts\CpeLookup;
use Gumslone\Vulns\Data\PackageData;
use Gumslone\Vulns\Data\VulnerabilityData;
use Gumslone\Vulns\Sources\AbstractSource;
use Gumslone\Vulns\Sources\EuvdSource;
use Gumslone\Vulns\Sources\NvdSource;
use Gumslone\Vulns\Support\ArrayCache;
use Gumslone\Vulns\Support\CpeResolver;
use Gumslone\Vulns\Support\ProductMatch;
use Gumslone\Vulns\Support\RetryHandlerFactory;
use Gumslone\Vulns\Testing\FakeSource;
use Gumslone\Vulns\VulnSearch;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Promise\Create;
use GuzzleHttp\Psr7\Response;

function rrHit(string $id, string $product, ?string $vendor, string $productVersion = '0 <99.0.0'): array
{
    return [
        'id' => $id, 'description' => "A bug in {$product}.", 'aliases' => str_replace('EUVD', 'CVE', $id), 'baseScore' => 7.5,
        'enisaIdProduct' => [['product' => ['name' => $product], 'product_version' => $productVersion]],
        'enisaIdVendor' => $vendor === null ? [] : [['vendor' => ['name' => $vendor]]],
    ];
}

/** @return array{0: EuvdSource, 1: ArrayObject} */
function rrEuvd(array $responses, array $options = [], ?ArrayCache $cache = null, ?CpeLookup $lookup = null): array
{
    $history = new ArrayObject;
    $stack = HandlerStack::create(new MockHandler($responses));
    $stack->push(Middleware::history($history));

    return [new EuvdSource(new Client(['handler' => $stack]), $options, null, $cache, $lookup), $history];
}

function rrIds(array $vulns): array
{
    return array_map(fn ($v) => $v->vulnId, $vulns);
}

// ── EUVD ─────────────────────────────────────────────────────────────────

it('searches a shared bare name once, not once per package that carries it', function () {
    // "@vueuse/core" and "@inertiajs/core" both search "core": the same pages.
    $page = new Response(200, [], json_encode(['items' => [rrHit('EUVD-2032-1', 'core', 'vueuse'), rrHit('EUVD-2032-2', 'core', 'inertiajs')], 'total' => 2]));
    [$source, $history] = rrEuvd([$page]);

    $results = $source->queryBatch([
        'a' => new PackageData(name: 'core', version: '1.0.0', ecosystem: 'npm', namespace: '@vueuse'),
        'b' => new PackageData(name: 'core', version: '1.0.0', ecosystem: 'npm', namespace: '@inertiajs'),
    ]);

    expect($history)->toHaveCount(1)
        ->and(rrIds($results['a']))->toBe(['CVE-2032-1'])
        ->and(rrIds($results['b']))->toBe(['CVE-2032-2']);
});

it('keeps same-named packages apart when only their CPE vendor differs', function () {
    // The Rust crate "openssl" (sfackler) and OpenSSL itself, in one batch and across the cache.
    $hits = ['items' => [rrHit('EUVD-2032-10', 'OpenSSL', 'OpenSSL', '0 <3.0.7'), rrHit('EUVD-2032-11', 'openssl', 'sfackler', '0 <0.10.90')], 'total' => 2];
    $crate = new PackageData(name: 'openssl', version: '0.10.81', ecosystem: 'cargo', cpe23: 'cpe:2.3:a:sfackler:openssl:*:*:*:*:*:*:*:*');
    $real = new PackageData(name: 'openssl', version: '3.0.0', ecosystem: 'generic', cpe23: 'cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:*');

    foreach ([['crate' => $crate, 'real' => $real], ['real' => $real, 'crate' => $crate]] as $batch) {
        [$source] = rrEuvd([new Response(200, [], json_encode($hits))]);
        $results = $source->queryBatch($batch);
        expect(rrIds($results['crate']))->toBe(['CVE-2032-11'])
            ->and(rrIds($results['real']))->toBe(['CVE-2032-10']);
    }

    // One package's cached answer must not be served to the other.
    $cache = new ArrayCache;
    [$first] = rrEuvd([new Response(200, [], json_encode($hits))], [], $cache);
    [$second] = rrEuvd([new Response(200, [], json_encode($hits))], [], $cache);
    expect(rrIds($first->queryBatch([$real])[0]))->toBe(['CVE-2032-10'])
        ->and(rrIds($second->queryBatch([$crate])[0]))->toBe(['CVE-2032-11']);
});

it('searches a Go module by its name, not by its major-version suffix', function () {
    $page = new Response(200, [], json_encode(['items' => [rrHit('EUVD-2032-20', 'jwt', 'golang-jwt')], 'total' => 1]));
    [$source, $history] = rrEuvd([$page, new Response(200, [], json_encode(['items' => [rrHit('EUVD-2032-21', 'yaml', 'go-yaml')], 'total' => 1]))]);

    $jwt = $source->queryBatch([new PackageData(name: 'github.com/golang-jwt/jwt/v5', version: '5.0.0', ecosystem: 'go')])[0];
    $yaml = $source->queryBatch([new PackageData(name: 'gopkg.in/yaml.v3', version: '3.0.0', ecosystem: 'go')])[0];

    parse_str($history[0]['request']->getUri()->getQuery(), $first);
    parse_str($history[1]['request']->getUri()->getQuery(), $second);
    expect($first['product'])->toBe('jwt')
        ->and($second['product'])->toBe('yaml')
        ->and(rrIds($jwt))->toBe(['CVE-2032-20']);
});

it("does not let a sibling product's range clear the package", function () {
    // Our entry has no version text; "vite-plugin-foo" has a clean range we escape.
    $item = ['id' => 'EUVD-2032-30', 'description' => 'x', 'aliases' => 'CVE-2032-30',
        'enisaIdVendor' => [['vendor' => ['name' => 'vitejs']]],
        'enisaIdProduct' => [
            ['product' => ['name' => 'vite'], 'product_version' => ''],
            ['product' => ['name' => 'vite-plugin-foo'], 'product_version' => '0 <1.0.0'],
        ]];
    [$source] = rrEuvd([new Response(200, [], json_encode(['items' => [$item], 'total' => 1]))]);

    expect(rrIds($source->queryBatch([new PackageData(name: 'vite', version: '5.0.0', ecosystem: 'npm')])[0]))->toBe(['CVE-2032-30']);
});

// ── ProductMatch ─────────────────────────────────────────────────────────

it('recognises the vendor shapes real records use', function (array $products, array $vendors, string $name, ?string $namespace, array $hints) {
    expect(ProductMatch::concerns($products, $vendors, $name, $namespace, vendorHints: $hints))->toBeTrue();
})->with([
    'short self-named: vue by vuejs' => [['vue'], ['vuejs'], 'vue', null, []],
    'short self-named: koa by koajs' => [['koa'], ['koajs'], 'koa', null, []],
    'org written as one word' => [['config'], ['thephpleague'], 'config', 'league', []],
    'the vendor IS a noise word' => [['PHP'], ['PHP Group'], 'php', null, ['php']],
    'Node.js by its hint' => [['Node.js'], ['Node.js'], 'node', null, ['nodejs']],
    'Maven: product carries vendor and a version digit' => [['Apache Log4j2'], ['Apache Software Foundation'], 'log4j-core', 'org.apache.logging.log4j', []],
    'Maven: vendor-prefixed product' => [['Apache Tomcat'], ['Apache Software Foundation'], 'tomcat-embed-core', 'org.apache.tomcat.embed', []],
    'Go module with a major-version suffix' => [['jwt'], ['golang-jwt'], 'github.com/golang-jwt/jwt/v5', null, []],
]);

it('still rejects what the looser rules must not let in', function (array $products, array $vendors, string $name, ?string $namespace) {
    expect(ProductMatch::concerns($products, $vendors, $name, $namespace))->toBeFalse();
})->with([
    'sibling component of the same vendor' => [['symfony/http-foundation'], ['symfony'], 'http-kernel', 'symfony'],
    'another product of the vendor' => [['Laravel Nova'], ['Laravel'], 'framework', 'laravel'],
    'short name inside another word' => [['vuex'], ['vuejs'], 'vue', null],
    'containment of a short word' => [['config'], ['bigleague'], 'config', 'lea'],
]);

it('treats a placeholder product name as no name at all', function () {
    expect(ProductMatch::concerns(['n/a'], ['n/a'], 'config', 'league'))->toBeNull()
        ->and(ProductMatch::concerns(['n/a', 'config'], ['thephpleague'], 'config', 'league'))->toBeTrue();
});

// ── NVD retries ──────────────────────────────────────────────────────────

/** @return int[] back-offs (ms) of NVD's retry stack for a request answered with these statuses */
function rrBackoffs(array $answers, float $spacing = 0.6, ?int $retries = null): array
{
    $delays = [];
    $stack = NvdSource::retryStack($retries ?? NvdSource::DEFAULT_RETRIES, 30, $spacing);
    $stack->setHandler(function ($request, array $options) use (&$answers, &$delays) {
        $delays[] = (int) ($options['delay'] ?? 0);

        return Create::promiseFor(new Response((int) array_shift($answers)));
    });
    (new Client(['handler' => $stack, 'http_errors' => false]))->get('https://nvd.test/cves/2.0');

    return array_slice($delays, 1);
}

it('keeps the patience for a blown rate limit where it was: three waits, not eight', function () {
    // 1.22.2 raised the retry count for 5xx and silently tripled the 403 chain to 450 s.
    expect(rrBackoffs(array_fill(0, 12, 403)))->toBe([30000, 60000, 60000]);
});

it('never passes a negative back-off to the HTTP handler', function () {
    $delays = [];
    $answers = [new Response(503, ['Retry-After' => '-5']), new Response(200)];
    $stack = RetryHandlerFactory::stack(2, 100);
    $stack->setHandler(function ($request, array $options) use (&$answers, &$delays) {
        $delays[] = (int) ($options['delay'] ?? 0);

        return Create::promiseFor(array_shift($answers));
    });
    (new Client(['handler' => $stack, 'http_errors' => false]))->get('https://api.test/x');

    expect($delays[1])->toBeGreaterThanOrEqual(0);
});

it('paces retries through the same budget as first attempts', function () {
    // Keyless NVD, every request answered 503 once: before, retries were sent
    // outside the pacer and one worker put 10 requests into a 30 s window.
    $clock = new class
    {
        public float $now = 1_000.0;

        /** @var float[] */
        public array $sent = [];
    };
    $answers = [];
    for ($i = 0; $i < 6; $i++) {
        $answers[] = 503;
        $answers[] = 200;
    }
    $options = [
        'clock' => fn (): float => $clock->now,
        'sleep' => function (float $seconds) use ($clock): void {
            $clock->now += $seconds;
        },
        'handler_base' => function ($request, array $options) use (&$answers, $clock) {
            $clock->sent[] = $clock->now;
            $status = (int) array_shift($answers);

            return Create::promiseFor(new Response($status, [], $status === 200 ? json_encode(['vulnerabilities' => [], 'totalResults' => 0]) : 'No server is available'));
        },
    ];
    $source = new NvdSource(new CpeResolver, null, null, $options, null, new ArrayCache);

    foreach (['a', 'b', 'c', 'd', 'e', 'f'] as $product) {
        $source->queryPackage(new PackageData(name: $product, version: '1.0', ecosystem: 'generic', cpe23: "cpe:2.3:a:{$product}:{$product}:1.0:*:*:*:*:*:*:*"));
    }

    $sent = $clock->sent;
    expect($sent)->toHaveCount(12);
    for ($i = 1; $i < count($sent); $i++) {
        expect($sent[$i] - $sent[$i - 1])->toBeGreaterThanOrEqual(6.0 - 1e-6); // six seconds apart, retries included
    }
    for ($i = 5; $i < count($sent); $i++) {
        expect($sent[$i] - $sent[$i - 5])->toBeGreaterThanOrEqual(30.0 - 1e-6); // never six requests inside 30 s
    }
});

it('reads an empty retry setting as "not set", not as zero', function () {
    $delays = fn (array $options) => (function () use ($options) {
        $seen = [];
        $answers = [503, 503, 200];
        $source = new NvdSource(new CpeResolver, null, null, $options + [
            'sleep' => fn () => null,
            'handler_base' => function ($request, array $o) use (&$answers, &$seen) {
                $seen[] = (int) ($o['delay'] ?? 0);
                $status = (int) array_shift($answers);

                return Create::promiseFor(new Response($status, [], $status === 200 ? json_encode(['vulnerabilities' => [], 'totalResults' => 0]) : ''));
            },
        ], null, new ArrayCache);
        try {
            $source->queryPackage(new PackageData(name: 'x', version: '1.0', ecosystem: 'generic', cpe23: 'cpe:2.3:a:x:x:1.0:*:*:*:*:*:*:*'));
        } catch (RuntimeException) {
            // out of retries: the lookup fails, as it should
        }

        return count($seen);
    })();

    // VULNS_NVD_RETRY= / VULNS_NVD_RETRY_DELAY= / VULNS_NVD_MIN_INTERVAL= left empty in .env
    expect($delays(['retry' => '', 'retry_delay' => '', 'min_interval' => '']))->toBe(3)
        ->and($delays(['retry' => null]))->toBe(3)
        ->and($delays(['retry' => 0]))->toBe(1); // an explicit 0 still means "do not retry"
});

// ── VulnSearch ───────────────────────────────────────────────────────────

it('does not ask a source by id again once it has failed in the same search', function () {
    // With patient retries a second round against a feed that is down could
    // hold one search for minutes more.
    $down = new class extends AbstractSource
    {
        public int $batches = 0;

        public int $lookups = 0;

        public function __construct()
        {
            $this->boot(['enabled' => true], null);
        }

        public function name(): string
        {
            return 'nvd';
        }

        public function supports(PackageData $package): bool
        {
            return true;
        }

        public function queryBatch(array $packages): array
        {
            $this->batches++;
            throw new RuntimeException('503 No server is available');
        }

        public function fetchById(string $vulnId): ?VulnerabilityData
        {
            $this->lookups++;
            throw new RuntimeException('503 No server is available');
        }
    };
    // A record without version data: exactly what range completion would look up by id.
    $undeterminable = new VulnerabilityData(vulnId: 'CVE-2032-90', source: 'cve_search', rawDataChecksum: 'x');
    $search = (new VulnSearch([new FakeSource('cve_search', ['lib' => [$undeterminable]]), $down]))
        ->completeRanges(['nvd']);

    $found = $search->search(new PackageData(name: 'lib', version: '1.0.0', ecosystem: 'npm'));

    expect($found)->toHaveCount(1)
        ->and($down->batches)->toBe(1)
        ->and($down->lookups)->toBe(0)
        ->and($search->errors()['nvd'])->toContain('503');
});

// ── EUVD: names with more records than can be read ───────────────────────

function rrPage(array $items, int $total): Response
{
    return new Response(200, [], json_encode(['items' => $items, 'total' => $total]));
}

function rrNoise(int $count = 100): array
{
    return array_map(fn (int $i) => rrHit("EUVD-2033-9{$i}", "Version Tool {$i}", 'Someone Else'), range(1, $count));
}

function rrQuery(ArrayObject $history, int $index): array
{
    parse_str($history[$index]['request']->getUri()->getQuery(), $query);

    return $query;
}

it("narrows an oversized search to the package's vendor instead of giving up on it", function () {
    // "version" has 9,090 records. Reading 2,000 of them and reporting the
    // package as "possibly incomplete" forever helped nobody.
    $cache = new ArrayCache;
    [$source, $history] = rrEuvd([
        rrPage(rrNoise(), 9090),
        rrPage([rrHit('EUVD-2033-1', 'version', 'sebastianbergmann')], 1),
    ], [], $cache);
    $package = [new PackageData(name: 'version', version: '5.0.2', ecosystem: 'composer', namespace: 'sebastian')];

    $found = $source->queryBatch($package)[0];

    expect($history)->toHaveCount(2) // not twenty pages
        ->and(rrQuery($history, 0))->not->toHaveKey('vendor')
        ->and(rrQuery($history, 1))->toMatchArray(['product' => 'version', 'vendor' => 'sebastian'])
        ->and(rrIds($found))->toBe(['CVE-2033-1'])
        ->and($source->warnings())->toBe([])
        ->and($source->incompleteKeys())->toBe([]);

    // A complete answer: cached like any other.
    [$again, $noRequests] = rrEuvd([], [], $cache);
    expect(rrIds($again->queryBatch($package)[0]))->toBe(['CVE-2033-1'])
        ->and($noRequests)->toHaveCount(0);
});

it('narrows by the package name when it has no vendor, and by the words of a Maven group', function () {
    [$source, $history] = rrEuvd([rrPage(rrNoise(), 9051), rrPage([], 0)]);
    $source->queryBatch([new PackageData(name: 'core', version: '1.0.0', ecosystem: 'npm')]);
    expect(rrQuery($history, 1)['vendor'])->toBe('core'); // the self-named project is all concerns() would accept

    [$source, $history] = rrEuvd([rrPage(rrNoise(), 5000), rrPage([], 0), rrPage([], 0), rrPage([], 0)]);
    $source->queryBatch([new PackageData(name: 'log4j-core', version: '2.14.0', ecosystem: 'maven', namespace: 'org.apache.logging.log4j')]);
    expect(array_map(fn (int $i) => rrQuery($history, $i)['vendor'], [1, 2, 3]))->toBe(['apache', 'logging', 'log4j']);

    [$source, $history] = rrEuvd([rrPage(rrNoise(), 5000), rrPage([], 0), rrPage([], 0)]);
    $source->queryBatch([new PackageData(name: 'openssl', version: '0.10.81', ecosystem: 'cargo', cpe23: 'cpe:2.3:a:sfackler:openssl:*:*:*:*:*:*:*:*')]);
    expect(rrQuery($history, 1)['vendor'])->toBe('sfackler');
});

it('still says so when even the vendor-narrowed search is too large to read', function () {
    [$source] = rrEuvd([
        rrPage(rrNoise(), 9000),
        rrPage(rrNoise(), 900), rrPage(rrNoise(), 900), // narrowed, and still more than two pages
    ], ['max_pages' => 2], $cache = new ArrayCache);
    $package = ['pkg' => new PackageData(name: 'version', version: '5.0.2', ecosystem: 'composer', namespace: 'sebastian')];

    $source->queryBatch($package);

    expect($source->warnings())->toHaveCount(1)
        ->and($source->warnings()[0])->toContain('truncated')
        ->and($source->incompleteKeys())->toBe(['pkg']);

    // An incomplete answer is never cached.
    [$again, $history] = rrEuvd([rrPage([], 0)], ['max_pages' => 2], $cache);
    $again->queryBatch($package);
    expect($history)->toHaveCount(1);
});
