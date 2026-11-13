<?php

/*
 * EUVD is searched by product name and answers a "contains" match. A full
 * fetch attached 5,700 unrelated advisories to 98 packages that way —
 * Jenkins and Intel configuration tools on league/config, 685 records on the
 * npm package "he". These are the shapes seen live.
 */

use Gumslone\Vulns\Support\ProductMatch;

it('accepts the package under its own name and vendor', function (array $products, array $vendors, string $name, ?string $namespace) {
    expect(ProductMatch::concerns($products, $vendors, $name, $namespace))->toBeTrue();
})->with([
    'composer vendor' => [['framework'], ['laravel'], 'framework', 'laravel'],
    'vendor/name as the product' => [['laravel/framework'], [], 'framework', 'laravel'],
    'name given as vendor/name' => [['framework'], ['Laravel'], 'laravel/framework', null],
    'npm scope' => [['types'], ['babel'], 'types', '@babel'],
    'vendor in other words' => [['config'], ['The PHP League'], 'config', 'league'],
    'vendor a prefix' => [['guzzle'], ['guzzle'], 'guzzle', 'guzzlehttp'],
    'self-named, no scope' => [['axios'], ['axios'], 'axios', null],
    'self-named with suffix' => [['express'], ['expressjs'], 'express', null],
    'self-named vendor prefix' => [['vite'], ['vitejs'], 'vite', null],
    'product carries its vendor' => [['axios/axios'], ['someone'], 'axios', null],
    'Maven group and loose name' => [['Apache Log4j2', 'log4j'], ['Apache Software Foundation'], 'log4j-core', 'org.apache.logging.log4j'],
    'Go module path' => [['gin'], ['gin-gonic'], 'gin', 'github.com/gin-gonic'],
    'one of several products' => [['other-thing', 'curl'], ['curl'], 'curl', null],
    'advisory without vendor' => [['curl'], [], 'curl', null],
    'vendor not given' => [['curl'], ['n/a'], 'curl', 'haxx'],
]);

it('rejects advisories about other products', function (array $products, array $vendors, string $name, ?string $namespace) {
    expect(ProductMatch::concerns($products, $vendors, $name, $namespace))->toBeFalse();
})->with([
    // What "product=config" really returned for league/config.
    'name only contained' => [['Microsoft Configuration Manager 2603'], ['Microsoft'], 'config', 'league'],
    'plugin with the word' => [['AWS Global Configuration Plugin'], ['Jenkins'], 'config', 'league'],
    'Perl module' => [['Config::IniFiles'], ['SHLOMIF'], 'config', 'league'],
    'same name, other vendor' => [['config'], ['node-config'], 'config', 'league'],
    'generic scoped name' => [['core'], ['Drupal'], 'core', '@vueuse'],
    'framework of another vendor' => [['Microsoft .NET Framework 4.8'], ['Microsoft'], 'framework', 'laravel'],
    'same name, unrelated vendor' => [['express'], ['Ubiquiti Inc'], 'express', null],
    'longer product name' => [['Cisco Unified Contact Center Express'], ['Cisco'], 'express', null],
    'sibling product' => [['vitest'], ['vitest-dev'], 'vite', null],
    'loose match without vendor' => [['vite-plus'], ['someone-else'], 'vite', null],
    'short name inside a title' => [['HE Station Manager'], ['Acme'], 'he', null],
    'processors' => [['AMD EPYC 9005 Series Processors'], ['AMD'], 'process', 'symfony'],
    'hosting noise is not a vendor' => [['gin'], ['GitHub'], 'gin', 'github.com/gin-gonic'],
]);

it('cannot judge an advisory that names no product', function () {
    expect(ProductMatch::concerns([], ['Microsoft'], 'config', 'league'))->toBeNull()
        ->and(ProductMatch::concerns(['', '  '], [], 'config', 'league'))->toBeNull();
});

it('accepts an exact name from any vendor when vendors are not required', function () {
    expect(ProductMatch::concerns(['express'], ['Ubiquiti Inc'], 'express', null, requireVendor: false))->toBeTrue()
        // …but still not a mere "contains" match.
        ->and(ProductMatch::concerns(['Cisco Unified Contact Center Express'], ['Cisco'], 'express', null, requireVendor: false))->toBeFalse();
});

it('lets a vendor hint settle what a name alone cannot', function () {
    // The Rust crate "openssl" is maintained by sfackler; OpenSSL's own CVEs are not its.
    expect(ProductMatch::concerns(['OpenSSL'], ['OpenSSL'], 'openssl', null))->toBeTrue() // no hint: self-named, accepted
        ->and(ProductMatch::concerns(['OpenSSL'], ['OpenSSL'], 'openssl', null, vendorHints: ['sfackler']))->toBeFalse()
        ->and(ProductMatch::concerns(['openssl'], ['sfackler'], 'openssl', null, vendorHints: ['sfackler']))->toBeTrue()
        // A hint widens as well: either the namespace or the CPE vendor may match.
        ->and(ProductMatch::concerns(['guzzle'], ['guzzlephp'], 'guzzle', 'acme', vendorHints: ['guzzlephp']))->toBeTrue()
        // NVD's synthetic "<name>_project" vendors say no more than the name does.
        ->and(ProductMatch::concerns(['qs'], ['qs'], 'qs', null, vendorHints: ['qs_project']))->toBeTrue()
        ->and(ProductMatch::concerns(['express'], ['Ubiquiti Inc'], 'express', null, vendorHints: ['expressjs']))->toBeFalse();
});
