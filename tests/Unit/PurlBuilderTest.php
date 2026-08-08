<?php

use Gumslone\Vulns\Support\PurlBuilder;

it('parses an unencoded npm scope without misreading it as a version', function () {
    // The '@' here starts a scope segment, not a version — splitting at the
    // last '@' anywhere used to yield name '' and version 'babel/core'.
    $parsed = (new PurlBuilder)->parse('pkg:npm/@babel/core');

    expect($parsed['name'])->toBe('core')
        ->and($parsed['namespace'])->toBe('@babel')
        ->and($parsed['version'])->toBeNull();
});

it('still splits the version at an @ after the last slash', function () {
    $parsed = (new PurlBuilder)->parse('pkg:npm/@babel/core@7.0.0');

    expect($parsed['name'])->toBe('core')
        ->and($parsed['namespace'])->toBe('@babel')
        ->and($parsed['version'])->toBe('7.0.0');
});

it('parses the spec-canonical encoded scope form unchanged', function () {
    $parsed = (new PurlBuilder)->parse('pkg:npm/%40babel/core@7.0.0');

    expect($parsed['name'])->toBe('core')
        ->and($parsed['namespace'])->toBe('@babel')
        ->and($parsed['version'])->toBe('7.0.0');
});

it('keeps parsing unnamespaced purls with and without versions', function () {
    expect((new PurlBuilder)->parse('pkg:pypi/requests@2.32.3'))
        ->toMatchArray(['type' => 'pypi', 'namespace' => null, 'name' => 'requests', 'version' => '2.32.3']);

    expect((new PurlBuilder)->parse('pkg:pypi/requests'))
        ->toMatchArray(['type' => 'pypi', 'namespace' => null, 'name' => 'requests', 'version' => null]);
});
