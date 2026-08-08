<?php

use Gumslone\Vulns\Support\ArrayCache;

it('honours DateInterval TTLs built from ISO durations', function () {
    // A constructed interval reports ->days === false, so field-summing the
    // interval used to expire day/month/year TTLs immediately.
    $cache = new ArrayCache;
    $cache->set('week', 'value', new DateInterval('P7D'));

    expect($cache->get('week'))->toBe('value')
        ->and($cache->has('week'))->toBeTrue();
});

it('honours integer TTLs and expiry', function () {
    $cache = new ArrayCache;
    $cache->set('fresh', 'value', 60);
    $cache->set('stale', 'value', -1);

    expect($cache->get('fresh'))->toBe('value')
        ->and($cache->get('stale', 'default'))->toBe('default');
});
