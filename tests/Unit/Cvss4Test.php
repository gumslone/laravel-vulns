<?php

use Gumslone\Vulns\Support\Cvss4;
use Gumslone\Vulns\Support\CvssCalculator;

// Expected scores computed with FIRST's reference implementation
// (github.com/FIRSTdotorg/cvss-v4-calculator); the port was additionally
// validated against it over 5000 random vectors.
it('scores CVSS v4.0 vectors exactly like the FIRST reference calculator', function (string $vector, float $expected) {
    expect(Cvss4::baseScore($vector))->toBe($expected);
})->with([
    'maximal base' => ['CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H', 10.0],
    'no impact' => ['CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N', 0.0],
    'network high impact' => ['CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N', 9.3],
    'local low priv' => ['CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N', 8.5],
    'physical' => ['CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N', 7.0],
    'with unreported threat' => ['CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U', 8.1],
    'subsequent safety' => ['CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:N/SC:H/SI:S/SA:S', 7.2],
]);

it('rejects malformed v4 vectors instead of guessing', function () {
    expect(Cvss4::baseScore('CVSS:4.0/AV:N/AC:L'))->toBeNull()
        ->and(Cvss4::baseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'))->toBeNull()
        ->and(Cvss4::baseScore('garbage'))->toBeNull();
});

it('routes v4 vectors through the version-agnostic calculator entry point', function () {
    $calc = new CvssCalculator;

    expect($calc->baseScore('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N'))->toBe(9.3)
        ->and($calc->baseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'))->toBe(9.8);
});
