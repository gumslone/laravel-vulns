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

// Reference values computed with FIRST's calculator; the modifier path is
// additionally validated against it over 5000 random modifier sets.
it('recalculates v4 environmental/threat scores like the FIRST reference', function () {
    // Air-gapped: MAV Physical drops a 9.3 network RCE to 7.0.
    $airGapped = Cvss4::environmental('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N', ['MAV' => 'P']);
    expect($airGapped['score'])->toBe(7.0)
        ->and($airGapped['vector'])->toEndWith('/MAV:P');

    // High confidentiality requirement + PoC-maturity threat.
    expect(Cvss4::environmental('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N', ['CR' => 'H', 'E' => 'P'])['score'])
        ->toBe(7.8);

    // Safety impact on subsequent systems raises the score.
    expect(Cvss4::environmental('CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:L/SC:H/SI:H/SA:H', ['MSI' => 'S'])['score'])
        ->toBe(8.1);

    // 'X' modifiers are no-ops; unknown keys are ignored; base stays intact.
    $noop = Cvss4::environmental('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N', ['MAV' => 'X', 'BOGUS' => 'H']);
    expect($noop['score'])->toBe(9.3)
        ->and($noop['vector'])->not->toContain('BOGUS');

    expect(Cvss4::environmental('not a vector', ['MAV' => 'P']))->toBeNull();
});

it('routes v4 environmental recalculation through the calculator entry point', function () {
    $result = (new CvssCalculator)->environmental(
        'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N',
        ['MAV' => 'P'],
    );

    expect($result['score'])->toBe(7.0);
});

it('routes v4 vectors through the version-agnostic calculator entry point', function () {
    $calc = new CvssCalculator;

    expect($calc->baseScore('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N'))->toBe(9.3)
        ->and($calc->baseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'))->toBe(9.8);
});

it('rejects invalid modifier values instead of silently mis-scoring', function () {
    $base = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N';

    // E:Z would otherwise read as E:U — the LOWEST threat level.
    expect(Cvss4::environmental($base, ['E' => 'Z']))->toBeNull()
        ->and(Cvss4::environmental($base, ['MAV' => 'Q']))->toBeNull()
        // v3-style values on v4 metrics are invalid too, not reinterpreted.
        ->and(Cvss4::environmental($base, ['MUI' => 'R']))->toBeNull();
});

it('never duplicates a metric when the base vector already carries it', function () {
    $base = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:P/CR:M';
    $result = Cvss4::environmental($base, ['E' => 'A', 'CR' => 'H', 'MAV' => 'P']);

    expect(substr_count($result['vector'], '/E:'))->toBe(1)
        ->and(substr_count($result['vector'], '/CR:'))->toBe(1)
        ->and($result['vector'])->toContain('/E:A')
        ->and($result['vector'])->toContain('/CR:H')
        ->and($result['vector'])->not->toContain('/E:P');
});

it('applies lowercase modifier keys identically on the v3 and v4 paths', function () {
    $calc = new CvssCalculator;

    $v4 = $calc->environmental('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N', ['mav' => 'p']);
    $v3 = $calc->environmental('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', ['mav' => 'p']);

    expect($v4['score'])->toBe(7.0)
        ->and($v3['score'])->toBeLessThan(9.8); // applied, not silently ignored
});
