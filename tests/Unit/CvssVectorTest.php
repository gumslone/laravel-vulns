<?php

use Gumslone\Vulns\Support\Cvss2;
use Gumslone\Vulns\Support\CvssCalculator;
use Gumslone\Vulns\Support\CvssVector;
use Gumslone\Vulns\Support\CvssVectorTable;

const V3_CRITICAL = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';
const V4_CRITICAL = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N';
const V2_HIGH = 'AV:N/AC:L/Au:N/C:P/I:P/A:P';

it('tells the version of any vector, prefixed or not', function () {
    expect(CvssVector::versionOf(V3_CRITICAL))->toBe('3.1')
        ->and(CvssVector::versionOf('CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'))->toBe('3.0')
        ->and(CvssVector::versionOf(V4_CRITICAL))->toBe('4.0')
        ->and(CvssVector::versionOf(V2_HIGH))->toBe('2.0')
        ->and(CvssVector::versionOf('(AV:N/AC:L/Au:N/C:P/I:P/A:P)'))->toBe('2.0')
        ->and(CvssVector::versionOf('AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'))->toBe('3.1')
        ->and(CvssVector::versionOf('CVSS:9.9/AV:N'))->toBeNull()
        ->and(CvssVector::versionOf('not a vector'))->toBeNull()
        ->and(CvssVector::majorVersionOf(V4_CRITICAL))->toBe(4);
});

it('splits a vector into base, temporal and environmental groups and scores each', function () {
    $v = CvssVector::parse(V3_CRITICAL.'/E:P/RL:O/MAV:L/CR:L');

    expect($v)->not->toBeNull()
        ->and($v->version())->toBe('3.1')
        ->and($v->baseVector())->toBe(V3_CRITICAL)
        ->and($v->temporal())->toBe(['E' => 'P', 'RL' => 'O'])
        ->and($v->environmental())->toBe(['CR' => 'L', 'MAV' => 'L'])
        ->and($v->baseScore())->toBe(9.8)
        ->and($v->temporalScore())->toBe(8.8)
        ->and($v->environmentalScore())->toBe((new CvssCalculator)->environmental(V3_CRITICAL, ['E' => 'P', 'RL' => 'O', 'MAV' => 'L', 'CR' => 'L'])['score'])
        ->and($v->score())->toBe($v->environmentalScore())
        ->and((string) $v)->toBe(V3_CRITICAL.'/E:P/RL:O/CR:L/MAV:L');
});

it('keeps the base score while temporal and environmental metrics change it', function () {
    $v = CvssVector::parse(V3_CRITICAL);

    $temporal = $v->withTemporal(['E' => 'P', 'RL' => 'O']);
    $environmental = $temporal->withEnvironmental(['MAV' => 'L', 'CR' => 'L']);

    expect($v->score())->toBe(9.8)
        ->and($temporal->baseScore())->toBe(9.8)
        ->and($temporal->temporalScore())->toBe(8.8)
        ->and($temporal->score())->toBe(8.8)
        ->and($environmental->baseScore())->toBe(9.8)
        ->and($environmental->temporalScore())->toBe(8.8)
        ->and($environmental->environmentalScore())->toBeLessThan(8.8)
        ->and($environmental->baseVector())->toBe(V3_CRITICAL)
        ->and($environmental->withoutModifiers()->equals($v))->toBeTrue()
        ->and($environmental->withoutEnvironmental()->equals($temporal))->toBeTrue()
        // X / null unsets a modifier
        ->and($temporal->withTemporal(['RL' => 'X'])->temporal())->toBe(['E' => 'P'])
        ->and($temporal->withTemporal(['E' => null])->temporal())->toBe(['RL' => 'O']);
});

it('merges another vector\'s modifiers onto this base — and the other way round with keepBase false', function () {
    $mine = CvssVector::parse(V3_CRITICAL.'/E:U/CR:H');
    $theirs = 'CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L/E:F/RL:W/MAV:A';

    $merged = $mine->merge($theirs);
    expect($merged->baseVector())->toBe(V3_CRITICAL)
        ->and($merged->temporal())->toBe(['E' => 'F', 'RL' => 'W'])   // theirs win, RL added
        ->and($merged->environmental())->toBe(['CR' => 'H', 'MAV' => 'A']) // mine kept where they're silent
        ->and($merged->baseScore())->toBe(9.8);

    $flipped = $mine->merge($theirs, keepBase: false);
    expect($flipped->baseVector())->toBe('CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L')
        ->and($flipped->temporal())->toBe(['E' => 'U', 'RL' => 'W']);  // mine win on the other's base

    $filled = $mine->fill($theirs);
    expect($filled->temporal())->toBe(['E' => 'U', 'RL' => 'W'])       // mine kept, gaps filled
        ->and($filled->environmental())->toBe(['CR' => 'H', 'MAV' => 'A']);
});

it('uses the temporal equation for temporal-only modifiers and the 3.0 formula for 3.0 vectors', function () {
    // Scope-changed: the environmental equation's modified-impact term differs
    // from the base one, so routing a temporal-only set through it is 0.1 off.
    $scoped = CvssVector::parse('CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H');
    expect($scoped->baseScore())->toBe(9.6)
        ->and($scoped->withTemporal(['E' => 'P', 'RL' => 'O'])->temporalScore())->toBe(8.6)
        ->and($scoped->withTemporal(['E' => 'H'])->temporalScore())->toBe(9.6)
        ->and($scoped->withTemporal(['E' => 'H'])->score())->toBe(9.6);

    $v2 = CvssVector::parse('AV:L/AC:L/Au:N/C:C/I:C/A:C');
    expect($v2->withTemporal(['E' => 'H'])->temporalScore())->toBe(7.2);

    // v3.0 keeps its own scope-changed modified-impact term and its prefix.
    $v30 = CvssVector::parse('CVSS:3.0/AV:P/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:H');
    $env = $v30->withEnvironmental(['MAV' => 'N']);
    expect($env->environmentalScore())->toBe(7.6)
        ->and((string) $env)->toStartWith('CVSS:3.0/')
        ->and(CvssVector::parse('CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:H')->withEnvironmental(['MAV' => 'N'])->environmentalScore())->toBe(7.7);

    // v4: a base score never includes the threat metric the vector carries.
    $v4 = CvssVector::parse('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U');
    expect($v4->baseScore())->toBe(9.3)->and($v4->score())->toBe(8.1)
        ->and((new CvssCalculator)->baseScore((string) $v4))->toBe(9.3);
});

it('refuses to merge across CVSS versions and rejects illegal metrics loudly', function () {
    $v3 = CvssVector::parse(V3_CRITICAL);

    expect(fn () => $v3->merge(V4_CRITICAL))->toThrow(InvalidArgumentException::class, 'v4.0')
        ->and(fn () => $v3->withTemporal(['MAV' => 'L']))->toThrow(InvalidArgumentException::class, 'environmental')
        ->and(fn () => $v3->withEnvironmental(['E' => 'P']))->toThrow(InvalidArgumentException::class, 'temporal')
        ->and(fn () => $v3->with(['E' => 'Z']))->toThrow(InvalidArgumentException::class, "Illegal value 'Z'")
        ->and(fn () => $v3->with(['NOPE' => 'H']))->toThrow(InvalidArgumentException::class, 'Unknown')
        ->and(fn () => $v3->with(['AV' => 'X']))->toThrow(InvalidArgumentException::class, 'cannot be unset')
        ->and(fn () => $v3->merge('garbage'))->toThrow(InvalidArgumentException::class, 'not a valid');
    // Unparseable input is null, never a partially scored object.
    expect(CvssVector::parse('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:Z/I:H/A:H'))->toBeNull()
        ->and(CvssVector::parse('CVSS:3.1/AV:N/AC:L'))->toBeNull()
        ->and(CvssVector::parse(V4_CRITICAL.'/E:Z'))->toBeNull();
});

it('scores CVSS v4 threat and environmental groups and passes supplemental metrics through', function () {
    $v = CvssVector::parse(V4_CRITICAL.'/E:P/U:Green');

    expect($v->baseScore())->toBe(9.3)
        ->and($v->threatScore())->toBe(8.9)
        ->and($v->temporal())->toBe(['E' => 'P'])
        ->and($v->supplemental())->toBe(['U' => 'GREEN'])
        ->and((string) $v)->toBe(V4_CRITICAL.'/E:P/U:Green')
        ->and($v->withEnvironmental(['MAV' => 'P'])->environmentalScore())->toBeLessThan(8.9)
        ->and($v->merge(V4_CRITICAL.'/E:U/MVC:N')->toString())->toBe(V4_CRITICAL.'/E:U/MVC:N/U:Green');
});

it('implements the CVSS v2 equations to the specification\'s worked example', function () {
    // CVE-2002-0392 from the v2 guide: base 7.8, temporal 6.4, environmental 9.2.
    $v = CvssVector::parse('AV:N/AC:L/Au:N/C:N/I:N/A:C');

    expect($v->version())->toBe('2.0')
        ->and($v->baseScore())->toBe(7.8)
        ->and($v->withTemporal(['E' => 'F', 'RL' => 'OF', 'RC' => 'C'])->temporalScore())->toBe(6.4)
        ->and($v->withTemporal(['E' => 'F', 'RL' => 'OF', 'RC' => 'C'])
            ->withEnvironmental(['CDP' => 'H', 'TD' => 'H', 'CR' => 'M', 'IR' => 'M', 'AR' => 'H'])
            ->environmentalScore())->toBe(9.2)
        ->and((string) $v->withTemporal(['E' => 'POC']))->toBe('AV:N/AC:L/Au:N/C:N/I:N/A:C/E:POC')
        ->and(Cvss2::baseScore('(AV:N/AC:L/Au:N/C:C/I:C/A:C)'))->toBe(10.0)
        ->and(Cvss2::baseScore('AV:N/AC:L/Au:N/C:N/I:N/A:N'))->toBe(0.0)
        ->and(Cvss2::temporalScore(V2_HIGH, ['E' => 'ZZ']))->toBeNull()
        ->and((new CvssCalculator)->baseScore(V2_HIGH))->toBe(7.5)
        ->and((new CvssCalculator)->temporalScore(V4_CRITICAL, ['E' => 'P']))->toBe(8.9);
});

it('ships a representative base vector for every reachable score of every version', function () {
    $calc = new CvssCalculator;
    foreach ([2 => CvssVectorTable::V2, 3 => CvssVectorTable::V3, 4 => CvssVectorTable::V4] as $version => $table) {
        expect(count($table))->toBeGreaterThan(60);
        foreach ($table as $score => $vector) {
            expect($calc->baseScore($vector))->toBe((float) $score, "v{$version} {$score}: {$vector}")
                ->and(CvssVector::majorVersionOf($vector))->toBe($version);
        }
    }

    expect(CvssVectorTable::vectorFor(3, 9.8))->toBe(V3_CRITICAL)
        ->and(CvssVectorTable::vectorFor(3, 7.5))->toBe('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N')
        ->and(CvssVectorTable::vectorFor(4, 9.3))->toBe(V4_CRITICAL)
        ->and(CvssVectorTable::vectorFor(2, 7.5))->toBe(V2_HIGH)
        ->and(CvssVectorTable::isExact(3, 7.5))->toBeTrue()
        // A score no base vector produces (temporal/environmental figures) maps to the nearest one, ties upward.
        ->and(CvssVectorTable::isExact(3, 9.7))->toBeFalse()
        ->and($calc->baseScore(CvssVectorTable::vectorFor(3, 9.7)))->toBe(9.8)
        ->and(CvssVectorTable::vectorFor(3, 11.0))->toBeNull()
        ->and(CvssVectorTable::vectorFor(5, 5.0))->toBeNull()
        ->and(CvssVector::fromScore(4, 9.3)?->toString())->toBe(V4_CRITICAL);
});
