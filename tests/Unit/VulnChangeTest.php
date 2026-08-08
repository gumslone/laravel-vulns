<?php

use Gumslone\Vulns\ChangeImpact;
use Gumslone\Vulns\ChangeType;
use Gumslone\Vulns\Data\VulnerabilityData;
use Gumslone\Vulns\Severity;
use Gumslone\Vulns\VulnChange;

function snapshot(array $overrides = []): VulnerabilityData
{
    return new VulnerabilityData(...array_merge([
        'vulnId' => 'CVE-2030-100',
        'source' => 'osv',
        'summary' => 'Original wording.',
        'severity' => Severity::Medium,
        'cvssV3Score' => 5.0,
    ], $overrides));
}

it('classifies a score increase as major', function () {
    $change = snapshot(['cvssV3Score' => 8.1, 'severity' => Severity::High])
        ->changesSince(snapshot());

    expect($change->isMajor())->toBeTrue()
        ->and($change->has(ChangeType::ScoreIncreased))->toBeTrue()
        ->and($change->has(ChangeType::SeverityRaised))->toBeTrue()
        ->and($change->details['cvss_v3_score'])->toBe([5.0, 8.1])
        ->and($change->summary())->toContain('score increased (5 → 8.1)');
});

it('classifies a downgrade as major too — it can release an SLA-tracked assessment', function () {
    $change = snapshot(['cvssV3Score' => 3.1, 'severity' => Severity::Low])
        ->changesSince(snapshot());

    expect($change->impact())->toBe(ChangeImpact::Major)
        ->and($change->has(ChangeType::ScoreDecreased))->toBeTrue()
        ->and($change->has(ChangeType::SeverityLowered))->toBeTrue();
});

it('classifies a rewritten description alone as minor', function () {
    $change = snapshot(['summary' => 'Clarified wording.'])->changesSince(snapshot());

    expect($change->impact())->toBe(ChangeImpact::Minor)
        ->and($change->has(ChangeType::DescriptionUpdated))->toBeTrue()
        ->and($change->isMajor())->toBeFalse();
});

it('reports no changes for identical snapshots', function () {
    $change = snapshot()->changesSince(snapshot());

    expect($change->hasChanges())->toBeFalse()
        ->and($change->impact())->toBe(ChangeImpact::None)
        ->and($change->summary())->toBe('no changes');
});

it('treats a first-time score as an increase and a dropped score as no rescore', function () {
    $scored = snapshot()->changesSince(snapshot(['cvssV3Score' => null, 'severity' => Severity::Unknown]));
    expect($scored->has(ChangeType::ScoreIncreased))->toBeTrue()
        ->and($scored->has(ChangeType::SeverityRaised))->toBeTrue();

    // value → null is upstream data loss, not a rescore
    $dropped = snapshot(['cvssV3Score' => null])->changesSince(snapshot());
    expect($dropped->has(ChangeType::ScoreDecreased))->toBeFalse();
});

it('flags a fix appearing and range edits as major', function () {
    $change = snapshot([
        'isFixed' => true,
        'fixedVersions' => ['4.17.21'],
        'affectedRanges' => [['range' => '< 4.17.21']],
    ])->changesSince(snapshot(['affectedRanges' => [['range' => '< 5.0']]]));

    expect($change->isMajor())->toBeTrue()
        ->and($change->has(ChangeType::FixAvailable))->toBeTrue()
        ->and($change->has(ChangeType::RangesChanged))->toBeTrue()
        ->and($change->details['fixed_versions'])->toBe([[], ['4.17.21']]);
});

it('ignores reference reordering but catches real reference additions', function () {
    $reordered = snapshot(['references' => ['https://b', 'https://a']])
        ->changesSince(snapshot(['references' => ['https://a', 'https://b']]));
    expect($reordered->hasChanges())->toBeFalse();

    $added = snapshot(['references' => ['https://a', 'https://c']])
        ->changesSince(snapshot(['references' => ['https://a']]));
    expect($added->impact())->toBe(ChangeImpact::Minor)
        ->and($added->has(ChangeType::ReferencesUpdated))->toBeTrue();
});
