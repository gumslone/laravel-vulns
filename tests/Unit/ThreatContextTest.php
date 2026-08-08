<?php

use Gumslone\Vulns\ChangeImpact;
use Gumslone\Vulns\ChangeType;
use Gumslone\Vulns\Data\VulnerabilityData;
use Gumslone\Vulns\ExploitMaturity;

it('derives exploit maturity from reference evidence the sources already deliver', function () {
    $clean = new VulnerabilityData(vulnId: 'CVE-2030-10', source: 'nvd', references: [
        ['type' => 'Vendor Advisory', 'url' => 'https://example.com/advisory'],
    ]);
    expect($clean->exploitMaturity())->toBe(ExploitMaturity::None)
        ->and($clean->exploitReferences())->toBe([]);

    // NVD tags exploit references; OSV marks proof links EVIDENCE.
    $poc = new VulnerabilityData(vulnId: 'CVE-2030-10', source: 'nvd', references: [
        ['type' => 'Exploit,Third Party Advisory', 'url' => 'https://example.com/poc-writeup'],
    ]);
    expect($poc->exploitMaturity())->toBe(ExploitMaturity::Poc);

    $evidence = new VulnerabilityData(vulnId: 'CVE-2030-10', source: 'osv', references: [
        ['type' => 'EVIDENCE', 'url' => 'https://github.com/x/y/issues/1'],
    ]);
    expect($evidence->exploitMaturity())->toBe(ExploitMaturity::Poc);

    // A Metasploit module means point-and-click exploitation.
    $weaponized = new VulnerabilityData(vulnId: 'CVE-2030-10', source: 'nvd', references: [
        ['type' => 'Exploit', 'url' => 'https://www.exploit-db.com/exploits/12345'],
        ['type' => null, 'url' => 'https://www.rapid7.com/db/modules/exploit/multi/http/thing'],
    ]);
    expect($weaponized->exploitMaturity())->toBe(ExploitMaturity::Weaponized)
        ->and($weaponized->exploitReferences())->toHaveCount(2);
});

it('answers reachability questions from the stored CVSS vectors', function () {
    $network = new VulnerabilityData(vulnId: 'CVE-2030-11', source: 'nvd',
        cvssV3Vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
    expect($network->attackVector())->toBe('network')
        ->and($network->isNetworkExploitable())->toBeTrue()
        ->and($network->requiresUserInteraction())->toBeFalse()
        ->and($network->requiresPrivileges())->toBeFalse();

    $local = new VulnerabilityData(vulnId: 'CVE-2030-11', source: 'nvd',
        cvssV4Vector: 'CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N');
    expect($local->attackVector())->toBe('local')
        ->and($local->isNetworkExploitable())->toBeFalse()
        ->and($local->requiresUserInteraction())->toBeTrue()
        ->and($local->requiresPrivileges())->toBeTrue();

    // v2 has no UI metric — unknown must stay null, not read as false.
    $v2only = new VulnerabilityData(vulnId: 'CVE-2030-11', source: 'nvd',
        cvssV2Vector: 'AV:N/AC:L/Au:N/C:P/I:P/A:P');
    expect($v2only->attackVector())->toBe('network')
        ->and($v2only->requiresUserInteraction())->toBeNull()
        ->and($v2only->requiresPrivileges())->toBeFalse();

    $unscored = new VulnerabilityData(vulnId: 'CVE-2030-11', source: 'osv');
    expect($unscored->attackVector())->toBeNull()
        ->and($unscored->isNetworkExploitable())->toBeFalse();
});

it('classifies exploit publication and withdrawal as major changes', function () {
    $before = new VulnerabilityData(vulnId: 'CVE-2030-12', source: 'nvd', references: [
        ['type' => 'Vendor Advisory', 'url' => 'https://example.com/advisory'],
    ]);

    $pocDropped = new VulnerabilityData(vulnId: 'CVE-2030-12', source: 'nvd', references: [
        ['type' => 'Vendor Advisory', 'url' => 'https://example.com/advisory'],
        ['type' => 'Exploit', 'url' => 'https://www.exploit-db.com/exploits/9'],
    ]);
    $change = $pocDropped->changesSince($before);
    expect($change->has(ChangeType::ExploitPublished))->toBeTrue()
        ->and($change->impact())->toBe(ChangeImpact::Major)
        ->and($change->details['exploit_maturity'])->toBe(['none', 'poc']);

    $withdrawn = new VulnerabilityData(vulnId: 'CVE-2030-12', source: 'nvd', isWithdrawn: true, references: [
        ['type' => 'Vendor Advisory', 'url' => 'https://example.com/advisory'],
    ]);
    expect($withdrawn->changesSince($before)->has(ChangeType::Withdrawn))->toBeTrue()
        ->and($withdrawn->changesSince($before)->impact())->toBe(ChangeImpact::Major);
});

it('exposes KEV context and withdrawn state in toArray', function () {
    $v = new VulnerabilityData(
        vulnId: 'CVE-2030-13', source: 'nvd',
        isKnownExploited: true,
        kevSince: new DateTimeImmutable('2030-02-01'),
        kevDueDate: new DateTimeImmutable('2030-02-22'),
        usedInRansomware: true,
        isWithdrawn: false,
        isDisputed: true,
        references: [['type' => 'Exploit', 'url' => 'https://www.exploit-db.com/exploits/1']],
    );

    $arr = $v->toArray();
    expect($arr['kev_since'])->toBe('2030-02-01')
        ->and($arr['kev_due_date'])->toBe('2030-02-22')
        ->and($arr['used_in_ransomware'])->toBeTrue()
        ->and($arr['is_disputed'])->toBeTrue()
        ->and($arr['exploit_maturity'])->toBe('poc');
});
