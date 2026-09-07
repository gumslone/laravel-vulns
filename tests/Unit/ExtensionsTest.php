<?php

use Gumslone\Vulns\ChangeType;
use Gumslone\Vulns\Data\PackageData;
use Gumslone\Vulns\Data\VulnerabilityData;
use Gumslone\Vulns\ExploitMaturity;
use Gumslone\Vulns\Severity;
use Gumslone\Vulns\Sources\MitreCveSource;
use Gumslone\Vulns\Support\VersionRange;
use Gumslone\Vulns\Testing\FakeSource;
use Gumslone\Vulns\VulnSearch;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;

it('round-trips a record through toArray() and fromArray(), re-deriving what was inferred', function () {
    $original = new VulnerabilityData(
        vulnId: 'GHSA-aaaa-bbbb-cccc', source: 'github', summary: 'Prototype pollution', severity: 'high',
        cvssV3Score: 7.5, epssScore: 0.42, isKnownExploited: true, kevSince: new DateTimeImmutable('2030-01-02'),
        ssvc: ['exploitation' => 'poc'], aliases: ['CVE-2030-40'], affectedRanges: [['range' => '< 2.0']],
        references: [['type' => 'WEB', 'url' => 'https://example.test']], cwes: ['CWE-1321'], isFixed: true,
        fixedVersions: ['2.0.0'], sourceModifiedAt: new DateTimeImmutable('2030-03-04 05:06:07'), extra: ['ghsa_id' => 'GHSA-aaaa-bbbb-cccc'],
    );

    $restored = VulnerabilityData::fromArray($original->toArray());

    expect($restored->toArray())->toBe($original->toArray())
        ->and($restored->isInferred('cvss_v3_vector'))->toBeTrue()
        ->and($restored->reported('cvss_v3_vector'))->toBeNull()
        ->and($restored->kevSince?->format('Y-m-d'))->toBe('2030-01-02')
        ->and($restored->sourceModifiedAt?->format('Y-m-d H:i:s'))->toBe('2030-03-04 05:06:07')
        ->and($restored->changesSince($original)->hasChanges())->toBeFalse();

    // camelCase keys (a JSON-serialised object) work too; vuln_id is required.
    expect(VulnerabilityData::fromArray(['vulnId' => 'CVE-2030-41', 'source' => 'nvd', 'cvssV3Score' => 9.8])->severity)->toBe(Severity::Critical)
        ->and(fn () => VulnerabilityData::fromArray(['source' => 'nvd']))->toThrow(InvalidArgumentException::class, 'vuln_id');
});

it('reads CISA SSVC decision points off the CVE record and treats "active" as exploited', function () {
    $mock = new MockHandler([new Response(200, [], json_encode([
        'cveMetadata' => ['cveId' => 'CVE-2024-3094', 'state' => 'PUBLISHED'],
        'containers' => [
            'cna' => ['descriptions' => [['lang' => 'en', 'value' => 'Backdoor in xz.']]],
            'adp' => [[
                'title' => 'CISA ADP Vulnrichment',
                'metrics' => [['other' => ['type' => 'ssvc', 'content' => [
                    'timestamp' => '2024-04-01T00:00:00.000000Z', 'version' => '2.0.3', 'role' => 'CISA Coordinator',
                    'options' => [['Exploitation' => 'active'], ['Automatable' => 'No'], ['Technical Impact' => 'Total']],
                ]]]],
            ]],
        ],
    ]))]);
    $source = new MitreCveSource(new Client(['handler' => HandlerStack::create($mock)]));

    $vuln = $source->fetchById('CVE-2024-3094');

    expect($vuln->ssvc)->toBe([
        'exploitation' => 'active', 'automatable' => 'no', 'technical_impact' => 'total',
        'version' => '2.0.3', 'timestamp' => '2024-04-01T00:00:00.000000Z', 'role' => 'CISA Coordinator',
    ])
        ->and($vuln->isKnownExploited)->toBeFalse()
        ->and($vuln->isActivelyExploited())->toBeTrue()
        ->and($vuln->exploitMaturity())->toBe(ExploitMaturity::Weaponized)
        ->and($vuln->toArray()['ssvc']['exploitation'])->toBe('active');

    // First sight of active exploitation is a re-triage trigger, KEV or not.
    $stored = VulnerabilityData::fromArray(['vuln_id' => 'CVE-2024-3094', 'source' => 'mitre']);
    $change = $vuln->changesSince($stored);
    expect($change->has(ChangeType::KnownExploited))->toBeTrue()->and($change->isMajor())->toBeTrue();

    // The merge keeps SSVC from whichever record carries it.
    $plain = new VulnerabilityData(vulnId: 'CVE-2024-3094', source: 'osv');
    $merged = (new VulnSearch([new FakeSource('osv', ['xz' => [$plain]]), new FakeSource('mitre', ['xz' => [$vuln]])]))
        ->search(new PackageData(name: 'xz', version: '5.6.0', ecosystem: 'generic'))[0];
    expect($merged->source)->toBe('osv')->and($merged->ssvc['exploitation'])->toBe('active');
});

it('recognises malicious packages by id, Snyk type or OSV origin marker', function () {
    expect((new VulnerabilityData(vulnId: 'MAL-2024-1', source: 'osv'))->isMalware())->toBeTrue()
        ->and((new VulnerabilityData(vulnId: 'GHSA-x', source: 'osv', aliases: ['MAL-2024-2']))->isMalware())->toBeTrue()
        ->and((new VulnerabilityData(vulnId: 'SNYK-JS-X-1', source: 'snyk', extra: ['type' => 'malware']))->isMalware())->toBeTrue()
        ->and((new VulnerabilityData(vulnId: 'GHSA-y', source: 'osv', extra: ['database_specific' => ['malicious-packages-origins' => [['source' => 'ossf']]]]))->isMalware())->toBeTrue()
        ->and((new VulnerabilityData(vulnId: 'CVE-2030-1', source: 'nvd'))->isMalware())->toBeFalse()
        ->and((new VulnerabilityData(vulnId: 'CVE-2030-1', source: 'nvd'))->toArray()['is_malware'])->toBeFalse();
});

it('recommends the lowest fix at or above the current version, same major line first', function () {
    $fixes = ['4.17.21', '5.0.1', '3.10.2'];

    expect(VersionRange::recommendedFix('4.17.20', $fixes))->toBe('4.17.21')
        ->and(VersionRange::recommendedFix('4.17.21', $fixes))->toBe('4.17.21')
        ->and(VersionRange::recommendedFix('4.18.0', $fixes))->toBe('5.0.1')      // past the 4.x fix → next line
        ->and(VersionRange::recommendedFix('3.9.0', $fixes))->toBe('3.10.2')
        ->and(VersionRange::recommendedFix('6.0.0', $fixes))->toBeNull()          // already past every fix
        ->and(VersionRange::recommendedFix(null, $fixes))->toBe('3.10.2')         // unknown current → lowest fix
        ->and(VersionRange::recommendedFix('1:4.17.20', $fixes))->toBe('3.10.2')  // uncomparable current → lowest fix
        ->and(VersionRange::recommendedFix('4.17.20', ['v4.17.21']))->toBe('v4.17.21')
        ->and(VersionRange::recommendedFix('4.17.20', ['2.x', 'latest']))->toBeNull()
        ->and(VersionRange::recommendedFix('4.17.20', []))->toBeNull();
});

it('reports per-package coverage so "nothing found" can be told from "not covered"', function () {
    $mapped = new PackageData(name: 'lodash', version: '4.17.20', ecosystem: 'npm', purl: 'pkg:npm/lodash@4.17.20');
    $unmapped = new PackageData(name: 'thing', version: '1.0', ecosystem: 'nonesuch');

    $picky = new class('picky') extends FakeSource
    {
        public function supports(PackageData $package): bool
        {
            return $package->ecosystem === 'npm';
        }
    };
    $search = new VulnSearch([
        new FakeSource('osv'),
        $picky,
        (new FakeSource('nvd'))->failing('503'),
        new FakeSource('off', enabled: false),
    ]);

    $results = $search->searchBatch(['a' => $mapped, 'b' => $unmapped]);

    expect($results)->toBe(['a' => [], 'b' => []])
        ->and($search->coverage()['a'])->toBe(['queried' => ['osv', 'picky'], 'skipped' => [], 'failed' => ['nvd']])
        ->and($search->coverage()['b'])->toBe(['queried' => ['osv'], 'skipped' => ['picky'], 'failed' => ['nvd']])
        ->and($search->errors())->toBe(['nvd' => '503']);
});

it('ships a FakeSource that answers by name or purl and can be made to fail', function () {
    $vuln = new VulnerabilityData(vulnId: 'CVE-2030-50', source: 'fake', aliases: ['GHSA-zzzz-zzzz-zzzz']);
    $source = new FakeSource('fake', ['pkg:npm/lodash@4.17.20' => [$vuln]]);

    expect($source->queryPackage(PackageData::fromPurl('pkg:npm/lodash@4.17.20')))->toBe([$vuln])
        ->and($source->queryPackage(new PackageData(name: 'other', version: '1', ecosystem: 'npm')))->toBe([])
        ->and($source->fetchById('ghsa-zzzz-zzzz-zzzz'))->toBe($vuln)
        ->and($source->fetchById('CVE-2030-51'))->toBeNull()
        ->and(fn () => $source->failing('down')->fetchById('CVE-2030-50'))->toThrow(RuntimeException::class, 'down');
});
