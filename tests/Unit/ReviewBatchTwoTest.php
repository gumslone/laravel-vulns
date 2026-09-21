<?php

/*
 * v1.18 review batch: CVSS v4 rounding, one validation table for every vector
 * parser, link allow-listing in the record, and three source mapping bugs.
 */

use Gumslone\Vulns\Data\PackageData;
use Gumslone\Vulns\Data\VulnerabilityData;
use Gumslone\Vulns\Severity;
use Gumslone\Vulns\Sources\GitHubAdvisorySource;
use Gumslone\Vulns\Sources\NvdSource;
use Gumslone\Vulns\Sources\SnykSource;
use Gumslone\Vulns\Support\CpeResolver;
use Gumslone\Vulns\Support\Cvss2;
use Gumslone\Vulns\Support\Cvss4;
use Gumslone\Vulns\Support\CvssCalculator;
use Gumslone\Vulns\Support\CvssVector;
use Gumslone\Vulns\Support\PurlBuilder;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;

function b2Client(array $responses): Client
{
    return new Client(['handler' => HandlerStack::create(new MockHandler($responses))]);
}

it('rounds CVSS v4 scores that are exactly x.x5 up, like the reference calculator', function () {
    expect(Cvss4::baseScore('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:L/VA:N/SC:H/SI:H/SA:H'))->toBe(8.6)
        ->and(Cvss4::vectorScore('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:L/E:U'))->toBe(9.1)
        // the well-known anchors are unchanged
        ->and(Cvss4::baseScore('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H'))->toBe(10.0)
        ->and(Cvss4::baseScore('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N'))->toBe(9.3)
        ->and(Cvss4::baseScore('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N'))->toBe(0.0);
});

it('validates vectors identically in every parser', function () {
    $calc = new CvssCalculator;
    $v3 = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';
    $v4 = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N';
    $v2 = 'AV:N/AC:L/Au:N/C:P/I:P/A:P';

    // Illegal values are malformed vectors — never a neighbouring level.
    foreach (["{$v4}/E:Z", str_replace('AV:N', 'AV:Z', $v4), str_replace('UI:N', 'UI:R', $v4), str_replace('SC:N', 'SC:S', $v4)] as $bad) {
        expect(Cvss4::vectorScore($bad))->toBeNull()->and(CvssVector::parse($bad))->toBeNull();
    }
    expect($calc->baseScore("{$v3}/E:Z"))->toBeNull()
        ->and($calc->baseScore('CVSS:3.2/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'))->toBeNull()
        ->and(CvssVector::parse('CVSS:3.2/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'))->toBeNull();

    // A repeated metric is malformed, not "last one wins".
    expect($calc->baseScore("{$v3}/AV:P"))->toBeNull()
        ->and(CvssVector::parse("{$v3}/AV:P"))->toBeNull()
        ->and(Cvss4::baseScore("{$v4}/AV:P"))->toBeNull()
        ->and(Cvss2::baseScore("{$v2}/AV:L"))->toBeNull();

    // Case and a trailing slash are tolerated everywhere.
    expect(Cvss4::baseScore(strtolower($v4).'/'))->toBe(9.3)
        ->and(CvssVector::parse(strtolower($v4).'/')?->baseScore())->toBe(9.3)
        ->and($calc->baseScore(strtolower($v3).'/'))->toBe(9.8)
        ->and(CvssVector::parse(strtolower($v3).'/')?->baseScore())->toBe(9.8);
});

it('rejects illegal v3 modifier values instead of scoring them, without warnings', function () {
    $calc = new CvssCalculator;
    $v3 = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';

    expect($calc->temporalScore($v3, ['E' => 'Z']))->toBeNull()
        ->and($calc->temporalScore($v3, ['E' => ['a']]))->toBeNull()
        ->and($calc->environmental($v3, ['MAV' => 'Z']))->toBeNull()
        ->and($calc->environmental($v3, ['CR' => 'Q']))->toBeNull()
        // "not defined" spellings are no-ops; lowercase keys work like on v2/v4
        ->and($calc->temporalScore($v3, ['E' => null, 'RL' => 'X', 'RC' => '']))->toBe(9.8)
        ->and($calc->temporalScore($v3, ['e' => 'u']))->toBe(9.0)
        ->and($calc->environmental($v3, ['mav' => 'l'])['vector'])->toContain('MAV:L');
});

it('keeps only links a consumer can render, and only real scores', function () {
    $vuln = new VulnerabilityData(
        vulnId: 'CVE-2030-70', source: 'osv', cvssV3Score: 11.0, cvssV2Score: -1.0, severity: 'high',
        references: [
            ['type' => 'WEB', 'url' => 'https://example.test/advisory'],
            ['type' => 'WEB', 'url' => 'javascript:alert(1)'],
            ['type' => 'WEB', 'url' => ' JaVaScRiPt:alert(1)'],
            'data:text/html;base64,PHNjcmlwdD4=',
            'ftp://patches.example.test/fix.tar.gz',
            ['type' => 'PACKAGE', 'url' => ''],
        ],
        sourceUrl: 'javascript:alert(document.cookie)',
    );

    expect(array_map(fn ($r) => is_array($r) ? $r['url'] : $r, $vuln->references))
        ->toBe(['https://example.test/advisory', 'ftp://patches.example.test/fix.tar.gz', ''])
        ->and($vuln->sourceUrl)->toBe('https://nvd.nist.gov/vuln/detail/CVE-2030-70')
        ->and($vuln->isInferred('source_url'))->toBeTrue()
        ->and($vuln->cvssV3Score)->toBeNull()
        ->and($vuln->cvssV3Vector)->toBeNull()
        ->and($vuln->cvssV2Score)->toBeNull()
        ->and($vuln->severity)->toBe(Severity::High);
});

it('NVD prefers the Primary assessment over a CNA Secondary one listed first', function () {
    $nvd = new NvdSource(new CpeResolver, null, b2Client([new Response(200, [], json_encode(['vulnerabilities' => [['cve' => [
        'id' => 'CVE-2030-80',
        'descriptions' => [['lang' => 'en', 'value' => 'x']],
        'metrics' => ['cvssMetricV31' => [
            ['type' => 'Secondary', 'cvssData' => ['baseScore' => 5.3, 'vectorString' => 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N']],
            ['type' => 'Primary', 'cvssData' => ['baseScore' => 9.8, 'vectorString' => 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H']],
        ]],
    ]]]]))]), ['rate_limit_max' => 1000]);

    expect($nvd->fetchById('CVE-2030-80')->cvssV3Score)->toBe(9.8);
});

it('Snyk files CWE ids under cwes, not as aliases of the advisory', function () {
    $snyk = new SnykSource(new PurlBuilder, b2Client([new Response(200, [], json_encode(['data' => [[
        'id' => 'SNYK-JS-LODASH-1', 'attributes' => [
            'key' => 'SNYK-JS-LODASH-1', 'title' => 'Prototype Pollution', 'effective_severity_level' => 'high',
            'problems' => [['source' => 'CVE', 'id' => 'CVE-2030-90'], ['source' => 'CWE', 'id' => 'CWE-1321'], ['source' => 'GHSA', 'id' => 'GHSA-aaaa-bbbb-cccc']],
        ],
    ]]]))]), ['api_token' => 't', 'org_id' => 'o', 'enabled' => true]);

    $vuln = $snyk->queryPackage(PackageData::fromPurl('pkg:npm/lodash@4.17.20'))[0];

    expect($vuln->vulnId)->toBe('CVE-2030-90')
        ->and($vuln->cwes)->toBe(['CWE-1321'])
        ->and($vuln->aliases)->toBe(['GHSA-aaaa-bbbb-cccc']);
});

it('GitHub reads both CVSS standards and the withdrawn stamp', function () {
    $github = new GitHubAdvisorySource(b2Client([new Response(200, [], json_encode(['data' => ['securityAdvisory' => [
        'ghsaId' => 'GHSA-aaaa-bbbb-cccc', 'summary' => 's', 'severity' => 'MODERATE', 'withdrawnAt' => '2030-01-01T00:00:00Z',
        'identifiers' => [['type' => 'GHSA', 'value' => 'GHSA-aaaa-bbbb-cccc']], 'references' => [], 'cwes' => ['nodes' => []],
        'cvssSeverities' => [
            'cvssV3' => ['score' => 0, 'vectorString' => null],
            'cvssV4' => ['score' => 9.3, 'vectorString' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N'],
        ],
    ]]]))]), ['token' => 't']);

    $vuln = $github->fetchById('GHSA-aaaa-bbbb-cccc');

    expect($vuln->cvssV4Score)->toBe(9.3)
        ->and($vuln->cvssV3Score)->toBeNull()
        ->and($vuln->severity)->toBe(Severity::Critical)
        ->and($vuln->isWithdrawn)->toBeTrue();
});
