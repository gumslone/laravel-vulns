<?php

/*
 * Self-hosted cve-search / Vulnerability-Lookup instances spell the flat
 * record's keys in camelCase and send `cwe` as a list. Both used to lose the
 * vectors — and the list made every lookup throw, so no CVE arrived at all.
 */

use Gumslone\Vulns\Data\PackageData;
use Gumslone\Vulns\Sources\CveSearchSource;
use Gumslone\Vulns\Support\CpeResolver;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;

function cveSearchWith(array $records): CveSearchSource
{
    $client = new Client(['handler' => HandlerStack::create(new MockHandler([
        new Response(200, [], json_encode(['results' => $records, 'total_count' => count($records)])),
    ]))]);

    return new CveSearchSource(new CpeResolver, null, $client);
}

it('reads camelCase vector keys and list-valued cwe from newer instances', function () {
    $grpc = new PackageData(name: 'grpc', version: '1.76.0', ecosystem: 'github', cpe23: 'cpe:2.3:a:grpc:grpc:1.76.0:*:*:*:*:*:*:*');

    $vulns = cveSearchWith([
        [
            'id' => 'CVE-2017-7860', 'summary' => 'Out-of-bounds read in gRPC', 'cwe' => ['CWE-125', 'NVD-CWE-Other'],
            'cvss' => 7.5, 'cvssVector' => 'AV:N/AC:L/Au:N/C:P/I:P/A:P',
            'published' => '2017-06-09T14:29:00', 'lastModified' => '2019-10-03T00:03:00', 'references' => ['https://x.test/a'],
        ],
        [
            'id' => 'CVE-2030-1', 'summary' => 'Newer record', 'cwe' => [['id' => 'CWE-400']],
            'cvss3' => 9.8, 'cvss3Vector' => 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
            'cvss4Vector' => 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N',
        ],
        // classic spelling still works
        ['id' => 'CVE-2030-2', 'summary' => 'Classic', 'cwe' => 'CWE-79', 'cvss3' => 6.1, 'cvss3-vector' => 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N', 'Published' => '2030-01-01T00:00:00'],
        // a garbage date or cwe must not drop the CVE
        ['id' => 'CVE-2030-3', 'summary' => 'Odd', 'cwe' => 'Unknown', 'cvss' => 'n/a', 'Published' => 'never'],
    ])->queryPackage($grpc);

    expect($vulns)->toHaveCount(4);
    [$old, $new, $classic, $odd] = $vulns;

    expect($old->cvssV2Score)->toBe(7.5)
        ->and($old->cvssV2Vector)->toBe('AV:N/AC:L/Au:N/C:P/I:P/A:P')
        ->and($old->isInferred('cvss_v2_vector'))->toBeFalse()
        ->and($old->cwes)->toBe(['CWE-125'])
        ->and($old->sourcePublishedAt?->format('Y-m-d'))->toBe('2017-06-09')
        ->and($old->sourceModifiedAt?->format('Y-m-d'))->toBe('2019-10-03')
        ->and($new->cvssV3Vector)->toBe('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')
        ->and($new->cvssV4Vector)->toBe('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N')
        ->and($new->cvssV4Score)->toBe(9.3)
        ->and($new->cwes)->toBe(['CWE-400'])
        ->and($classic->cvssV3Vector)->toBe('CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N')
        ->and($classic->cwes)->toBe(['CWE-79'])
        ->and($odd->cwes)->toBe([])
        ->and($odd->cvssV2Score)->toBeNull()
        ->and($odd->sourcePublishedAt)->toBeNull();
});
