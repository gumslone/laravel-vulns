<?php

use Gumslone\Vulns\Data\PackageData;
use Gumslone\Vulns\Data\VulnerabilityData;
use Gumslone\Vulns\Export\CycloneDxExporter;
use Gumslone\Vulns\Export\OpenVexExporter;
use Gumslone\Vulns\Export\OsvExporter;
use Gumslone\Vulns\Sources\EuvdSource;
use Gumslone\Vulns\Sources\NvdSource;
use Gumslone\Vulns\Support\ArrayCache;
use Gumslone\Vulns\Support\CpeResolver;
use Gumslone\Vulns\Support\LockfileReader;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;

function exVuln(): VulnerabilityData
{
    return new VulnerabilityData(
        vulnId: 'CVE-2030-1', source: 'osv', summary: 'Prototype pollution', details: 'Long text', aliases: ['GHSA-aaaa-bbbb-cccc'],
        cvssV3Score: 9.8, cvssV3Vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', cvssV2Score: 7.5, cwes: ['CWE-1321'],
        fixedVersions: ['4.17.21'], references: [['type' => 'EXPLOIT', 'url' => 'https://x.test/poc'], ['type' => 'FIX', 'url' => 'https://x.test/fix']],
        affectedRanges: [['type' => 'SEMVER', 'events' => [['introduced' => '0'], ['fixed' => '4.17.21']], 'product' => 'lodash'], ['range' => '< 4.17.21']],
        sourcePublishedAt: new DateTimeImmutable('2030-01-02T03:04:05Z'), sourceModifiedAt: new DateTimeImmutable('2030-02-03T04:05:06Z'),
    );
}

it('exports a record as OSV, keeping only what the source actually stated', function () {
    $osv = OsvExporter::export(exVuln());

    expect($osv['id'])->toBe('CVE-2030-1')
        ->and($osv['aliases'])->toBe(['GHSA-aaaa-bbbb-cccc'])
        ->and($osv['modified'])->toBe('2030-02-03T04:05:06Z')
        // the v2 vector was inferred for a bare score — not the source's statement
        ->and($osv['severity'])->toBe([['type' => 'CVSS_V3', 'score' => 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H']])
        ->and($osv['affected'][0]['ranges'])->toBe([['type' => 'SEMVER', 'events' => [['introduced' => '0'], ['fixed' => '4.17.21']]]])
        ->and($osv['references'])->toBe([['type' => 'WEB', 'url' => 'https://x.test/poc'], ['type' => 'FIX', 'url' => 'https://x.test/fix']])
        ->and($osv['database_specific']['version_constraints'])->toBe(['< 4.17.21'])
        ->and($osv)->not->toHaveKey('withdrawn');
});

it('exports a record as a CycloneDX vulnerability with optional VEX analysis', function () {
    $cdx = CycloneDxExporter::export(exVuln(), ['pkg:npm/lodash@4.17.20'], ['state' => 'not_affected', 'justification' => 'code_not_reachable']);

    expect($cdx['id'])->toBe('CVE-2030-1')
        ->and($cdx['ratings'][0])->toBe(['source' => ['name' => 'osv'], 'score' => 9.8, 'severity' => 'critical', 'method' => 'CVSSv31', 'vector' => 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'])
        ->and($cdx['ratings'][1])->toBe(['source' => ['name' => 'osv'], 'score' => 7.5, 'severity' => 'high', 'method' => 'CVSSv2'])
        ->and($cdx['cwes'])->toBe([1321])
        ->and($cdx['recommendation'])->toBe('Upgrade to 4.17.21.')
        ->and($cdx['affects'])->toBe([['ref' => 'pkg:npm/lodash@4.17.20']])
        ->and($cdx['analysis']['state'])->toBe('not_affected');
});

it('builds OpenVEX statements and enforces the specification\'s own rules', function () {
    $statement = OpenVexExporter::statement(exVuln(), ['pkg:npm/lodash@4.17.20'], 'not_affected', 'vulnerable_code_not_in_execute_path');
    $doc = OpenVexExporter::document([$statement], 'security@example.test');

    expect($statement['vulnerability']['name'])->toBe('CVE-2030-1')
        ->and($statement['products'])->toBe([['@id' => 'pkg:npm/lodash@4.17.20']])
        ->and($doc['@context'])->toBe('https://openvex.dev/ns/v0.2.0')
        ->and($doc['statements'])->toHaveCount(1)
        ->and(fn () => OpenVexExporter::statement(exVuln(), ['pkg:npm/x@1'], 'not_affected'))->toThrow(InvalidArgumentException::class, 'justification')
        ->and(fn () => OpenVexExporter::statement(exVuln(), ['pkg:npm/x@1'], 'affected'))->toThrow(InvalidArgumentException::class, 'action statement')
        ->and(fn () => OpenVexExporter::statement(exVuln(), ['pkg:npm/x@1'], 'meh'))->toThrow(InvalidArgumentException::class);
});

it('reads npm v1 lockfiles too and refuses files it does not know', function () {
    $dir = sys_get_temp_dir().'/vulns-lock-'.bin2hex(random_bytes(4));
    mkdir($dir);
    file_put_contents("{$dir}/package-lock.json", json_encode(['lockfileVersion' => 1, 'dependencies' => [
        'a' => ['version' => '1.0.0', 'dependencies' => ['b' => ['version' => '2.0.0', 'dev' => true]]],
        'git-dep' => ['version' => 'github:owner/repo#abc'],
    ]]));
    file_put_contents("{$dir}/other.json", json_encode(['hello' => 'world']));

    expect(array_keys(LockfileReader::read("{$dir}/package-lock.json")))->toBe(['npm:a@1.0.0', 'npm:b@2.0.0'])
        ->and(array_keys(LockfileReader::read("{$dir}/package-lock.json", includeDev: false)))->toBe(['npm:a@1.0.0'])
        ->and(fn () => LockfileReader::read("{$dir}/other.json"))->toThrow(InvalidArgumentException::class, 'Unrecognised')
        ->and(fn () => LockfileReader::read("{$dir}/missing.lock"))->toThrow(InvalidArgumentException::class, 'not found');
});

it('answers repeated product lookups from the cache — complete answers only', function () {
    $stack = function (array $responses, array &$history) {
        $s = HandlerStack::create(new MockHandler($responses));
        $s->push(Middleware::history($history));

        return new Client(['handler' => $s]);
    };
    $cve = fn (string $id) => ['cve' => ['id' => $id, 'descriptions' => [['lang' => 'en', 'value' => 'x']], 'configurations' => [['nodes' => [['cpeMatch' => [
        ['vulnerable' => true, 'criteria' => 'cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*', 'versionEndExcluding' => '2.0.0'],
    ]]]]]]];
    $widget = fn (string $version) => new PackageData(name: 'widget', version: $version, ecosystem: 'generic', cpe23: "cpe:2.3:a:acme:widget:{$version}:*:*:*:*:*:*:*");

    // One request serves every version of the product; the version filter still runs per package.
    $history = [];
    $nvd = new NvdSource(new CpeResolver, null, $stack([new Response(200, [], json_encode(['totalResults' => 1, 'vulnerabilities' => [$cve('CVE-2030-9')]]))], $history),
        ['rate_limit_max' => 1000], null, new ArrayCache);
    expect($nvd->queryPackage($widget('1.0.0')))->toHaveCount(1)
        ->and($nvd->queryPackage($widget('3.0.0')))->toBe([])
        ->and($history)->toHaveCount(1);

    // result_cache_ttl = 0 switches it off.
    $history = [];
    $uncached = new NvdSource(new CpeResolver, null, $stack([new Response(200, [], json_encode(['totalResults' => 0, 'vulnerabilities' => []])), new Response(200, [], json_encode(['totalResults' => 0, 'vulnerabilities' => []]))], $history),
        ['rate_limit_max' => 1000, 'result_cache_ttl' => 0], null, new ArrayCache);
    $uncached->queryPackage($widget('1.0.0'));
    $uncached->queryPackage($widget('1.0.0'));
    expect($history)->toHaveCount(2);

    // A truncated answer is never stored.
    $history = [];
    $page = fn () => new Response(200, [], json_encode(['items' => array_map(fn ($i) => ['id' => "EUVD-2030-{$i}", 'description' => 'x'], range(1, 100)), 'total' => 300]));
    $euvd = new EuvdSource($stack([$page(), $page()], $history), ['max_pages' => 1], null, new ArrayCache);
    $curl = [new PackageData(name: 'curl', version: '8.0.0', ecosystem: 'deb')];
    $euvd->queryBatch($curl);
    $euvd->queryBatch($curl);
    expect($history)->toHaveCount(2);
});
