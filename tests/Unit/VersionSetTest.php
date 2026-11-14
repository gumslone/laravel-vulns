<?php

/*
 * Two gaps in version matching:
 *  - an advisory range written in anything but ">= a, < b" — "5.5.*", "^5.5",
 *    "~5.5.0", "5.5.0 - 5.5.20", "5.4.x || 5.5.x" — was "can't tell";
 *  - an installed version given as a constraint ("^1.6.0" from a manifest
 *    without a lock file, "1.x" in a search) was "can't tell" against every
 *    advisory, so nothing was ever filtered.
 */

use Gumslone\Vulns\Data\PackageData;
use Gumslone\Vulns\Data\VulnerabilityData;
use Gumslone\Vulns\Sources\OssIndexSource;
use Gumslone\Vulns\Sources\OsvSource;
use Gumslone\Vulns\Sources\SnykSource;
use Gumslone\Vulns\Support\ArrayCache;
use Gumslone\Vulns\Support\CpeResolver;
use Gumslone\Vulns\Support\PurlBuilder;
use Gumslone\Vulns\Support\VersionRange;
use Gumslone\Vulns\Support\VersionSet;
use Gumslone\Vulns\Testing\FakeSource;
use Gumslone\Vulns\VulnSearch;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;

it('reads a constraint in every common syntax', function (string $expression, array $expected) {
    expect(VersionSet::describe($expression))->toBe($expected);
})->with([
    // comparators
    'and, commas' => ['>= 1.2, < 2.0', ['>= 1.2, < 2.0']],
    'and, spaces' => ['>=1.2 <2.0', ['>= 1.2, < 2.0']],
    'exclusive both' => ['>1.0 <=1.5', ['> 1.0, <= 1.5']],
    'exact' => ['= 1.4.2', ['= 1.4.2']],
    'bare' => ['1.4.2', ['= 1.4.2']],
    'v prefix' => ['>=v1.2.0', ['>= 1.2.0']],
    'upper only' => ['< 2', ['< 2']],
    'pre-release bound' => ['>=1.0.0-rc.1 <1.0.0', ['>= 1.0.0-rc.1, < 1.0.0']],
    // alternatives
    'npm or' => ['5.4.x || 5.5.x', ['>= 5.4, < 5.5', '>= 5.5, < 5.6']],
    'composer or' => ['>=5.5,<5.5.21|>=6,<6.1', ['>= 5.5, < 5.5.21', '>= 6, < 6.1']],
    // wildcards
    'patch wildcard' => ['1.2.*', ['>= 1.2, < 1.3']],
    'minor wildcard x' => ['1.x', ['>= 1, < 2']],
    'double wildcard' => ['1.x.x', ['>= 1, < 2']],
    'everything' => ['*', ['*']],
    'gradle dynamic' => ['2.+', ['>= 2, < 3']],
    'gradle dynamic patch' => ['1.2.+', ['>= 1.2, < 1.3']],
    'wildcard with <=' => ['<= 5.5.*', ['< 5.6']],
    'wildcard with >' => ['> 1.2.x', ['>= 1.3']],
    // caret
    'caret' => ['^1.2.3', ['>= 1.2.3, < 2']],
    'caret zero major' => ['^0.2.3', ['>= 0.2.3, < 0.3']],
    'caret zero minor' => ['^0.0.3', ['>= 0.0.3, < 0.0.4']],
    'caret partial' => ['^1.2', ['>= 1.2, < 2']],
    'caret zero' => ['^0', ['>= 0, < 1']],
    // tilde — the wider reading where ecosystems differ
    'tilde patch' => ['~1.2.3', ['>= 1.2.3, < 1.3']],
    'tilde minor' => ['~1.2', ['>= 1.2, < 2']],
    'tilde major' => ['~1', ['>= 1, < 2']],
    'ruby pessimistic' => ['~> 2.1.4', ['>= 2.1.4, < 2.2']],
    'pep 440 compatible' => ['~=4.2.0', ['>= 4.2.0, < 4.3']],
    // hyphen
    'hyphen' => ['1.2.3 - 2.3.4', ['>= 1.2.3, <= 2.3.4']],
    'hyphen partial upper' => ['1.2 - 2.3', ['>= 1.2, < 2.4']],
    // Maven / NuGet intervals
    'half-open interval' => ['[1.0,2.0)', ['>= 1.0, < 2.0']],
    'upper bounded interval' => ['(,1.0]', ['<= 1.0']],
    'lower bounded interval' => ['[1.5,)', ['>= 1.5']],
    'exact interval' => ['[1.0]', ['= 1.0']],
    'union of intervals' => ['(,1.0],[1.2,)', ['<= 1.0', '>= 1.2']],
]);

it('refuses what it cannot read rather than guessing', function (string $expression) {
    expect(VersionSet::parse($expression))->toBeNull()
        ->and(VersionSet::describe($expression))->toBeNull();
})->with([
    'prose' => ['all versions of the legacy branch'],
    'through' => ['1.7.0 through 1.15.x'],
    'tag' => ['latest'],
    'branch' => ['dev-main'],
    'not equal' => ['!= 1.2.3'],
    'debian epoch' => ['>= 1:2.0'],
    'letter release' => ['< 1.1.1k'],
    'unknown qualifier' => ['>= 1.0.0-foo'],
    'unspecified bound' => ['7.0.0 <unspecified'],
    'contradiction' => ['>2.0 <1.0'],
    'empty' => ['  '],
    'malformed interval' => ['[1.0,2.0'],
    'empty brackets' => ['(1.0)'],
]);

it('tells an exact version from a constraint', function () {
    expect(VersionSet::isRange('1.2.3'))->toBeFalse()
        ->and(VersionSet::isRange('v1.2'))->toBeFalse()
        ->and(VersionSet::isRange('1.0.0-rc.1'))->toBeFalse()
        ->and(VersionSet::isRange('^1.2.3'))->toBeTrue()
        ->and(VersionSet::isRange('1.x'))->toBeTrue()
        ->and(VersionSet::isRange('>=1.0 <2'))->toBeTrue()
        ->and(VersionSet::isRange('[1.0,2.0)'))->toBeTrue()
        ->and(VersionSet::isRange('latest'))->toBeFalse()
        ->and(VersionSet::isRange('1.1.1k'))->toBeFalse()
        ->and(VersionSet::isRange(null))->toBeFalse();
});

it('decides membership, edges included', function () {
    $set = VersionSet::parse('>= 1.7.0, < 1.16.0 || 2.x');

    expect(VersionSet::contains($set, '1.7.0'))->toBeTrue()
        ->and(VersionSet::contains($set, '1.15.9'))->toBeTrue()
        ->and(VersionSet::contains($set, '1.16.0'))->toBeFalse()
        ->and(VersionSet::contains($set, '1.6.9'))->toBeFalse()
        ->and(VersionSet::contains($set, '2.4.1'))->toBeTrue()
        ->and(VersionSet::contains($set, '3.0.0'))->toBeFalse()
        ->and(VersionSet::contains($set, '1.16.0-rc.1'))->toBeTrue()   // a pre-release of the fix is still below it
        ->and(VersionSet::contains($set, '1.1.1k'))->toBeNull();       // cannot be placed
});

it('finds whether two sets share a version', function (string $a, string $b, bool $expected) {
    expect(VersionSet::overlaps(VersionSet::parse($a), VersionSet::parse($b)))->toBe($expected);
})->with([
    'inside' => ['^1.10', '>= 1.7.0, < 1.16.0', true],
    'partly' => ['1.x', '>= 1.7.0, < 1.16.0', true],
    'above the fix' => ['>=1.16', '>= 1.7.0, < 1.16.0', false],
    'below the introduction' => ['<1.7.0', '>= 1.7.0, < 1.16.0', false],
    'touching, upper exclusive' => ['>=1.16.0', '< 1.16.0', false],
    'touching, both inclusive' => ['>=1.16.0', '<= 1.16.0', true],
    'other major line' => ['2.x', '^1.2.3', false],
    'everything' => ['*', '= 4.2.0', true],
    'one alternative reaches' => ['0.9.x || 3.x', '>= 3.1, < 3.2', true],
]);

it('turns an OSV event list into its affected windows', function () {
    expect(VersionSet::fromEvents([['introduced' => '0'], ['fixed' => '1.2.3']]))->toBe([[null, true, '1.2.3', false]])
        ->and(VersionSet::fromEvents([['introduced' => '5.0.0'], ['fixed' => '5.4.3'], ['introduced' => '5.5.0'], ['last_affected' => '5.5.20']]))
        ->toBe([['5.0.0', true, '5.4.3', false], ['5.5.0', true, '5.5.20', true]])
        ->and(VersionSet::fromEvents([['introduced' => '2.0.0']]))->toBe([['2.0.0', true, null, true]])
        ->and(VersionSet::fromEvents([['introduced' => '1.1.1k'], ['fixed' => '2']]))->toBeNull()
        ->and(VersionSet::fromEvents([]))->toBeNull();
});

// ── in the matcher ───────────────────────────────────────────────────────

it('matches an advisory range written in any of those syntaxes', function (string $range, string $inside, string $outside) {
    expect(VersionRange::isVulnerable($inside, [['range' => $range]]))->toBeTrue()
        ->and(VersionRange::isVulnerable($outside, [['range' => $range]]))->toBeFalse();
})->with([
    'wildcard' => ['5.5.*', '5.5.10', '5.6.0'],
    'x line' => ['5.x', '5.9.9', '6.0.0'],
    'caret' => ['^5.5', '5.9.0', '6.0.0'],
    'tilde' => ['~5.5.0', '5.5.20', '5.6.0'],
    'hyphen' => ['5.5.0 - 5.5.20', '5.5.20', '5.5.21'],
    'npm or' => ['5.4.x || 5.5.x', '5.4.2', '5.6.0'],
    'composer or' => ['>=5.5,<5.5.21|>=6,<6.1', '6.0.5', '5.5.21'],
    'interval' => ['[5.5,5.6)', '5.5.10', '5.6'],
    'spaces instead of commas' => ['>=5.5 <5.6', '5.5.10', '5.6.0'],
]);

it('still cannot tell from a bare version or prose in an advisory range', function () {
    // What a lone "8" means is for the source to say (a release line, usually) —
    // it converts it before storing; the matcher does not guess "exactly 8".
    expect(VersionRange::isVulnerable('5.5.10', [['range' => '8']]))->toBeNull()
        ->and(VersionRange::isVulnerable('5.5.10', [['range' => '1.7.0 through 1.15.x']]))->toBeNull()
        ->and(VersionRange::isVulnerable('5.5.10', [['range' => '< 5.0'], ['raw' => 'other builds']]))->toBeNull();
});

it('judges an installed constraint by whether it overlaps an affected range', function (string $installed, ?bool $expected) {
    $ranges = [['range' => '>= 1.7.0, < 1.16.0', 'source' => 'nvd'], ['type' => 'SEMVER', 'events' => [['introduced' => '2.0.0'], ['fixed' => '2.3.1']]]];

    expect(VersionRange::isVulnerable($installed, $ranges))->toBe($expected);
})->with([
    'wildcard line that reaches in' => ['1.x', true],
    'caret inside' => ['^1.10', true],
    'range across the introduction' => ['>=1.0 <1.8', true],
    'reaches the second window' => ['~2.2.0', true],
    'line past the fix' => ['1.18.x', false],
    'between the windows' => ['>=1.16 <2.0', false],
    'past both' => ['>=2.3.1', false],
    'maven interval before the first' => ['[1.0,1.7.0)', false],
    'tag' => ['latest', null],
    'branch' => ['dev-main', null],
]);

it('proves nothing for an installed constraint while any range is unreadable', function () {
    expect(VersionRange::isVulnerable('>=3.0', [['range' => '< 2.0'], ['raw' => 'some other builds']]))->toBeNull()
        ->and(VersionRange::isVulnerable('1.x', [['range' => '< 2.0'], ['raw' => 'some other builds']]))->toBeTrue() // an overlap is an overlap
        ->and(VersionRange::isVulnerable('1.x', [['type' => 'GIT', 'events' => [['introduced' => 'abc123']]]]))->toBeNull();
});

it('counts a constraint as past the fixes when its lowest version is', function () {
    expect(VersionRange::isPastAllFixes('>=1.16.0', ['npm:1.16.0']))->toBeTrue()
        ->and(VersionRange::isPastAllFixes('^2.0', ['1.16.0', '1.9.4']))->toBeTrue()
        ->and(VersionRange::isPastAllFixes('^1.10', ['1.16.0']))->toBeFalse()   // may resolve below the fix
        ->and(VersionRange::isPastAllFixes('<3.0', ['1.16.0']))->toBeFalse()    // no lower bound
        ->and(VersionRange::isPastAllFixes('1.x || 3.x', ['2.0.0']))->toBeFalse()
        ->and(VersionRange::isPastAllFixes('latest', ['1.16.0']))->toBeFalse();
});

// ── in the sources ───────────────────────────────────────────────────────

it('asks OSV about a constraint without a version, so the ranges can be overlapped', function () {
    // OSV matches one exact version; "^1.6.0" would simply find nothing.
    $history = [];
    $stack = HandlerStack::create(new MockHandler([
        new Response(200, [], json_encode(['vulns' => []])),
        new Response(200, [], json_encode(['vulns' => []])),
    ]));
    $stack->push(Middleware::history($history));
    $osv = new OsvSource(new Client(['handler' => $stack]), cache: new ArrayCache);

    $osv->queryPackage(new PackageData(name: 'axios', version: '^1.6.0', ecosystem: 'npm'));
    $osv->queryPackage(new PackageData(name: 'axios', version: '1.6.0', ecosystem: 'npm'));

    $constraint = json_decode((string) $history[0]['request']->getBody(), true);
    $exact = json_decode((string) $history[1]['request']->getBody(), true);
    expect($constraint)->toBe(['package' => ['name' => 'axios', 'ecosystem' => 'npm']])
        ->and($exact['version'])->toBe('1.6.0');
});

it('filters a search for a constraint down to the advisories that can affect it', function () {
    $advisory = fn (string $id, string $range) => new VulnerabilityData(vulnId: $id, source: 'osv', affectedRanges: [['range' => $range]], rawDataChecksum: $id);
    $search = new VulnSearch([new FakeSource('osv', ['axios' => [
        $advisory('CVE-2033-1', '>= 1.7.0, < 1.16.0'),
        $advisory('CVE-2033-2', '< 0.30.0'),
        $advisory('CVE-2033-3', '>= 1.17.0, < 1.20.0'),
    ]])]);
    $ids = fn (string $version) => array_map(
        fn ($v) => $v->vulnId,
        $search->search(new PackageData(name: 'axios', version: $version, ecosystem: 'npm')),
    );

    expect($ids('1.x'))->toBe(['CVE-2033-1', 'CVE-2033-3'])       // the whole 1.x line
        ->and($ids('^1.18'))->toBe(['CVE-2033-3'])
        ->and($ids('>=1.20'))->toBe([])
        ->and($ids('0.x || 1.16.x'))->toBe(['CVE-2033-2'])
        ->and($ids('*'))->toHaveCount(3)
        ->and($ids('1.18.1'))->toBe(['CVE-2033-3']);              // an exact version, as before
});

it('leaves a constraint out of sources and identifiers that need one exact version', function () {
    $constraint = new PackageData(name: 'axios', version: '^1.6.0', ecosystem: 'npm', purl: 'pkg:npm/axios@%5E1.6.0');
    $exact = new PackageData(name: 'axios', version: '1.6.0', ecosystem: 'npm', purl: 'pkg:npm/axios@1.6.0');
    $builder = new PurlBuilder;
    $ossIndex = new OssIndexSource($builder);
    $snyk = new SnykSource($builder);

    expect($ossIndex->supports($constraint))->toBeFalse()
        ->and($ossIndex->supports($exact))->toBeTrue()
        ->and($snyk->supports($constraint))->toBeFalse()
        // …and a CPE built for it names the product at any version.
        ->and((new CpeResolver)->resolveCpe23($constraint))->toMatch('/^cpe:2\.3:a:[^:]+:axios:\*:/');
});
