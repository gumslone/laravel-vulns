<?php

declare(strict_types=1);

namespace Gumslone\Vulns\Support;

/**
 * Decides whether a concrete package version falls inside a vulnerability's
 * affected range(s).
 *
 * Several sources (GitHub Security Advisories, EUVD, CVE-Search) return every
 * advisory for a package name without checking the installed version, leaving
 * the version filtering to us. This parses the constraint strings they attach
 * (npm/composer style: ">= 4.0.0, < 4.17.21", "< 1.2.3", "= 1.0.0") so a
 * fully-patched package is not flagged for a fixed CVE.
 *
 * It is deliberately conservative: when the version is unknown or a constraint
 * can't be parsed, it returns null ("can't tell") so the caller keeps the
 * advisory rather than risk a false negative.
 */
final class VersionRange
{
    /**
     * The version to upgrade to: the lowest published fix at or above the
     * current version, preferring one on the same major line (a patch
     * release over a major bump). The lowest fix when the current version
     * can't be compared; null when none is comparable or the current
     * version is already past every fix.
     *
     * @param  string[]  $fixedVersions
     */
    public static function recommendedFix(?string $version, array $fixedVersions): ?string
    {
        // A list, not a map: PHP would turn a key like '5' into an int.
        $candidates = [];
        foreach ($fixedVersions as $fixed) {
            $bare = self::stripEcosystem((string) $fixed); // "Packagist:1.8.0" → "1.8.0"
            $comparable = Version::comparable($bare);
            if ($comparable !== null) {
                $candidates[] = [$comparable, $bare];
            }
        }
        if ($candidates === []) {
            return null;
        }
        usort($candidates, fn (array $a, array $b) => self::compare($a[0], $b[0]));

        $current = $version === null ? null : Version::comparable($version);
        if ($current === null) {
            return $candidates[0][1];
        }

        $major = explode('.', $current)[0];
        foreach ($candidates as [$comparable, $original]) {
            if (self::compare($comparable, $current) >= 0 && explode('.', $comparable)[0] === $major) {
                return $original;
            }
        }
        foreach ($candidates as [$comparable, $original]) {
            if (self::compare($comparable, $current) >= 0) {
                return $original;
            }
        }

        return null;
    }

    private static function compare(string $a, string $b): int
    {
        return Version::compare($a, $b);
    }

    /**
     * The ranges that speak about ONE package, out of an advisory's whole
     * list. Multi-product advisories (NVD configurations, EUVD product
     * lists) tag each range with a `product`; another product's "< 9.0.0"
     * says nothing about this package, and must neither flag nor clear it.
     *
     * Untagged ranges always count. When ranges are tagged but none names
     * this package, the result is [] — "can't tell", which isVulnerable()
     * answers with null.
     *
     * @param  array<int, array<string, mixed>|string>  $ranges
     * @return array<int, array<string, mixed>|string>
     */
    public static function relevantTo(array $ranges, string $packageName): array
    {
        $tagged = array_filter($ranges, fn ($r) => is_array($r) && is_string($r['product'] ?? null) && trim($r['product']) !== '');
        if ($tagged === []) {
            return $ranges;
        }

        $own = array_filter($tagged, fn (array $r) => self::sameProduct($r['product'], $packageName));
        if ($own === []) {
            return [];
        }

        return array_values(array_filter($ranges, fn ($r) => ! in_array($r, $tagged, true) || in_array($r, $own, true)));
    }

    /**
     * Whether an advisory's product label and a package name denote the same
     * thing: compared on the last name segment ("vendor:product", "group:
     * artifact", "vendor/name" → the tail), case- and separator-insensitive,
     * one containing the other on a word boundary ("log4j" ~ "log4j-core",
     * but "express" ≁ "expressvpn").
     */
    public static function sameProduct(string $product, string $packageName): bool
    {
        $token = function (string $value): string {
            $value = strtolower(trim($value));
            $value = preg_replace('#^.*[/:]#', '', $value) ?? $value;

            return trim((string) preg_replace('/[^a-z0-9.]+/', '-', $value), '-');
        };
        $a = $token($product);
        $b = $token($packageName);
        if ($a === '' || $b === '') {
            return false;
        }

        $within = fn (string $needle, string $haystack): bool => (bool) preg_match(
            '/(?<![a-z0-9])'.preg_quote($needle, '/').'(?![a-z0-9])/', $haystack,
        );

        return $within($a, $b) || $within($b, $a);
    }

    /**
     * @param  array<int, array<string, mixed>|string>  $ranges  affectedRanges entries
     * @return bool|null true = in an affected range; false = provably outside EVERY range; null = undeterminable (any range unreadable and none matched)
     */
    public static function isVulnerable(?string $version, array $ranges): ?bool
    {
        if ($version === null || trim($version) === '' || $ranges === []) {
            return null;
        }

        $version = self::normalise($version);
        $sawParseable = false;
        $sawUndeterminable = false;

        foreach ($ranges as $range) {
            // OSV-shaped entry: {type, events: [{introduced}, {fixed}, …]}.
            if (is_array($range) && ! isset($range['range']) && is_array($range['events'] ?? null)) {
                if (strtoupper((string) ($range['type'] ?? '')) === 'GIT') {
                    continue; // commits, not versions — says nothing in version space
                }
                $result = self::withinEvents($version, $range['events']);
                if ($result === true) {
                    return true;
                }
                $result === null ? $sawUndeterminable = true : $sawParseable = true;

                continue;
            }
            $constraint = is_array($range)
                ? (is_string($range['range'] ?? null) ? $range['range'] : null)
                : (is_string($range) ? $range : null);

            if ($constraint === null || trim($constraint) === '') {
                // An entry we can't read (OSV event lists, a constraint that
                // didn't parse upstream) may be the one that covers this
                // version — it must not be outvoted by the ranges that don't.
                $sawUndeterminable = true;

                continue;
            }

            $result = self::satisfies($version, $constraint);
            if ($result === null) {
                $sawUndeterminable = true;

                continue;
            }

            $sawParseable = true;
            if ($result === true) {
                return true; // inside an affected range
            }
        }

        // "Not affected" only when EVERY range was readable and none matched.
        return $sawParseable && ! $sawUndeterminable ? false : null;
    }

    /**
     * OSV event timeline: affected from each `introduced` until the next
     * `fixed` / `limit` (exclusive) or `last_affected` (inclusive). Null when
     * any event's version can't be ordered against ours.
     *
     * @param  array<int, array<string, mixed>>  $events
     */
    private static function withinEvents(string $version, array $events): ?bool
    {
        if (! Version::isOrderable($version)) {
            return null;
        }

        $timeline = [];
        foreach ($events as $event) {
            foreach (['introduced', 'fixed', 'last_affected', 'limit'] as $kind) {
                if (! is_array($event) || ! isset($event[$kind]) || ! is_scalar($event[$kind])) {
                    continue;
                }
                $at = (string) $event[$kind] === '0' ? '0' : self::normalise((string) $event[$kind]);
                if (! Version::isOrderable($at)) {
                    return null;
                }
                $timeline[] = [$at, $kind];
            }
        }
        if ($timeline === []) {
            return null;
        }

        // Ascending; at the same version a closing event comes before an opening one.
        usort($timeline, fn (array $a, array $b) => Version::order($a[0], $b[0])
            ?: ($a[1] === 'introduced' ? 1 : 0) <=> ($b[1] === 'introduced' ? 1 : 0));

        $affected = false;
        foreach ($timeline as [$at, $kind]) {
            $cmp = Version::order($version, $at);
            $affected = match ($kind) {
                'introduced' => $cmp >= 0 ? true : $affected,
                'last_affected' => $cmp > 0 ? false : $affected,
                default => $cmp >= 0 ? false : $affected, // fixed, limit
            };
        }

        return $affected;
    }

    /**
     * Whether $version satisfies every comma-separated clause of a constraint
     * (clauses are AND-ed, as in npm/GitHub ranges). Null if any clause is
     * unparseable.
     */
    private static function satisfies(string $version, string $constraint): ?bool
    {
        // "*" — every version (NVD's unbounded CPE match).
        if (trim($constraint) === '*') {
            return true;
        }

        $clauses = array_filter(array_map('trim', explode(',', $constraint)), fn (string $c) => $c !== '');
        if ($clauses === []) {
            return null;
        }

        foreach ($clauses as $clause) {
            if (! preg_match('/^(>=|<=|==|=|>|<)\s*(.+)$/', $clause, $m)) {
                return null;
            }

            $bound = self::normalise($m[2]);

            // Equality needs no ordering, so letter-suffixed release tags
            // ("1.1.0a") and other unorderable versions still decide —
            // EUVD's old records enumerate affected releases exactly this way.
            if ($m[1] === '=' || $m[1] === '==') {
                $equal = (Version::order($version, $bound) ?? (strcasecmp($version, $bound) === 0 ? 0 : 1)) === 0;
                if (! $equal) {
                    return false; // one clause fails → the AND fails
                }

                continue;
            }

            // version_compare misorders anything that isn't a clean
            // dotted-numeric version — Debian epochs "1:1.5" or "1.1.1k"
            // sort BELOW a bare number, which would make ">= 1.1.1" wrongly
            // fail and clear a genuinely vulnerable package (a false negative
            // — the dangerous direction). Version::order() only orders what
            // every ecosystem agrees on; otherwise stay fail-safe.
            $cmp = Version::order($version, $bound);
            if ($cmp === null) {
                return null;
            }

            $ok = match ($m[1]) {
                '>=' => $cmp >= 0,
                '>' => $cmp > 0,
                '<=' => $cmp <= 0,
                default => $cmp < 0, // '<' — the clause regex admits nothing else
            };

            if ($ok === false) {
                return false; // one clause fails → the AND fails
            }
        }

        return true;
    }

    /**
     * Whether the installed version sits at or above EVERY published fix — the
     * package is past all known fixes, so a finding still claiming it's
     * affected is a false positive (typically from a source that matched by
     * name without a version range). Fixes accumulate within a release line, so
     * being past all of them means safe.
     *
     * Requires at least one comparable fix; an unorderable version or fix makes
     * it undeterminable (false), staying fail-safe. Fix entries may carry an
     * ecosystem prefix ("Packagist:1.8.0") which is stripped.
     *
     * @param  array<int, string>  $fixedVersions
     */
    public static function isPastAllFixes(?string $version, array $fixedVersions): bool
    {
        if ($version === null) {
            return false;
        }
        if (! Version::isOrderable($version)) {
            return false;
        }

        $fixes = [];
        foreach ($fixedVersions as $entry) {
            if (trim((string) $entry) === '') {
                continue;
            }
            $fix = self::stripEcosystem((string) $entry);
            if (! Version::isOrderable($fix)) {
                return false; // an unorderable fix (1:2.0, 2.0.post1) may lie above installed
            }
            $fixes[] = $fix;
        }
        if ($fixes === []) {
            return false; // no fix data — can't conclude
        }

        foreach ($fixes as $fix) {
            if (Version::order($fix, $version) > 0) {
                return false; // a fix lies above installed → not yet past it
            }
        }

        return true;
    }

    /** "Packagist:1.8.0" → "1.8.0"; bare versions pass through. */
    private static function stripEcosystem(string $entry): string
    {
        // A numeric prefix is a Debian/RPM epoch ("1:0.9"), part of the version.
        return preg_match('/^[A-Za-z][^:]*:(.+)$/', $entry, $m) ? $m[1] : $entry;
    }

    private static function normalise(string $version): string
    {
        return Version::normalize($version);
    }
}
