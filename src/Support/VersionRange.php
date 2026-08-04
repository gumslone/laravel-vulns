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
     * @param  array<int, array<string, mixed>|string>  $ranges  affectedRanges entries
     * @return bool|null  true = in an affected range; false = provably outside every parseable range; null = undeterminable
     */
    public static function isVulnerable(?string $version, array $ranges): ?bool
    {
        if ($version === null || trim($version) === '' || $ranges === []) {
            return null;
        }

        $version = self::normalise($version);
        $sawParseable = false;

        foreach ($ranges as $range) {
            $constraint = is_array($range)
                ? (is_string($range['range'] ?? null) ? $range['range'] : null)
                : (is_string($range) ? $range : null);

            if ($constraint === null || trim($constraint) === '') {
                continue;
            }

            $result = self::satisfies($version, $constraint);
            if ($result === null) {
                continue; // unparseable — ignore this entry
            }

            $sawParseable = true;
            if ($result === true) {
                return true; // inside an affected range
            }
        }

        // Parsed at least one range and matched none → outside all of them.
        return $sawParseable ? false : null;
    }

    /**
     * Whether $version satisfies every comma-separated clause of a constraint
     * (clauses are AND-ed, as in npm/GitHub ranges). Null if any clause is
     * unparseable.
     */
    private static function satisfies(string $version, string $constraint): ?bool
    {
        $clauses = array_filter(array_map('trim', explode(',', $constraint)));
        if ($clauses === []) {
            return null;
        }

        // version_compare misorders anything that isn't a clean dotted-numeric
        // version — Maven "5.3.0.RELEASE" and Debian epochs "1:1.5" sort BELOW a
        // bare number, which would make ">= 5.3.0" wrongly fail and clear a
        // genuinely vulnerable package (a false negative — the dangerous
        // direction). Only decide when the installed version is safely
        // comparable; otherwise return null so the caller stays fail-safe.
        if (! self::isComparable($version)) {
            return null;
        }

        foreach ($clauses as $clause) {
            if (! preg_match('/^(>=|<=|==|=|>|<)\s*(.+)$/', $clause, $m)) {
                return null;
            }

            $bound = self::normalise($m[2]);
            if (! self::isComparable($bound)) {
                return null; // can't trust the comparison against this bound
            }

            $cmp = version_compare($version, $bound);
            $ok = match ($m[1]) {
                '>=' => $cmp >= 0,
                '>' => $cmp > 0,
                '<=' => $cmp <= 0,
                '<' => $cmp < 0,
                '=', '==' => $cmp === 0,
                default => null,
            };

            if ($ok === null) {
                return null;
            }
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
        $installed = Version::comparable($version);
        if ($installed === null) {
            return false;
        }

        $fixes = array_values(array_filter(array_map(
            fn ($entry) => Version::comparable(self::stripEcosystem((string) $entry)),
            $fixedVersions,
        )));
        if ($fixes === []) {
            return false; // no comparable fix data — can't conclude
        }

        foreach ($fixes as $fix) {
            if (version_compare($fix, $installed, '>')) {
                return false; // a fix lies above installed → not yet past it
            }
        }

        return true;
    }

    /** "Packagist:1.8.0" → "1.8.0"; bare versions pass through. */
    private static function stripEcosystem(string $entry): string
    {
        return str_contains($entry, ':') ? substr($entry, strpos($entry, ':') + 1) : $entry;
    }

    private static function normalise(string $version): string
    {
        return Version::normalize($version);
    }

    /**
     * Only pure dotted-numeric versions (1, 1.2, 1.2.3.4) are safe to order with
     * version_compare. Anything with a qualifier (RELEASE, Final, rc1),
     * a Debian epoch (1:x), or other non-numeric text is treated as
     * undeterminable so we never assert "not affected" on it.
     */
    private static function isComparable(string $version): bool
    {
        return Version::comparable($version) !== null;
    }
}
