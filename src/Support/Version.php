<?php

declare(strict_types=1);

namespace Gumslone\Vulns\Support;

/**
 * The single home for version-string normalization. Four call sites used to
 * carry their own copies and disagreed on details (two stripped only a
 * lowercase "v" prefix), so a "V1.2" release compared differently depending on
 * which code path touched it.
 */
final class Version
{
    /** Strip whitespace and a leading "v"/"V" prefix. */
    public static function normalize(string $version): string
    {
        return ltrim(trim($version), 'vV');
    }

    /**
     * Normalize, and return null unless the result is a pure dotted-numeric
     * version (1, 1.2, 1.2.3.4) — the only shape PHP's version_compare orders
     * reliably. Qualifiers (RELEASE, rc1), Debian epochs (1:x) and hashes
     * return null so callers can stay fail-safe instead of mis-comparing.
     */
    public static function comparable(string $version): ?string
    {
        $version = self::normalize($version);

        return preg_match('/^\d+(\.\d+)*$/', $version) ? $version : null;
    }

    /**
     * version_compare on two comparable() versions with the shorter side
     * zero-padded, so 1.0 equals 1.0.0 (unpadded, PHP orders 1.0 BELOW
     * 1.0.0 — which would put a vulnerable "1.0" outside ">= 1.0.0").
     */
    public static function compare(string $a, string $b): int
    {
        $pa = explode('.', $a);
        $pb = explode('.', $b);
        $length = max(count($pa), count($pb));

        return version_compare(
            implode('.', array_pad($pa, $length, '0')),
            implode('.', array_pad($pb, $length, '0')),
        );
    }

    /**
     * Pre-release tags whose order every ecosystem agrees on, lowest first.
     * Anything else after a dash ("-1" is a Debian/Maven REVISION, above the
     * release; composer's "-p1" is a patch) is left unordered.
     */
    private const PRE_RELEASE_RANK = [
        'dev' => 0, 'nightly' => 0, 'canary' => 0,
        'a' => 1, 'alpha' => 1,
        'b' => 2, 'beta' => 2,
        'm' => 3, 'milestone' => 3,
        'pre' => 4, 'preview' => 4,
        'rc' => 5, 'cr' => 5,
        'snapshot' => 6,
    ];

    /**
     * Order two versions, or null when it can't be done SAFELY — the answer
     * VersionRange turns into "can't tell" rather than "not affected".
     *
     * Orderable: dotted-numeric cores (zero-padded, so 1.0 = 1.0.0), an
     * optional dash pre-release made of known tags and numbers
     * (1.0.0-rc.1 < 1.0.0, 2.0-beta9 < 2.0-beta10 < 2.0), semver build
     * metadata (ignored) and Maven's release markers (5.3.0.RELEASE = 5.3.0).
     * Not orderable: epochs (1:2.0), "~", PEP 440 suffixes (1.0rc1,
     * 1.0.post1), letter releases (1.1.1k), revisions (1.0-1), hashes.
     */
    public static function order(string $a, string $b): ?int
    {
        $pa = self::parts($a);
        $pb = self::parts($b);
        if ($pa === null || $pb === null) {
            return null;
        }

        $core = self::compare($pa[0], $pb[0]);
        if ($core !== 0) {
            return $core;
        }

        // Same core: a release outranks its pre-releases.
        if ($pa[1] === [] || $pb[1] === []) {
            return ($pa[1] === [] ? 1 : 0) <=> ($pb[1] === [] ? 1 : 0);
        }

        foreach ($pa[1] as $i => $token) {
            if (! isset($pb[1][$i])) {
                return 1; // rc.1.1 > rc.1
            }
            $other = $pb[1][$i];
            $cmp = match (true) {
                is_int($token) && is_int($other) => $token <=> $other,
                is_int($token) => -1, // numeric identifiers rank below tags (semver §11)
                is_int($other) => 1,
                default => self::PRE_RELEASE_RANK[$token] <=> self::PRE_RELEASE_RANK[$other],
            };
            if ($cmp !== 0) {
                return $cmp;
            }
        }

        return count($pa[1]) <=> count($pb[1]);
    }

    /** Whether order() can place this version at all. */
    public static function isOrderable(string $version): bool
    {
        return self::parts($version) !== null;
    }

    /**
     * @return array{0: string, 1: array<int, int|string>}|null [dotted-numeric core, pre-release tokens]
     */
    private static function parts(string $version): ?array
    {
        $version = self::normalize($version);
        $version = (string) preg_replace('/\+[0-9A-Za-z.-]+$/', '', $version);           // semver build metadata
        $version = (string) preg_replace('/[.-](release|final|ga)$/i', '', $version);      // Maven release markers

        if (! preg_match('/^(\d+(?:\.\d+)*)(?:-([0-9A-Za-z.-]+))?$/', $version, $m)) {
            return null;
        }
        if (! isset($m[2]) || $m[2] === '') {
            return [$m[1], []];
        }

        // "beta9" → beta, 9 — so beta9 < beta10, which a string compare gets wrong.
        preg_match_all('/[A-Za-z]+|\d+/', $m[2], $found);
        $tokens = [];
        foreach ($found[0] as $token) {
            if (ctype_digit($token)) {
                $tokens[] = (int) $token;
            } elseif (isset(self::PRE_RELEASE_RANK[strtolower($token)])) {
                $tokens[] = strtolower($token);
            } else {
                return null; // an unknown qualifier — never guess its place
            }
        }

        // A leading number is a revision (1.0-1), which sorts ABOVE the
        // release in dpkg/rpm/Maven and below it in semver: not orderable.
        return $tokens === [] || is_int($tokens[0]) ? null : [$m[1], $tokens];
    }
}
