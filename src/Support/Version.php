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
}
