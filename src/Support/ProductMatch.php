<?php

declare(strict_types=1);

namespace Gumslone\Vulns\Support;

/**
 * Does an advisory that names its products and vendors in free text concern
 * a given package?
 *
 * Feeds that are searched by product NAME (EUVD) answer a "contains" match:
 * a search for "config" returns Microsoft Configuration Manager, a Jenkins
 * configuration plugin and the Perl module Config::IniFiles alongside
 * league/config. Without a second look every one of them lands on the
 * package — a short, generic name ("core", "types", "he", "ms") collects
 * hundreds.
 *
 * The rule is deliberately precise rather than generous — such feeds
 * complement the ecosystem-native sources (OSV, GitHub), they do not replace
 * them:
 *
 *  - the product must BE the package: the same name, or "vendor/name";
 *  - when the package's vendor is known (composer vendor, npm scope, Maven
 *    group, repository owner), the advisory's vendor must be related to it;
 *  - a vendor hint from elsewhere — the vendor of the package's curated CPE —
 *    counts like the package's own vendor, and settles the cases a name alone
 *    cannot: the Rust crate "openssl" (vendor "sfackler") is not OpenSSL;
 *  - when no vendor is known at all (an unscoped npm name without a CPE), the
 *    vendor must be related to the package name itself — the self-named
 *    project ("axios" by "axios", "express" by "expressjs", "vite" by "vitejs");
 *  - a looser name match ("log4j" ~ "log4j-core") counts only together with
 *    a vendor match.
 *
 * An advisory that names no product at all cannot be judged and is reported
 * as such (null) — the caller decides; "can't tell" is not "not affected".
 */
final class ProductMatch
{
    /** Words that say nothing about who a vendor is. */
    private const NOISE = [
        'the', 'inc', 'ltd', 'llc', 'gmbh', 'corp', 'corporation', 'company', 'software', 'foundation',
        'project', 'team', 'group', 'org', 'com', 'net', 'io', 'dev', 'labs', 'open', 'source', 'community',
        'github', 'gitlab', 'bitbucket', 'www', 'php', 'js', 'node', 'npm',
    ];

    /** Vendor or product texts that mean "not given". */
    private const UNKNOWN = ['', 'n-a', 'na', 'unknown', 'unspecified', 'none'];

    /** What projects append to their own name to form an organisation name: vue → vuejs, node → nodejs. */
    private const VENDOR_SUFFIX = '/(?<=..)(js|io|hq|org|dev|team|labs|lang|project)$/';

    /**
     * @param  string[]  $productNames  the advisory's product names, as written
     * @param  string[]  $vendorNames  the advisory's vendor names, as written
     * @param  string  $name  package name, bare or "vendor/name" / "group:artifact"
     * @param  string|null  $namespace  the package's vendor / scope / group, when known
     * @param  bool  $requireVendor  false accepts an exact product name even when the
     *                               vendor is unrelated (more findings, more false ones)
     * @param  string[]  $vendorHints  further names the package's vendor goes by
     *                                 (e.g. its CPE vendor); "_project" suffixes are ignored
     * @return bool|null true = concerns the package, false = about other products,
     *                   null = the advisory names no product
     */
    public static function concerns(array $productNames, array $vendorNames, string $name, ?string $namespace = null, bool $requireVendor = true, array $vendorHints = []): ?bool
    {
        [$embeddedVendor, $bareName] = self::split(self::withoutGoMajor($name));
        $package = self::token($bareName);
        $vendor = self::token(ltrim((string) ($namespace !== null && trim($namespace) !== '' ? $namespace : $embeddedVendor), '@'));
        if ($package === '') {
            return null;
        }

        // Everything known about who makes the package. Only without any of
        // it does the package name itself stand in (the self-named project).
        $known = array_values(array_unique(array_filter([
            $vendor,
            ...array_map(fn ($hint) => self::token((string) preg_replace('/_project$/i', '', trim((string) $hint))), $vendorHints),
        ])));
        $references = $known !== [] ? $known : [$package];

        $vendors = array_values(array_filter(
            array_map(self::token(...), $vendorNames),
            fn (string $v) => ! in_array($v, self::UNKNOWN, true),
        ));

        $named = false;
        foreach ($productNames as $productName) {
            // A placeholder ("n/a") names nothing.
            if (in_array(self::token((string) $productName), self::UNKNOWN, true)) {
                continue;
            }
            $named = true;

            // "laravel/framework", "axios/axios": the product carries its own vendor.
            [$productVendor, $productBare] = self::split((string) $productName);
            $product = self::token($productBare);
            $candidates = $productVendor !== '' ? [...$vendors, self::token($productVendor)] : $vendors;

            $exact = $product === $package;
            // Looser: one name inside the other on a word boundary ("log4j" ~
            // "log4j-core") — also once the product has shed its vendor's
            // name and version digits ("Apache Log4j2" → "log4j", "Apache
            // Tomcat" → "tomcat").
            $bare = self::withoutVendorWords($product, $candidates);
            $loose = ! $exact && $product !== '' && (
                self::within($product, $package) || self::within($package, $product)
                || ($bare !== '' && $bare !== $product && ($bare === $package || self::within($bare, $package)))
            );
            if (! $exact && ! $loose) {
                continue;
            }

            $affinity = false;
            foreach ($references as $reference) {
                if (self::vendorRelated($candidates, $reference)) {
                    $affinity = true;
                    break;
                }
            }

            if ($exact && ($affinity || $candidates === [] || ! $requireVendor)) {
                return true; // no vendor on the advisory: nothing to contradict the name
            }
            if ($loose && $affinity) {
                return true;
            }
        }

        return $named ? false : null;
    }

    /**
     * Whether any advisory vendor is related to the package's vendor (or, for
     * a package without one, to its own name). Related means: the same once
     * punctuation is ignored ("Node.js" ~ "nodejs"); sharing a telling word
     * ("Apache Software Foundation" ~ "org.apache.logging.log4j"); one word
     * being the other plus an organisation suffix ("vuejs" ~ "vue"); a prefix
     * of at least four letters ("guzzle" ~ "guzzlehttp"); or one word inside
     * the other when it has at least five ("thephpleague" ~ "league").
     *
     * @param  string[]  $vendors  normalised advisory vendors
     */
    private static function vendorRelated(array $vendors, string $reference): bool
    {
        // The reference's own words always count, even ones that are noise
        // elsewhere: for PHP itself "php" IS the vendor.
        $referenceWords = self::words($reference) ?: self::rawWords($reference);
        $referenceStems = array_map(self::stem(...), $referenceWords);
        $squashedReference = str_replace(['-', '.'], '', $reference);

        foreach ($vendors as $vendor) {
            if ($vendor === $reference || str_replace(['-', '.'], '', $vendor) === $squashedReference) {
                return true;
            }
            $vendorWords = array_filter(self::rawWords($vendor), fn (string $word) => (strlen($word) >= 3 && ! in_array($word, self::NOISE, true))
                || in_array($word, $referenceWords, true) || in_array($word, $referenceStems, true));

            foreach ($vendorWords as $word) {
                foreach ($referenceWords as $referenceWord) {
                    if ($word === $referenceWord || self::stem($word) === self::stem($referenceWord)) {
                        return true;
                    }
                    [$short, $long] = strlen($word) <= strlen($referenceWord) ? [$word, $referenceWord] : [$referenceWord, $word];
                    if (strlen($short) >= 4 && str_starts_with($long, $short)) {
                        return true;
                    }
                    if (strlen($short) >= 5 && str_contains($long, $short)) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    /** @return string[] the telling words of a normalised token */
    private static function words(string $token): array
    {
        return array_values(array_filter(
            self::rawWords($token),
            fn (string $word) => strlen($word) >= 3 && ! in_array($word, self::NOISE, true),
        ));
    }

    /** @return string[] every word of a normalised token */
    private static function rawWords(string $token): array
    {
        return array_values(array_filter(preg_split('/[-.]+/', $token) ?: [], fn (string $word) => $word !== ''));
    }

    /** A word without the suffix organisations add to a project name. */
    private static function stem(string $word): string
    {
        return (string) preg_replace(self::VENDOR_SUFFIX, '', $word);
    }

    /**
     * A product token without its vendor's words and without version digits
     * glued to a word: "apache-log4j2" by "Apache Software Foundation" →
     * "log4j".
     *
     * @param  string[]  $vendors  normalised vendors of the advisory
     */
    private static function withoutVendorWords(string $product, array $vendors): string
    {
        $vendorWords = array_merge(...array_map(self::words(...), $vendors ?: ['']));
        $words = array_filter(self::rawWords($product), fn (string $word) => ! in_array($word, $vendorWords, true));

        return implode('-', array_filter(array_map(
            fn (string $word) => preg_match('/^[a-z].*[a-z]\d+$/', $word) ? (string) preg_replace('/\d+$/', '', $word) : $word,
            $words,
        )));
    }

    /**
     * The package's bare product name: without a vendor / path prefix and
     * without a Go major-version suffix ("github.com/golang-jwt/jwt/v5" →
     * "jwt", "gopkg.in/yaml.v3" → "yaml", "laravel/framework" → "framework").
     */
    public static function bareName(string $name): string
    {
        return self::split(self::withoutGoMajor($name))[1];
    }

    /** Whether two product names are the same name, vendor prefixes and Go major suffixes aside. */
    public static function sameName(string $a, string $b): bool
    {
        $a = self::token(self::bareName($a));

        return $a !== '' && $a === self::token(self::bareName($b));
    }

    /** "…/jwt/v5" → "…/jwt"; "gopkg.in/yaml.v3" → "gopkg.in/yaml". Only on path-like names. */
    public static function withoutGoMajor(string $name): string
    {
        $name = trim($name);
        if (! str_contains($name, '/')) {
            return $name;
        }

        return (string) preg_replace(['#/v\d+$#', '#\.v\d+$#'], '', $name);
    }

    /** @return array{0: string, 1: string} [vendor part, name part] of "vendor/name" or "group:artifact" */
    private static function split(string $name): array
    {
        $name = trim($name);
        $at = max((int) strrpos($name, '/'), (int) strrpos($name, ':'));
        // A leading separator or "::" (Perl's Config::IniFiles) is part of the name.
        if ($at <= 0 || str_contains($name, '::') || str_contains($name, ' ')) {
            return ['', $name];
        }

        return [substr($name, 0, $at), substr($name, $at + 1)];
    }

    /** Lowercase, every run of non-alphanumerics (dots kept) as one hyphen. */
    private static function token(string $value): string
    {
        return trim((string) preg_replace('/[^a-z0-9.]+/', '-', strtolower(trim($value))), '-.');
    }

    private static function within(string $needle, string $haystack): bool
    {
        return (bool) preg_match('/(?<![a-z0-9])'.preg_quote($needle, '/').'(?![a-z0-9])/', $haystack);
    }
}
