<?php

declare(strict_types=1);

namespace Gumslone\Vulns\Support;

/**
 * A set of versions written as a constraint, in any of the syntaxes package
 * ecosystems use:
 *
 *   comparators       >= 1.2, < 2.0      >=1.2 <2.0      = 1.4.2
 *   alternatives      5.4.x || 5.5.x     >=5.5,<5.5.21|>=6,<6.1
 *   wildcards         1.2.*   1.2.x   1.x   *      Gradle's 1.2.+
 *   caret             ^1.2.3  (< 2.0.0)   ^0.2.3  (< 0.3.0)   ^0.0.3  (< 0.0.4)
 *   tilde             ~1.2.3  (< 1.3.0)   ~1.2  (< 2.0)   also ~> and ~=
 *   hyphen            1.2.3 - 2.3.4      1.2 - 2.3  (< 2.4)
 *   intervals         [1.0,2.0)   (,1.0]   [1.0]   (,1.0],[1.2,)     Maven, NuGet
 *
 * It answers two questions VersionRange could not: whether a version lies in
 * an advisory range written like that, and — when the INSTALLED version is
 * itself such a constraint ("^1.6.0" from a manifest without a lock file,
 * "1.x" typed into a search) — whether the versions it allows overlap the
 * versions an advisory affects.
 *
 * Reading is strict. Every token must be one of the forms above with bounds
 * Version::order() can place; anything else — prose, "!=", "latest", a
 * branch name, a Debian epoch — makes the whole expression unreadable (null),
 * which callers turn into "can't tell", never into "not affected".
 *
 * Where ecosystems disagree, the WIDER reading is taken, because a wider set
 * can only add findings: "~1.2" is ">= 1.2, < 2.0" (Composer, RubyGems, PEP
 * 440), not npm's "< 1.3".
 *
 * An interval is [lower|null, lowerInclusive, upper|null, upperInclusive];
 * null means unbounded on that side.
 *
 * @phpstan-type Interval array{0: string|null, 1: bool, 2: string|null, 3: bool}
 */
final class VersionSet
{
    private const OPERATOR = '(>=|<=|==|=|>|<|\^|~>|~=|~)';

    /**
     * @param  bool  $allowBare  false refuses an expression that is nothing but one plain
     *                           version ("5.5.10") — it carries no range syntax, and what a
     *                           bare version means in an advisory is the source's to say
     * @return list<Interval>|null the alternatives of the expression; null when it cannot be read
     */
    public static function parse(string $expression, bool $allowBare = true): ?array
    {
        $expression = trim($expression);
        if ($expression === '') {
            return null;
        }
        if (preg_match('/^[\[(]/', $expression)) {
            return self::brackets($expression);
        }

        $alternatives = preg_split('/\s*\|\|?\s*/', $expression) ?: [];
        $rangeSyntax = count($alternatives) > 1;
        $intervals = [];
        foreach ($alternatives as $alternative) {
            $interval = self::alternative(trim($alternative), $rangeSyntax);
            if ($interval === null) {
                return null;
            }
            if ($interval !== false) {
                $intervals[] = $interval;
            }
        }

        // Every alternative contradicted itself (">2 <1"): not a set we can use.
        if ($intervals === [] || (! $allowBare && ! $rangeSyntax)) {
            return null;
        }

        return $intervals;
    }

    /** Whether $version is a readable constraint rather than one exact, orderable version. */
    public static function isRange(?string $version): bool
    {
        if ($version === null || trim($version) === '') {
            return false;
        }
        $version = Version::normalize($version);

        return ! Version::isOrderable($version) && self::parse($version) !== null;
    }

    /**
     * @param  list<Interval>  $intervals
     * @return bool|null null when the version, or a bound it must be compared with, cannot be ordered
     */
    public static function contains(array $intervals, string $version): ?bool
    {
        $version = Version::normalize($version);
        if (! Version::isOrderable($version)) {
            return null;
        }

        $undetermined = false;
        foreach ($intervals as [$lower, $lowerInclusive, $upper, $upperInclusive]) {
            $above = $lower === null ? 1 : Version::order($version, $lower);
            $below = $upper === null ? -1 : Version::order($version, $upper);
            if ($above === null || $below === null) {
                $undetermined = true;

                continue;
            }
            if (($above > 0 || ($above === 0 && $lowerInclusive)) && ($below < 0 || ($below === 0 && $upperInclusive))) {
                return true;
            }
        }

        return $undetermined ? null : false;
    }

    /**
     * Whether two sets share at least one version.
     *
     * @param  list<Interval>  $a
     * @param  list<Interval>  $b
     * @return bool|null null when bounds cannot be ordered against each other and nothing else overlapped
     */
    public static function overlaps(array $a, array $b): ?bool
    {
        $undetermined = false;
        foreach ($a as $left) {
            foreach ($b as $right) {
                $shared = self::intersect($left, $right);
                if ($shared === null) {
                    $undetermined = true;
                } elseif ($shared !== false) {
                    return true;
                }
            }
        }

        return $undetermined ? null : false;
    }

    /**
     * The lowest version any alternative allows — every version in the set is
     * at or above it. Null when the set is unbounded below (or cannot be ordered).
     *
     * @param  list<Interval>  $intervals
     */
    public static function lowest(array $intervals): ?string
    {
        $lowest = null;
        foreach ($intervals as [$lower]) {
            if ($lower === null) {
                return null;
            }
            if ($lowest === null) {
                $lowest = $lower;

                continue;
            }
            $order = Version::order($lower, $lowest);
            if ($order === null) {
                return null;
            }
            $lowest = $order < 0 ? $lower : $lowest;
        }

        return $lowest;
    }

    /**
     * The expression in the plain comparator grammar, one string per
     * alternative — "^1.2.3 || 2.x" → [">= 1.2.3, < 2", ">= 2, < 3"]. For
     * showing what a constraint was read as.
     *
     * @return list<string>|null
     */
    public static function describe(string $expression): ?array
    {
        $intervals = self::parse($expression);
        if ($intervals === null) {
            return null;
        }

        return array_map(function (array $interval): string {
            [$lower, $lowerInclusive, $upper, $upperInclusive] = $interval;
            if ($lower !== null && $lower === $upper) {
                return "= {$lower}";
            }
            $clauses = array_filter([
                $lower !== null ? ($lowerInclusive ? '>= ' : '> ').$lower : null,
                $upper !== null ? ($upperInclusive ? '<= ' : '< ').$upper : null,
            ]);

            return $clauses === [] ? '*' : implode(', ', $clauses);
        }, $intervals);
    }

    /**
     * The affected windows of an OSV event list as intervals: from each
     * `introduced` to the next `fixed` / `limit` (exclusive) or
     * `last_affected` (inclusive), open-ended when nothing closes it.
     *
     * @param  array<int, mixed>  $events
     * @return list<Interval>|null null when an event's version cannot be ordered
     */
    public static function fromEvents(array $events): ?array
    {
        $timeline = [];
        foreach ($events as $event) {
            foreach (['introduced', 'fixed', 'last_affected', 'limit'] as $kind) {
                if (! is_array($event) || ! isset($event[$kind]) || ! is_scalar($event[$kind])) {
                    continue;
                }
                $at = (string) $event[$kind] === '0' ? '0' : Version::normalize((string) $event[$kind]);
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

        $intervals = [];
        $open = false;
        $start = null;
        foreach ($timeline as [$at, $kind]) {
            if ($kind === 'introduced') {
                if (! $open) {
                    $open = true;
                    $start = $at === '0' ? null : $at;
                }

                continue;
            }
            if ($open) {
                $intervals[] = [$start, true, $at, $kind === 'last_affected'];
                $open = false;
            }
        }
        if ($open) {
            $intervals[] = [$start, true, null, true];
        }

        return $intervals;
    }

    /**
     * One alternative: comparators that must all hold.
     *
     * @return Interval|false|null false = the comparators contradict each other; null = unreadable
     */
    private static function alternative(string $text, bool &$rangeSyntax): array|false|null
    {
        if ($text === '') {
            return null;
        }
        if (in_array($text, ['*', 'x', 'X', '+'], true)) {
            $rangeSyntax = true;

            return [null, true, null, true];
        }

        // "1.2.3 - 2.3.4": both ends included; a partial upper end covers its whole line.
        if (preg_match('/^v?(\d\S*)\s+-\s+v?(\d\S*)$/i', $text, $m)) {
            if (! Version::isOrderable($m[1]) || ! Version::isOrderable($m[2])) {
                return null;
            }
            $rangeSyntax = true;
            $segments = self::segments($m[2]);
            $partial = count($segments) < 3 && preg_match('/^\d+(\.\d+)*$/', $m[2]);

            return self::intersect(
                [$m[1], true, null, true],
                $partial ? [null, true, self::bump($segments), false] : [null, true, $m[2], true],
            );
        }

        // ">= 1.0" → ">=1.0", then split on spaces, commas and "&&".
        $text = (string) preg_replace('/'.self::OPERATOR.'\s+/', '$1', $text);
        $tokens = preg_split('/[\s,]+|\s*&&\s*/', $text, -1, PREG_SPLIT_NO_EMPTY) ?: [];
        if ($tokens === []) {
            return null;
        }
        if (count($tokens) > 1) {
            $rangeSyntax = true;
        }

        $interval = [null, true, null, true];
        foreach ($tokens as $token) {
            $part = self::comparator($token, $rangeSyntax);
            if ($part === null) {
                return null;
            }
            $interval = self::intersect($interval, $part);
            if ($interval === null || $interval === false) {
                return $interval;
            }
        }

        return $interval;
    }

    /** @return Interval|null */
    private static function comparator(string $token, bool &$rangeSyntax): ?array
    {
        if (! preg_match('/^'.self::OPERATOR.'?v?(\d.*)$/i', $token, $m)) {
            return null;
        }
        [$operator, $version] = [$m[1], $m[2]];
        if ($operator !== '') {
            $rangeSyntax = true;
        }

        // "1.2.x", "1.*", "1.x.x", Gradle's "1.2.+": the whole line under the prefix.
        if (preg_match('/^(\d+(?:\.\d+)*)(?:(?:\.[xX*])+|\.\+)$/', $version, $w)) {
            $rangeSyntax = true;
            $prefix = $w[1];
            $next = self::bump(self::segments($prefix));

            return match ($operator) {
                '', '=', '==' => [$prefix, true, $next, false],
                '>=' => [$prefix, true, null, true],
                '>' => [$next, true, null, true],
                '<' => [null, true, $prefix, false],
                '<=' => [null, true, $next, false],
                '^' => [$prefix, true, self::caretUpper(self::segments($prefix)), false],
                default => [$prefix, true, self::tildeUpper(self::segments($prefix)), false], // ~, ~>, ~=
            };
        }

        if (! Version::isOrderable($version)) {
            return null;
        }

        return match ($operator) {
            '', '=', '==' => [$version, true, $version, true],
            '>=' => [$version, true, null, true],
            '>' => [$version, false, null, true],
            '<' => [null, true, $version, false],
            '<=' => [null, true, $version, true],
            '^' => [$version, true, self::caretUpper(self::segments($version)), false],
            default => [$version, true, self::tildeUpper(self::segments($version)), false], // ~, ~>, ~=
        };
    }

    /**
     * Maven / NuGet interval notation, one interval or a comma-separated union.
     *
     * @return list<Interval>|null
     */
    private static function brackets(string $expression): ?array
    {
        $pattern = '/([\[(])\s*([^,\[\]()]*?)\s*(?:(,)\s*([^,\[\]()]*?)\s*)?([\])])/';
        if (! preg_match_all($pattern, $expression, $groups, PREG_SET_ORDER)
            || trim((string) preg_replace($pattern, '', $expression), ", \t") !== '') {
            return null;
        }

        $intervals = [];
        foreach ($groups as $group) {
            [, $open, $first, $comma, $second, $close] = $group;
            $first = Version::normalize($first);
            $second = Version::normalize($second);
            if (($first !== '' && ! Version::isOrderable($first)) || ($second !== '' && ! Version::isOrderable($second))) {
                return null;
            }

            if ($comma === '') {
                // "[1.0]" — exactly that version; "(1.0)" means nothing.
                if ($open !== '[' || $close !== ']' || $first === '') {
                    return null;
                }
                $intervals[] = [$first, true, $first, true];

                continue;
            }

            $interval = self::intersect(
                [$first !== '' ? $first : null, $open === '[', null, true],
                [null, true, $second !== '' ? $second : null, $close === ']'],
            );
            if ($interval === null) {
                return null;
            }
            if ($interval !== false) {
                $intervals[] = $interval;
            }
        }

        return $intervals === [] ? null : $intervals;
    }

    /**
     * @param  Interval  $a
     * @param  Interval  $b
     * @return Interval|false|null false = nothing in common; null = bounds cannot be ordered
     */
    private static function intersect(array $a, array $b): array|false|null
    {
        // The higher lower bound…
        [$lower, $lowerInclusive] = [$a[0], $a[1]];
        if ($b[0] !== null) {
            $order = $lower === null ? 1 : Version::order($b[0], $lower);
            if ($order === null) {
                return null;
            }
            if ($order > 0) {
                [$lower, $lowerInclusive] = [$b[0], $b[1]];
            } elseif ($order === 0) {
                $lowerInclusive = $lowerInclusive && $b[1];
            }
        }
        // …and the lower upper bound.
        [$upper, $upperInclusive] = [$a[2], $a[3]];
        if ($b[2] !== null) {
            $order = $upper === null ? -1 : Version::order($b[2], $upper);
            if ($order === null) {
                return null;
            }
            if ($order < 0) {
                [$upper, $upperInclusive] = [$b[2], $b[3]];
            } elseif ($order === 0) {
                $upperInclusive = $upperInclusive && $b[3];
            }
        }

        if ($lower !== null && $upper !== null) {
            $order = Version::order($lower, $upper);
            if ($order === null) {
                return null;
            }
            if ($order > 0 || ($order === 0 && ! ($lowerInclusive && $upperInclusive))) {
                return false;
            }
        }

        return [$lower, $lowerInclusive, $upper, $upperInclusive];
    }

    /** @return int[] the numeric core of a version: "1.2.3-rc.1" → [1, 2, 3] */
    private static function segments(string $version): array
    {
        preg_match('/^\d+(?:\.\d+)*/', Version::normalize($version), $m);

        return array_map('intval', explode('.', $m[0] ?? '0'));
    }

    /** @param  int[]  $segments  "1.2" → "1.3": the first version past the line */
    private static function bump(array $segments): string
    {
        $segments[count($segments) - 1]++;

        return implode('.', $segments);
    }

    /**
     * Caret: changes that do not touch the left-most non-zero segment.
     * ^1.2.3 → 2, ^0.2.3 → 0.3, ^0.0.3 → 0.0.4, ^0 → 1.
     *
     * @param  int[]  $segments
     */
    private static function caretUpper(array $segments): string
    {
        $index = count($segments) - 1;
        foreach ($segments as $i => $segment) {
            if ($segment !== 0) {
                $index = $i;
                break;
            }
        }

        return self::bump(array_slice($segments, 0, $index + 1));
    }

    /**
     * Tilde: the last given segment may move. ~1.2.3 → 1.3, ~1.2 → 2, ~1 → 2.
     *
     * @param  int[]  $segments
     */
    private static function tildeUpper(array $segments): string
    {
        return self::bump(array_slice($segments, 0, max(1, count($segments) - 1)));
    }
}
