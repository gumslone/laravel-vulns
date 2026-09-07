<?php

declare(strict_types=1);

namespace Gumslone\Vulns\Support;

/**
 * CVSS v2.0 calculator (base, temporal and environmental equations) per the
 * FIRST specification. Older advisories — and NVD's `cvssMetricV2` block —
 * still carry only a v2 score or vector, and a v2 score without its vector
 * (or the reverse) needs recomputing like the newer standards do.
 *
 * Vectors are the unprefixed NVD form `AV:N/AC:L/Au:N/C:P/I:P/A:P`, with the
 * optional temporal (E/RL/RC) and environmental (CDP/TD/CR/IR/AR) groups.
 * "Not defined" is `ND` (an `X` is accepted as its synonym).
 *
 * @see https://www.first.org/cvss/v2/guide
 */
final class Cvss2
{
    private const AV = ['L' => 0.395, 'A' => 0.646, 'N' => 1.0];

    private const AC = ['H' => 0.35, 'M' => 0.61, 'L' => 0.71];

    private const AU = ['M' => 0.45, 'S' => 0.56, 'N' => 0.704];

    private const CIA = ['N' => 0.0, 'P' => 0.275, 'C' => 0.660];

    private const E = ['U' => 0.85, 'POC' => 0.9, 'F' => 0.95, 'H' => 1.0, 'ND' => 1.0];

    private const RL = ['OF' => 0.87, 'TF' => 0.90, 'W' => 0.95, 'U' => 1.0, 'ND' => 1.0];

    private const RC = ['UC' => 0.90, 'UR' => 0.95, 'C' => 1.0, 'ND' => 1.0];

    private const CDP = ['N' => 0.0, 'L' => 0.1, 'LM' => 0.3, 'MH' => 0.4, 'H' => 0.5, 'ND' => 0.0];

    private const TD = ['N' => 0.0, 'L' => 0.25, 'M' => 0.75, 'H' => 1.0, 'ND' => 1.0];

    private const REQUIREMENT = ['L' => 0.5, 'M' => 1.0, 'H' => 1.51, 'ND' => 1.0];

    public const BASE_METRICS = ['AV', 'AC', 'AU', 'C', 'I', 'A'];

    /**
     * Metric map for a v2 vector — base metrics required and validated,
     * temporal/environmental metrics validated when present, `ND` dropped.
     *
     * @return array<string, string>|null null when malformed
     */
    public static function parse(string $vector): ?array
    {
        $vector = trim($vector, " \t()");
        if (str_starts_with(strtoupper($vector), 'CVSS:2.0/')) {
            $vector = substr($vector, 9);
        }

        $metrics = [];
        foreach (explode('/', $vector) as $part) {
            if (! str_contains($part, ':')) {
                return null;
            }
            [$key, $value] = explode(':', $part, 2);
            $metrics[strtoupper(trim($key))] = strtoupper(trim($value));
        }

        foreach (self::BASE_METRICS as $key) {
            if (! isset($metrics[$key]) || ! isset(self::table($key)[$metrics[$key]])) {
                return null;
            }
        }

        foreach (['E', 'RL', 'RC', 'CDP', 'TD', 'CR', 'IR', 'AR'] as $key) {
            if (! isset($metrics[$key])) {
                continue;
            }
            if ($metrics[$key] === 'X' || $metrics[$key] === 'ND') {
                unset($metrics[$key]);
            } elseif (! isset(self::table($key)[$metrics[$key]])) {
                return null;
            }
        }

        return $metrics;
    }

    public static function baseScore(string $vector): ?float
    {
        $m = self::parse($vector);

        return $m === null ? null : self::base($m, self::impact($m));
    }

    /**
     * Temporal score: base × E × RL × RC.
     *
     * @param  array<string, string>  $modifiers  e.g. ['E' => 'POC', 'RL' => 'OF']; ND/X entries ignored
     */
    public static function temporalScore(string $vector, array $modifiers = []): ?float
    {
        $m = self::parse($vector);
        if ($m === null || ($applied = self::modifiers($modifiers)) === null) {
            return null;
        }
        $m = $applied + $m;

        return self::round(self::base($m, self::impact($m)) * self::temporalFactor($m));
    }

    /**
     * Environmental score per the v2 equation: the impact sub-score adjusted
     * by the CR/IR/AR requirements, re-run through base and temporal, then
     * scaled by collateral damage potential and target distribution.
     *
     * @param  array<string, string>  $modifiers  e.g. ['CDP' => 'LM', 'TD' => 'H', 'CR' => 'H', 'E' => 'F']
     * @return array{score: float, vector: string}|null null when the vector doesn't parse or a modifier value is invalid
     */
    public static function environmental(string $vector, array $modifiers): ?array
    {
        $m = self::parse($vector);
        if ($m === null || ($applied = self::modifiers($modifiers)) === null) {
            return null;
        }
        $m = $applied + $m;

        $adjustedImpact = min(10.0, 10.41 * (1
            - (1 - self::CIA[$m['C']] * self::REQUIREMENT[$m['CR'] ?? 'ND'])
            * (1 - self::CIA[$m['I']] * self::REQUIREMENT[$m['IR'] ?? 'ND'])
            * (1 - self::CIA[$m['A']] * self::REQUIREMENT[$m['AR'] ?? 'ND'])));

        $adjustedTemporal = self::round(self::base($m, $adjustedImpact) * self::temporalFactor($m));
        $cdp = self::CDP[$m['CDP'] ?? 'ND'];
        $td = self::TD[$m['TD'] ?? 'ND'];

        return [
            'score' => self::round(($adjustedTemporal + (10 - $adjustedTemporal) * $cdp) * $td),
            'vector' => self::build($m),
        ];
    }

    /** Canonical string for a metric map (spec order, `Au` in its official casing). */
    public static function build(array $m): string
    {
        $parts = [];
        foreach (['AV', 'AC', 'AU', 'C', 'I', 'A', 'E', 'RL', 'RC', 'CDP', 'TD', 'CR', 'IR', 'AR'] as $key) {
            if (isset($m[$key])) {
                $parts[] = ($key === 'AU' ? 'Au' : $key).':'.$m[$key];
            }
        }

        return implode('/', $parts);
    }

    /** @return array<string, string[]> legal values per metric */
    public static function values(): array
    {
        return array_map('array_keys', [
            'AV' => self::AV, 'AC' => self::AC, 'AU' => self::AU,
            'C' => self::CIA, 'I' => self::CIA, 'A' => self::CIA,
            'E' => self::E, 'RL' => self::RL, 'RC' => self::RC,
            'CDP' => self::CDP, 'TD' => self::TD,
            'CR' => self::REQUIREMENT, 'IR' => self::REQUIREMENT, 'AR' => self::REQUIREMENT,
        ]);
    }

    /** @return array<string, float> */
    private static function table(string $key): array
    {
        return match ($key) {
            'AV' => self::AV, 'AC' => self::AC, 'AU' => self::AU,
            'C', 'I', 'A' => self::CIA,
            'E' => self::E, 'RL' => self::RL, 'RC' => self::RC,
            'CDP' => self::CDP, 'TD' => self::TD,
            'CR', 'IR', 'AR' => self::REQUIREMENT,
            default => [],
        };
    }

    /**
     * Uppercased, validated modifier map; null when a value is illegal (an
     * unknown value must not silently score as "not defined").
     *
     * @return array<string, string>|null
     */
    private static function modifiers(array $modifiers): ?array
    {
        $applied = [];
        foreach ($modifiers as $key => $value) {
            $key = strtoupper((string) $key);
            $value = strtoupper(trim((string) $value));
            if ($value === '' || $value === 'X' || $value === 'ND' || in_array($key, self::BASE_METRICS, true)) {
                continue;
            }
            $table = self::table($key);
            if ($table === []) {
                continue; // unknown key: no-op
            }
            if (! isset($table[$value])) {
                return null;
            }
            $applied[$key] = $value;
        }

        return $applied;
    }

    private static function impact(array $m): float
    {
        return 10.41 * (1 - (1 - self::CIA[$m['C']]) * (1 - self::CIA[$m['I']]) * (1 - self::CIA[$m['A']]));
    }

    private static function base(array $m, float $impact): float
    {
        $exploitability = 20 * self::AV[$m['AV']] * self::AC[$m['AC']] * self::AU[$m['AU']];
        $f = $impact == 0.0 ? 0.0 : 1.176;

        return self::round(((0.6 * $impact) + (0.4 * $exploitability) - 1.5) * $f);
    }

    private static function temporalFactor(array $m): float
    {
        return self::E[$m['E'] ?? 'ND'] * self::RL[$m['RL'] ?? 'ND'] * self::RC[$m['RC'] ?? 'ND'];
    }

    /** One decimal, half up — and never the IEEE "-0.0" a zero product yields. */
    private static function round(float $value): float
    {
        $rounded = round($value, 1);

        return $rounded == 0.0 ? 0.0 : $rounded;
    }
}
