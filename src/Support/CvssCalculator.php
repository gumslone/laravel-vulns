<?php

declare(strict_types=1);

namespace Gumslone\Vulns\Support;

/**
 * CVSS v3.0 / v3.1 score calculator (base and environmental metric groups).
 *
 * Implements the FIRST.org specification so an assessor can recompute a
 * vulnerability's score for their specific environment — e.g. lowering the
 * attack vector for an air-gapped deployment, or raising confidentiality
 * requirements for a system handling sensitive data.
 *
 * @see https://www.first.org/cvss/v3.1/specification-document
 */
class CvssCalculator
{
    private const AV = ['N' => 0.85, 'A' => 0.62, 'L' => 0.55, 'P' => 0.2];

    private const AC = ['L' => 0.77, 'H' => 0.44];

    private const PR_UNCHANGED = ['N' => 0.85, 'L' => 0.62, 'H' => 0.27];

    private const PR_CHANGED = ['N' => 0.85, 'L' => 0.68, 'H' => 0.5];

    private const UI = ['N' => 0.85, 'R' => 0.62];

    private const CIA = ['H' => 0.56, 'L' => 0.22, 'N' => 0.0];

    private const REQUIREMENT = ['H' => 1.5, 'M' => 1.0, 'L' => 0.5, 'X' => 1.0];

    // Temporal metric groups
    private const E = ['X' => 1.0, 'H' => 1.0, 'F' => 0.97, 'P' => 0.94, 'U' => 0.91];

    private const RL = ['X' => 1.0, 'U' => 1.0, 'W' => 0.97, 'T' => 0.96, 'O' => 0.95];

    private const RC = ['X' => 1.0, 'C' => 1.0, 'R' => 0.96, 'U' => 0.92];

    /** Base metrics required in a valid vector. */
    private const BASE_METRICS = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'];

    /**
     * Parse a CVSS v3.x vector string into its metric map.
     *
     * @return array<string, string>|null null when the vector is malformed
     */
    public function parse(string $vector): ?array
    {
        $vector = trim($vector);
        $parts = explode('/', $vector);

        // Optional "CVSS:3.x" prefix
        if ($parts && str_starts_with($parts[0], 'CVSS:')) {
            array_shift($parts);
        }

        $metrics = [];
        foreach ($parts as $part) {
            if (! str_contains($part, ':')) {
                return null;
            }
            [$key, $value] = explode(':', $part, 2);
            $metrics[strtoupper($key)] = strtoupper($value);
        }

        // Every base metric must be present AND carry a valid value — an
        // out-of-range value (e.g. "C:Z") must yield null, not a silently
        // under-scored vector.
        $allowed = [
            'AV' => ['N', 'A', 'L', 'P'], 'AC' => ['L', 'H'], 'PR' => ['N', 'L', 'H'],
            'UI' => ['N', 'R'], 'S' => ['U', 'C'],
            'C' => ['H', 'L', 'N'], 'I' => ['H', 'L', 'N'], 'A' => ['H', 'L', 'N'],
        ];
        foreach ($allowed as $key => $valid) {
            if (! isset($metrics[$key]) || ! in_array($metrics[$key], $valid, true)) {
                return null;
            }
        }

        return $metrics;
    }

    /**
     * Base score for a vector string, or null when it can't be parsed.
     */
    public function baseScore(string $vector): ?float
    {
        // v4.0 vectors use a different scoring system entirely — route them
        // to the MacroVector calculator so callers can stay version-agnostic.
        if (str_starts_with(ltrim($vector), 'CVSS:4.0/')) {
            return Cvss4::baseScore($vector);
        }

        $m = $this->parse($vector);

        return $m ? $this->computeBase($m) : null;
    }

    /**
     * Temporal score for a vector, factoring in Exploit Code Maturity (E),
     * Remediation Level (RL), and Report Confidence (RC). Null on parse error.
     *
     * @param  array<string, string>  $modifiers  e.g. ['E' => 'F', 'RL' => 'O']
     */
    public function temporalScore(string $baseVector, array $modifiers = []): ?float
    {
        $base = $this->baseScore($baseVector);
        if ($base === null) {
            return null;
        }

        $modifiers = array_map('strtoupper', $modifiers);

        return $this->roundUp($base * $this->temporalFactor($modifiers));
    }

    /**
     * Recompute the environmental score after applying modified base metrics,
     * security requirements, and the temporal group. Metrics left as 'X' (or
     * omitted) fall back to the corresponding base value.
     *
     * @param  array<string, string>  $modifiers  e.g. ['MAV' => 'L', 'CR' => 'H', 'E' => 'F']
     * @return array{score: float, vector: string}|null
     */
    public function environmental(string $baseVector, array $modifiers): ?array
    {
        $base = $this->parse($baseVector);
        if (! $base) {
            return null;
        }

        $modifiers = array_map('strtoupper', array_filter($modifiers, fn ($v) => $v !== null && $v !== ''));

        $get = fn (string $modified, string $baseKey) => (($modifiers[$modified] ?? 'X') !== 'X')
            ? $modifiers[$modified]
            : $base[$baseKey];

        $mav = $get('MAV', 'AV');
        $mac = $get('MAC', 'AC');
        $mui = $get('MUI', 'UI');
        $ms = $get('MS', 'S');
        $mpr = $get('MPR', 'PR');
        $mc = $get('MC', 'C');
        $mi = $get('MI', 'I');
        $ma = $get('MA', 'A');

        $cr = $modifiers['CR'] ?? 'X';
        $ir = $modifiers['IR'] ?? 'X';
        $ar = $modifiers['AR'] ?? 'X';

        $scopeChanged = $ms === 'C';

        $miss = min(
            1 - (
                (1 - self::REQUIREMENT[$cr] * self::CIA[$mc])
                * (1 - self::REQUIREMENT[$ir] * self::CIA[$mi])
                * (1 - self::REQUIREMENT[$ar] * self::CIA[$ma])
            ),
            0.915,
        );

        $modifiedImpact = $scopeChanged
            ? 7.52 * ($miss - 0.029) - 3.25 * (($miss * 0.9731 - 0.02) ** 13)
            : 6.42 * $miss;

        $prTable = $scopeChanged ? self::PR_CHANGED : self::PR_UNCHANGED;
        $modifiedExploitability = 8.22 * self::AV[$mav] * self::AC[$mac] * $prTable[$mpr] * self::UI[$mui];

        if ($modifiedImpact <= 0) {
            $score = 0.0;
        } else {
            $raw = $scopeChanged
                ? 1.08 * ($modifiedImpact + $modifiedExploitability)
                : $modifiedImpact + $modifiedExploitability;
            $score = $this->roundUp($this->roundUp(min($raw, 10)) * $this->temporalFactor($modifiers));
        }

        return [
            'score' => $score,
            'vector' => $this->buildEnvironmentalVector($base, $modifiers),
        ];
    }

    /**
     * Combined temporal multiplier E × RL × RC.
     *
     * @param  array<string, string>  $modifiers
     */
    private function temporalFactor(array $modifiers): float
    {
        return self::E[$modifiers['E'] ?? 'X']
            * self::RL[$modifiers['RL'] ?? 'X']
            * self::RC[$modifiers['RC'] ?? 'X'];
    }

    private function computeBase(array $m): float
    {
        $scopeChanged = ($m['S'] ?? 'U') === 'C';

        $iss = 1 - ((1 - self::CIA[$m['C']]) * (1 - self::CIA[$m['I']]) * (1 - self::CIA[$m['A']]));

        $impact = $scopeChanged
            ? 7.52 * ($iss - 0.029) - 3.25 * (($iss - 0.02) ** 15)
            : 6.42 * $iss;

        $prTable = $scopeChanged ? self::PR_CHANGED : self::PR_UNCHANGED;
        $exploitability = 8.22 * self::AV[$m['AV']] * self::AC[$m['AC']] * $prTable[$m['PR']] * self::UI[$m['UI']];

        if ($impact <= 0) {
            return 0.0;
        }

        $raw = $scopeChanged ? 1.08 * ($impact + $exploitability) : $impact + $exploitability;

        return $this->roundUp(min($raw, 10));
    }

    /**
     * CVSS v3.1 "Roundup": round up to one decimal place.
     */
    private function roundUp(float $value): float
    {
        $scaled = (int) round($value * 100000);

        if ($scaled % 10000 === 0) {
            return $scaled / 100000;
        }

        return (floor($scaled / 10000) + 1) / 10;
    }

    /**
     * @param  array<string, string>  $base
     * @param  array<string, string>  $modifiers
     */
    private function buildEnvironmentalVector(array $base, array $modifiers): string
    {
        $order = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'];
        $parts = ['CVSS:3.1'];

        foreach ($order as $key) {
            $parts[] = "{$key}:{$base[$key]}";
        }

        foreach (['E', 'RL', 'RC', 'MAV', 'MAC', 'MPR', 'MUI', 'MS', 'MC', 'MI', 'MA', 'CR', 'IR', 'AR'] as $key) {
            if (isset($modifiers[$key]) && $modifiers[$key] !== 'X') {
                $parts[] = "{$key}:{$modifiers[$key]}";
            }
        }

        return implode('/', $parts);
    }

    /**
     * Qualitative severity label for a numeric score.
     */
    public function severityLabel(float $score): string
    {
        return match (true) {
            $score >= 9.0 => 'critical',
            $score >= 7.0 => 'high',
            $score >= 4.0 => 'medium',
            $score > 0.0 => 'low',
            default => 'none',
        };
    }
}
