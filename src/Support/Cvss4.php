<?php

declare(strict_types=1);

namespace Gumslone\Vulns\Support;

/**
 * CVSS v4.0 base-score calculator — a faithful port of FIRST's reference
 * implementation (github.com/FIRSTdotorg/cvss-v4-calculator, BSD-2-Clause):
 * the vector's MacroVector is looked up in the official 270-entry table, then
 * the score is interpolated toward the next lower MacroVector by the vector's
 * severity distance from its MacroVector's maximal vectors.
 *
 * Sources like OSV publish only the CVSS:4.0 vector string; without this the
 * advisory would carry no numeric score at all.
 */
final class Cvss4
{
    private const METRIC_LEVELS = [
        'AV' => ['N' => 0.0, 'A' => 0.1, 'L' => 0.2, 'P' => 0.3],
        'PR' => ['N' => 0.0, 'L' => 0.1, 'H' => 0.2],
        'UI' => ['N' => 0.0, 'P' => 0.1, 'A' => 0.2],
        'AC' => ['L' => 0.0, 'H' => 0.1],
        'AT' => ['N' => 0.0, 'P' => 0.1],
        'VC' => ['H' => 0.0, 'L' => 0.1, 'N' => 0.2],
        'VI' => ['H' => 0.0, 'L' => 0.1, 'N' => 0.2],
        'VA' => ['H' => 0.0, 'L' => 0.1, 'N' => 0.2],
        'SC' => ['H' => 0.1, 'L' => 0.2, 'N' => 0.3],
        'SI' => ['S' => 0.0, 'H' => 0.1, 'L' => 0.2, 'N' => 0.3],
        'SA' => ['S' => 0.0, 'H' => 0.1, 'L' => 0.2, 'N' => 0.3],
        'CR' => ['H' => 0.0, 'M' => 0.1, 'L' => 0.2],
        'IR' => ['H' => 0.0, 'M' => 0.1, 'L' => 0.2],
        'AR' => ['H' => 0.0, 'M' => 0.1, 'L' => 0.2],
    ];

    /** Highest-severity vector fragments per EQ level (official max_composed). */
    private const MAX_COMPOSED = [
        'eq1' => [
            0 => ['AV:N/PR:N/UI:N/'],
            1 => ['AV:A/PR:N/UI:N/', 'AV:N/PR:L/UI:N/', 'AV:N/PR:N/UI:P/'],
            2 => ['AV:P/PR:N/UI:N/', 'AV:A/PR:L/UI:P/'],
        ],
        'eq2' => [
            0 => ['AC:L/AT:N/'],
            1 => ['AC:H/AT:N/', 'AC:L/AT:P/'],
        ],
        'eq3' => [
            0 => [
                0 => ['VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/'],
                1 => ['VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/', 'VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/'],
            ],
            1 => [
                0 => ['VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/', 'VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/'],
                1 => ['VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/', 'VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/', 'VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/', 'VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/', 'VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/'],
            ],
            2 => [
                1 => ['VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/'],
            ],
        ],
        'eq4' => [
            0 => ['SC:H/SI:S/SA:S/'],
            1 => ['SC:H/SI:H/SA:H/'],
            2 => ['SC:L/SI:L/SA:L/'],
        ],
        'eq5' => [
            0 => ['E:A/'],
            1 => ['E:P/'],
            2 => ['E:U/'],
        ],
    ];

    /** Max severity distances per EQ MacroVector level (official max_severity). */
    private const MAX_SEVERITY = [
        'eq1' => [0 => 1, 1 => 4, 2 => 5],
        'eq2' => [0 => 1, 1 => 2],
        'eq3eq6' => [0 => [0 => 7, 1 => 6], 1 => [0 => 8, 1 => 8], 2 => [1 => 10]],
        'eq4' => [0 => 6, 1 => 5, 2 => 4],
        'eq5' => [0 => 1, 1 => 1, 2 => 1],
    ];

    /** Official MacroVector score table (cvss_lookup, 270 entries). */
    private const LOOKUP = [
        '000000' => 10, '000001' => 9.9, '000010' => 9.8, '000011' => 9.5, '000020' => 9.5, '000021' => 9.2,
        '000100' => 10, '000101' => 9.6, '000110' => 9.3, '000111' => 8.7, '000120' => 9.1, '000121' => 8.1,
        '000200' => 9.3, '000201' => 9, '000210' => 8.9, '000211' => 8, '000220' => 8.1, '000221' => 6.8,
        '001000' => 9.8, '001001' => 9.5, '001010' => 9.5, '001011' => 9.2, '001020' => 9, '001021' => 8.4,
        '001100' => 9.3, '001101' => 9.2, '001110' => 8.9, '001111' => 8.1, '001120' => 8.1, '001121' => 6.5,
        '001200' => 8.8, '001201' => 8, '001210' => 7.8, '001211' => 7, '001220' => 6.9, '001221' => 4.8,
        '002001' => 9.2, '002011' => 8.2, '002021' => 7.2, '002101' => 7.9, '002111' => 6.9, '002121' => 5,
        '002201' => 6.9, '002211' => 5.5, '002221' => 2.7, '010000' => 9.9, '010001' => 9.7, '010010' => 9.5,
        '010011' => 9.2, '010020' => 9.2, '010021' => 8.5, '010100' => 9.5, '010101' => 9.1, '010110' => 9,
        '010111' => 8.3, '010120' => 8.4, '010121' => 7.1, '010200' => 9.2, '010201' => 8.1, '010210' => 8.2,
        '010211' => 7.1, '010220' => 7.2, '010221' => 5.3, '011000' => 9.5, '011001' => 9.3, '011010' => 9.2,
        '011011' => 8.5, '011020' => 8.5, '011021' => 7.3, '011100' => 9.2, '011101' => 8.2, '011110' => 8,
        '011111' => 7.2, '011120' => 7, '011121' => 5.9, '011200' => 8.4, '011201' => 7, '011210' => 7.1,
        '011211' => 5.2, '011220' => 5, '011221' => 3, '012001' => 8.6, '012011' => 7.5, '012021' => 5.2,
        '012101' => 7.1, '012111' => 5.2, '012121' => 2.9, '012201' => 6.3, '012211' => 2.9, '012221' => 1.7,
        '100000' => 9.8, '100001' => 9.5, '100010' => 9.4, '100011' => 8.7, '100020' => 9.1, '100021' => 8.1,
        '100100' => 9.4, '100101' => 8.9, '100110' => 8.6, '100111' => 7.4, '100120' => 7.7, '100121' => 6.4,
        '100200' => 8.7, '100201' => 7.5, '100210' => 7.4, '100211' => 6.3, '100220' => 6.3, '100221' => 4.9,
        '101000' => 9.4, '101001' => 8.9, '101010' => 8.8, '101011' => 7.7, '101020' => 7.6, '101021' => 6.7,
        '101100' => 8.6, '101101' => 7.6, '101110' => 7.4, '101111' => 5.8, '101120' => 5.9, '101121' => 5,
        '101200' => 7.2, '101201' => 5.7, '101210' => 5.7, '101211' => 5.2, '101220' => 5.2, '101221' => 2.5,
        '102001' => 8.3, '102011' => 7, '102021' => 5.4, '102101' => 6.5, '102111' => 5.8, '102121' => 2.6,
        '102201' => 5.3, '102211' => 2.1, '102221' => 1.3, '110000' => 9.5, '110001' => 9, '110010' => 8.8,
        '110011' => 7.6, '110020' => 7.6, '110021' => 7, '110100' => 9, '110101' => 7.7, '110110' => 7.5,
        '110111' => 6.2, '110120' => 6.1, '110121' => 5.3, '110200' => 7.7, '110201' => 6.6, '110210' => 6.8,
        '110211' => 5.9, '110220' => 5.2, '110221' => 3, '111000' => 8.9, '111001' => 7.8, '111010' => 7.6,
        '111011' => 6.7, '111020' => 6.2, '111021' => 5.8, '111100' => 7.4, '111101' => 5.9, '111110' => 5.7,
        '111111' => 5.7, '111120' => 4.7, '111121' => 2.3, '111200' => 6.1, '111201' => 5.2, '111210' => 5.7,
        '111211' => 2.9, '111220' => 2.4, '111221' => 1.6, '112001' => 7.1, '112011' => 5.9, '112021' => 3,
        '112101' => 5.8, '112111' => 2.6, '112121' => 1.5, '112201' => 2.3, '112211' => 1.3, '112221' => 0.6,
        '200000' => 9.3, '200001' => 8.7, '200010' => 8.6, '200011' => 7.2, '200020' => 7.5, '200021' => 5.8,
        '200100' => 8.6, '200101' => 7.4, '200110' => 7.4, '200111' => 6.1, '200120' => 5.6, '200121' => 3.4,
        '200200' => 7, '200201' => 5.4, '200210' => 5.2, '200211' => 4, '200220' => 4, '200221' => 2.2,
        '201000' => 8.5, '201001' => 7.5, '201010' => 7.4, '201011' => 5.5, '201020' => 6.2, '201021' => 5.1,
        '201100' => 7.2, '201101' => 5.7, '201110' => 5.5, '201111' => 4.1, '201120' => 4.6, '201121' => 1.9,
        '201200' => 5.3, '201201' => 3.6, '201210' => 3.4, '201211' => 1.9, '201220' => 1.9, '201221' => 0.8,
        '202001' => 6.4, '202011' => 5.1, '202021' => 2, '202101' => 4.7, '202111' => 2.1, '202121' => 1.1,
        '202201' => 2.4, '202211' => 0.9, '202221' => 0.4, '210000' => 8.8, '210001' => 7.5, '210010' => 7.3,
        '210011' => 5.3, '210020' => 6, '210021' => 5, '210100' => 7.3, '210101' => 5.5, '210110' => 5.9,
        '210111' => 4, '210120' => 4.1, '210121' => 2, '210200' => 5.4, '210201' => 4.3, '210210' => 4.5,
        '210211' => 2.2, '210220' => 2, '210221' => 1.1, '211000' => 7.5, '211001' => 5.5, '211010' => 5.8,
        '211011' => 4.5, '211020' => 4, '211021' => 2.1, '211100' => 6.1, '211101' => 5.1, '211110' => 4.8,
        '211111' => 1.8, '211120' => 2, '211121' => 0.9, '211200' => 4.6, '211201' => 1.8, '211210' => 1.7,
        '211211' => 0.7, '211220' => 0.8, '211221' => 0.2, '212001' => 5.3, '212011' => 2.4, '212021' => 1.4,
        '212101' => 2.4, '212111' => 1.2, '212121' => 0.5, '212201' => 1, '212211' => 0.3, '212221' => 0.1,
    ];

    /** The base score for a CVSS:4.0 vector string, or null if unparsable. */
    public static function baseScore(string $vector): ?float
    {
        $m = self::parse($vector);
        if ($m === null) {
            return null;
        }

        // No impact anywhere scores a flat zero (official shortcut).
        $noImpact = true;
        foreach (['VC', 'VI', 'VA', 'SC', 'SI', 'SA'] as $metric) {
            if (self::m($m, $metric) !== 'N') {
                $noImpact = false;
                break;
            }
        }
        if ($noImpact) {
            return 0.0;
        }

        $macro = self::macroVector($m);
        $value = self::LOOKUP[$macro] ?? null;
        if ($value === null) {
            return null;
        }
        $value = (float) $value;

        [$eq1, $eq2, $eq3, $eq4, $eq5, $eq6] = array_map('intval', str_split($macro));

        // Scores of the next lower MacroVector per EQ (null when none exists).
        $lower = fn (string $key): ?float => isset(self::LOOKUP[$key]) ? (float) self::LOOKUP[$key] : null;
        $scoreEq1Lower = $lower(($eq1 + 1).$eq2.$eq3.$eq4.$eq5.$eq6);
        $scoreEq2Lower = $lower($eq1.($eq2 + 1).$eq3.$eq4.$eq5.$eq6);
        $scoreEq4Lower = $lower($eq1.$eq2.$eq3.($eq4 + 1).$eq5.$eq6);
        $scoreEq5Lower = $lower($eq1.$eq2.$eq3.$eq4.($eq5 + 1).$eq6);

        // EQ3 and EQ6 are entangled; their combined lower macro follows the
        // official case table, taking the higher-scoring path at 00.
        if ($eq3 === 0 && $eq6 === 0) {
            $left = $lower($eq1.$eq2.$eq3.$eq4.$eq5.($eq6 + 1));
            $right = $lower($eq1.$eq2.($eq3 + 1).$eq4.$eq5.$eq6);
            $scoreEq3Eq6Lower = ($left !== null && ($right === null || $left > $right)) ? $left : $right;
        } elseif ($eq3 === 1 && $eq6 === 0) {
            $scoreEq3Eq6Lower = $lower($eq1.$eq2.$eq3.$eq4.$eq5.($eq6 + 1));
        } else {
            $scoreEq3Eq6Lower = $lower($eq1.$eq2.($eq3 + 1).$eq4.$eq5.$eq6);
        }

        // Severity distance from the first maximal vector that dominates ours.
        $maxVectors = [];
        foreach (self::MAX_COMPOSED['eq1'][$eq1] as $a) {
            foreach (self::MAX_COMPOSED['eq2'][$eq2] as $b) {
                foreach (self::MAX_COMPOSED['eq3'][$eq3][$eq6] as $c) {
                    foreach (self::MAX_COMPOSED['eq4'][$eq4] as $d) {
                        foreach (self::MAX_COMPOSED['eq5'][$eq5] as $e) {
                            $maxVectors[] = $a.$b.$c.$d.$e;
                        }
                    }
                }
            }
        }

        $distance = [];
        foreach ($maxVectors as $maxVector) {
            $distance = [];
            foreach (array_keys(self::METRIC_LEVELS) as $metric) {
                $distance[$metric] = self::METRIC_LEVELS[$metric][self::m($m, $metric)]
                    - self::METRIC_LEVELS[$metric][self::extract($metric, $maxVector)];
            }
            if (min($distance) >= 0) {
                break; // the first dominating max vector is the one
            }
        }

        $step = 0.1;
        $currentEq1 = $distance['AV'] + $distance['PR'] + $distance['UI'];
        $currentEq2 = $distance['AC'] + $distance['AT'];
        $currentEq3Eq6 = $distance['VC'] + $distance['VI'] + $distance['VA']
            + $distance['CR'] + $distance['IR'] + $distance['AR'];
        $currentEq4 = $distance['SC'] + $distance['SI'] + $distance['SA'];

        $existing = 0;
        $normalized = 0.0;
        $contribute = function (?float $lowerScore, float $current, float $maxSeverity) use ($value, &$existing, &$normalized, $step): void {
            if ($lowerScore === null) {
                return;
            }
            $existing++;
            $normalized += ($value - $lowerScore) * ($current / ($maxSeverity * $step));
        };
        $contribute($scoreEq1Lower, $currentEq1, (float) self::MAX_SEVERITY['eq1'][$eq1]);
        $contribute($scoreEq2Lower, $currentEq2, (float) self::MAX_SEVERITY['eq2'][$eq2]);
        $contribute($scoreEq3Eq6Lower, $currentEq3Eq6, (float) self::MAX_SEVERITY['eq3eq6'][$eq3][$eq6]);
        $contribute($scoreEq4Lower, $currentEq4, (float) self::MAX_SEVERITY['eq4'][$eq4]);
        if ($scoreEq5Lower !== null) {
            $existing++; // eq5's proportional distance is always zero
        }

        $value -= $existing > 0 ? $normalized / $existing : 0.0;

        return round(max(0.0, min(10.0, $value)) * 10) / 10;
    }

    /**
     * Metric map from a CVSS:4.0 vector, all optional metrics defaulted to
     * 'X'. Null when the prefix is wrong or a mandatory base metric missing.
     *
     * @return array<string, string>|null
     */
    private static function parse(string $vector): ?array
    {
        $vector = trim($vector, " \t()");
        if (! str_starts_with($vector, 'CVSS:4.0/')) {
            return null;
        }

        $metrics = [];
        foreach (explode('/', substr($vector, 9)) as $part) {
            if (str_contains($part, ':')) {
                [$key, $val] = explode(':', $part, 2);
                $metrics[strtoupper($key)] = strtoupper($val);
            }
        }

        foreach (['AV', 'AC', 'AT', 'PR', 'UI', 'VC', 'VI', 'VA', 'SC', 'SI', 'SA'] as $required) {
            if (! isset($metrics[$required])) {
                return null;
            }
        }

        foreach ([
            'E', 'CR', 'IR', 'AR',
            'MAV', 'MAC', 'MAT', 'MPR', 'MUI', 'MVC', 'MVI', 'MVA', 'MSC', 'MSI', 'MSA',
        ] as $optional) {
            $metrics[$optional] ??= 'X';
        }

        return $metrics;
    }

    /**
     * Effective value of a metric: environmental override when set, worst
     * case for unset threat/requirement metrics — mirrors the reference m().
     */
    private static function m(array $metrics, string $metric): string
    {
        $selected = $metrics[$metric] ?? 'X';

        if ($metric === 'E' && $selected === 'X') {
            return 'A';
        }
        if (in_array($metric, ['CR', 'IR', 'AR'], true) && $selected === 'X') {
            return 'H';
        }

        $modified = $metrics['M'.$metric] ?? 'X';

        return $modified !== 'X' ? $modified : $selected;
    }

    /** The six-digit MacroVector for a metric map. */
    private static function macroVector(array $m): string
    {
        $av = self::m($m, 'AV');
        $pr = self::m($m, 'PR');
        $ui = self::m($m, 'UI');
        if ($av === 'N' && $pr === 'N' && $ui === 'N') {
            $eq1 = 0;
        } elseif ($av !== 'P' && ($av === 'N' || $pr === 'N' || $ui === 'N')) {
            $eq1 = 1;
        } else {
            $eq1 = 2;
        }

        $eq2 = self::m($m, 'AC') === 'L' && self::m($m, 'AT') === 'N' ? 0 : 1;

        $vc = self::m($m, 'VC');
        $vi = self::m($m, 'VI');
        $va = self::m($m, 'VA');
        if ($vc === 'H' && $vi === 'H') {
            $eq3 = 0;
        } elseif ($vc === 'H' || $vi === 'H' || $va === 'H') {
            $eq3 = 1;
        } else {
            $eq3 = 2;
        }

        // EQ4 keys off the raw modified subsequent metrics, not m().
        if (($m['MSI'] ?? '') === 'S' || ($m['MSA'] ?? '') === 'S') {
            $eq4 = 0;
        } elseif (self::m($m, 'SC') === 'H' || self::m($m, 'SI') === 'H' || self::m($m, 'SA') === 'H') {
            $eq4 = 1;
        } else {
            $eq4 = 2;
        }

        $eq5 = match (self::m($m, 'E')) {
            'A' => 0,
            'P' => 1,
            default => 2,
        };

        $eq6 = (self::m($m, 'CR') === 'H' && $vc === 'H')
            || (self::m($m, 'IR') === 'H' && $vi === 'H')
            || (self::m($m, 'AR') === 'H' && $va === 'H') ? 0 : 1;

        return "{$eq1}{$eq2}{$eq3}{$eq4}{$eq5}{$eq6}";
    }

    /** Value of a metric inside a max-vector fragment string. */
    private static function extract(string $metric, string $maxVector): string
    {
        $after = substr($maxVector, strpos($maxVector, $metric.':') + strlen($metric) + 1);
        $slash = strpos($after, '/');

        return $slash === false ? $after : substr($after, 0, $slash);
    }
}
