<?php

declare(strict_types=1);

namespace Gumslone\Vulns\Support;

/**
 * An immutable CVSS vector (v2.0, v3.0, v3.1 or v4.0) split into its metric
 * groups, with the scores each group yields and the operations an assessor
 * needs on one:
 *
 *   $v = CvssVector::parse('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
 *   $v->baseScore();                                        // 9.8
 *   $v->withTemporal(['E' => 'P', 'RL' => 'O'])->temporalScore();   // 8.8
 *   $v->withEnvironmental(['MAV' => 'L', 'CR' => 'L'])->environmentalScore();
 *   $v->merge($theirs);          // my base, their temporal + environmental
 *   (string) $v;                 // canonical vector string, groups in spec order
 *
 * The base group is the advisory's — it never changes through withTemporal /
 * withEnvironmental / merge / fill, so "keep the base score, adjust the
 * temporal or environmental score" is the default rather than a discipline.
 * In v4 terms the "temporal" group is the Threat metric (E) and the
 * supplemental metrics (S, AU, R, V, RE, U) pass through untouched.
 */
final class CvssVector implements \Stringable
{
    /** @var array<string, array<string, string[]>> version family => group => ordered metric keys */
    private const GROUPS = [
        '2.0' => [
            'base' => ['AV', 'AC', 'AU', 'C', 'I', 'A'],
            'temporal' => ['E', 'RL', 'RC'],
            'environmental' => ['CDP', 'TD', 'CR', 'IR', 'AR'],
            'supplemental' => [],
        ],
        '3.x' => [
            'base' => ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'],
            'temporal' => ['E', 'RL', 'RC'],
            'environmental' => ['CR', 'IR', 'AR', 'MAV', 'MAC', 'MPR', 'MUI', 'MS', 'MC', 'MI', 'MA'],
            'supplemental' => [],
        ],
        '4.0' => [
            'base' => ['AV', 'AC', 'AT', 'PR', 'UI', 'VC', 'VI', 'VA', 'SC', 'SI', 'SA'],
            'temporal' => ['E'],
            'environmental' => ['CR', 'IR', 'AR', 'MAV', 'MAC', 'MAT', 'MPR', 'MUI', 'MVC', 'MVI', 'MVA', 'MSC', 'MSI', 'MSA'],
            'supplemental' => ['S', 'AU', 'R', 'V', 'RE', 'U'],
        ],
    ];

    /** @var array<string, array<string, string[]>> legal values per metric, per version family */
    private const VALUES = [
        '3.x' => [
            'AV' => ['N', 'A', 'L', 'P'], 'AC' => ['L', 'H'], 'PR' => ['N', 'L', 'H'], 'UI' => ['N', 'R'],
            'S' => ['U', 'C'], 'C' => ['H', 'L', 'N'], 'I' => ['H', 'L', 'N'], 'A' => ['H', 'L', 'N'],
            'E' => ['U', 'P', 'F', 'H'], 'RL' => ['O', 'T', 'W', 'U'], 'RC' => ['U', 'R', 'C'],
            'CR' => ['L', 'M', 'H'], 'IR' => ['L', 'M', 'H'], 'AR' => ['L', 'M', 'H'],
            'MAV' => ['N', 'A', 'L', 'P'], 'MAC' => ['L', 'H'], 'MPR' => ['N', 'L', 'H'], 'MUI' => ['N', 'R'],
            'MS' => ['U', 'C'], 'MC' => ['H', 'L', 'N'], 'MI' => ['H', 'L', 'N'], 'MA' => ['H', 'L', 'N'],
        ],
        '4.0' => [
            'AV' => ['N', 'A', 'L', 'P'], 'AC' => ['L', 'H'], 'AT' => ['N', 'P'], 'PR' => ['N', 'L', 'H'],
            'UI' => ['N', 'P', 'A'], 'VC' => ['H', 'L', 'N'], 'VI' => ['H', 'L', 'N'], 'VA' => ['H', 'L', 'N'],
            'SC' => ['H', 'L', 'N'], 'SI' => ['S', 'H', 'L', 'N'], 'SA' => ['S', 'H', 'L', 'N'],
            'E' => ['A', 'P', 'U'],
            'CR' => ['H', 'M', 'L'], 'IR' => ['H', 'M', 'L'], 'AR' => ['H', 'M', 'L'],
            'MAV' => ['N', 'A', 'L', 'P'], 'MAC' => ['L', 'H'], 'MAT' => ['N', 'P'], 'MPR' => ['N', 'L', 'H'],
            'MUI' => ['N', 'P', 'A'], 'MVC' => ['H', 'L', 'N'], 'MVI' => ['H', 'L', 'N'], 'MVA' => ['H', 'L', 'N'],
            'MSC' => ['H', 'L', 'N'], 'MSI' => ['S', 'H', 'L', 'N'], 'MSA' => ['S', 'H', 'L', 'N'],
            'S' => ['N', 'P'], 'AU' => ['N', 'Y'], 'R' => ['A', 'U', 'I'], 'V' => ['D', 'C'], 'RE' => ['L', 'M', 'H'],
            'U' => ['CLEAR', 'GREEN', 'AMBER', 'RED'],
        ],
    ];

    /** Official casing for the few metric values that aren't a bare uppercase letter. */
    private const CASING = ['CLEAR' => 'Clear', 'GREEN' => 'Green', 'AMBER' => 'Amber', 'RED' => 'Red'];

    /**
     * @param  array<string, string>  $metrics  uppercase key => uppercase value, base group complete
     */
    private function __construct(
        private readonly string $version,
        private readonly array $metrics,
    ) {}

    /**
     * Parse any CVSS vector string. Null when the version can't be told, a
     * base metric is missing, or a value is illegal — never a "best effort"
     * object that would score as something the source didn't say. Unknown
     * metric keys are ignored; "not defined" entries (X / ND) are dropped.
     */
    public static function parse(string $vector): ?self
    {
        $vector = trim($vector, " \t()");
        $version = self::versionOf($vector);
        if ($version === null) {
            return null;
        }

        if ($version === '2.0') {
            $metrics = Cvss2::parse($vector);

            return $metrics === null ? null : new self($version, $metrics);
        }

        $body = preg_replace('/^CVSS:\d\.\d\//i', '', $vector) ?? $vector;
        $family = self::family($version);
        $metrics = [];
        foreach (explode('/', $body) as $part) {
            if (! str_contains($part, ':')) {
                return null;
            }
            [$key, $value] = explode(':', $part, 2);
            $key = strtoupper(trim($key));
            $value = strtoupper(trim($value));
            if (! isset(self::VALUES[$family][$key])) {
                continue;
            }
            if ($value === 'X' || $value === '') {
                continue;
            }
            if (! in_array($value, self::VALUES[$family][$key], true)) {
                return null;
            }
            $metrics[$key] = $value;
        }

        foreach (self::GROUPS[$family]['base'] as $key) {
            if (! isset($metrics[$key])) {
                return null;
            }
        }

        return new self($version, $metrics);
    }

    /** A representative base vector for a score (see CvssVectorTable). */
    public static function fromScore(int $majorVersion, float $score): ?self
    {
        $vector = CvssVectorTable::vectorFor($majorVersion, $score);

        return $vector === null ? null : self::parse($vector);
    }

    /**
     * The CVSS version a vector string is written in — '2.0', '3.0', '3.1',
     * '4.0' — from its prefix, or for the unprefixed v2 form from the
     * Authentication metric (`Au:`) that v3 replaced with PR. An unprefixed
     * vector carrying PR: and S: is taken as 3.1. Null when neither applies.
     */
    public static function versionOf(string $vector): ?string
    {
        $vector = trim($vector, " \t()");
        if (preg_match('/^CVSS:(2\.0|3\.0|3\.1|4\.0)\//i', $vector, $m)) {
            return $m[1];
        }
        if (str_starts_with(strtoupper($vector), 'CVSS:')) {
            return null;
        }
        if (preg_match('/(?:^|\/)AU:/i', $vector)) {
            return '2.0';
        }
        if (preg_match('/(?:^|\/)PR:/i', $vector) && preg_match('/(?:^|\/)S:/i', $vector)) {
            return '3.1';
        }

        return null;
    }

    /** 2, 3 or 4 — the slot a vector belongs to on VulnerabilityData. Null when unrecognisable. */
    public static function majorVersionOf(string $vector): ?int
    {
        $version = self::versionOf($vector);

        return $version === null ? null : (int) $version[0];
    }

    public function version(): string
    {
        return $this->version;
    }

    public function majorVersion(): int
    {
        return (int) $this->version[0];
    }

    /** @return array<string, string> every metric, canonical order */
    public function metrics(): array
    {
        $ordered = [];
        foreach (self::GROUPS[self::family($this->version)] as $keys) {
            foreach ($keys as $key) {
                if (isset($this->metrics[$key])) {
                    $ordered[$key] = $this->metrics[$key];
                }
            }
        }

        return $ordered;
    }

    public function metric(string $key): ?string
    {
        return $this->metrics[strtoupper($key)] ?? null;
    }

    /** @return array<string, string> */
    public function temporal(): array
    {
        return $this->group('temporal');
    }

    /** @return array<string, string> */
    public function environmental(): array
    {
        return $this->group('environmental');
    }

    /** @return array<string, string> v4 supplemental metrics; empty for other versions */
    public function supplemental(): array
    {
        return $this->group('supplemental');
    }

    public function hasTemporal(): bool
    {
        return $this->temporal() !== [];
    }

    public function hasEnvironmental(): bool
    {
        return $this->environmental() !== [];
    }

    /** The base group alone. */
    public function base(): self
    {
        return new self($this->version, $this->group('base'));
    }

    public function baseVector(): string
    {
        return $this->base()->toString();
    }

    public function baseScore(): ?float
    {
        return $this->scoreFor([]);
    }

    /**
     * Base × temporal group (v4: the Threat metric). Equals the base score
     * when no temporal metric is set — the specification's "not defined"
     * semantics, not an error.
     */
    public function temporalScore(): ?float
    {
        return $this->scoreFor($this->temporal());
    }

    /** Alias of temporalScore() in v4 vocabulary. */
    public function threatScore(): ?float
    {
        return $this->temporalScore();
    }

    /** Base × temporal × environmental groups — the score for the vector as written. */
    public function environmentalScore(): ?float
    {
        return $this->scoreFor($this->temporal() + $this->environmental());
    }

    /**
     * The score this vector expresses: environmental when environmental
     * metrics are set, else temporal when those are, else base.
     */
    public function score(): ?float
    {
        return match (true) {
            $this->hasEnvironmental() => $this->environmentalScore(),
            $this->hasTemporal() => $this->temporalScore(),
            default => $this->baseScore(),
        };
    }

    /**
     * A copy with temporal metrics set (v3: E/RL/RC, v4: E, v2: E/RL/RC).
     * `X` / `ND` / null removes a metric. Keys outside the group or illegal
     * values throw — a silent no-op would leave a score unadjusted.
     *
     * @param  array<string, string|null>  $metrics
     */
    public function withTemporal(array $metrics): self
    {
        return $this->with($metrics, 'temporal');
    }

    /**
     * A copy with environmental metrics set (v3: CR/IR/AR + MAV…MA, v4:
     * CR/IR/AR + MAV…MSA, v2: CDP/TD/CR/IR/AR). Same rules as withTemporal().
     *
     * @param  array<string, string|null>  $metrics
     */
    public function withEnvironmental(array $metrics): self
    {
        return $this->with($metrics, 'environmental');
    }

    /**
     * A copy with any metrics overlaid — temporal, environmental or
     * supplemental in one call. Base metrics can be replaced but never
     * removed. Throws on unknown keys or illegal values.
     *
     * @param  array<string, string|null>  $metrics
     */
    public function with(array $metrics, ?string $onlyGroup = null): self
    {
        $family = self::family($this->version);
        $values = $family === '2.0' ? Cvss2::values() : self::VALUES[$family];
        $merged = $this->metrics;

        foreach ($metrics as $key => $value) {
            $key = strtoupper((string) $key);
            if (! isset($values[$key])) {
                throw new \InvalidArgumentException("Unknown CVSS v{$this->version} metric '{$key}'.");
            }
            $group = $this->groupOf($key);
            if ($onlyGroup !== null && $group !== $onlyGroup) {
                throw new \InvalidArgumentException("'{$key}' is a {$group} metric, not a {$onlyGroup} one.");
            }

            $value = strtoupper(trim((string) $value));
            if ($value === '' || $value === 'X' || $value === 'ND') {
                if ($group === 'base') {
                    throw new \InvalidArgumentException("Base metric '{$key}' cannot be unset.");
                }
                unset($merged[$key]);

                continue;
            }
            if (! in_array($value, $values[$key], true)) {
                throw new \InvalidArgumentException(sprintf(
                    "Illegal value '%s' for CVSS v%s metric %s (allowed: %s).",
                    $value, $this->version, $key, implode(', ', $values[$key]),
                ));
            }
            $merged[$key] = $value;
        }

        return new self($this->version, $merged);
    }

    public function withoutTemporal(): self
    {
        return new self($this->version, array_diff_key($this->metrics, $this->temporal()));
    }

    public function withoutEnvironmental(): self
    {
        return new self($this->version, array_diff_key($this->metrics, $this->environmental()));
    }

    /** Base (+ supplemental) only — every temporal and environmental metric dropped. */
    public function withoutModifiers(): self
    {
        return $this->withoutTemporal()->withoutEnvironmental();
    }

    /**
     * Merge two vectors of the same major version: keep this vector's base
     * group and take the other's temporal + environmental metrics — the
     * other's win where both set one, this vector's remain where only it
     * does. With $keepBase = false the roles flip (the other's base, this
     * vector's modifiers on top). Throws when the versions differ — a v3
     * environmental group means nothing on a v4 base.
     */
    public function merge(self|string $other, bool $keepBase = true): self
    {
        $other = $this->sibling($other, 'merge');
        if (! $keepBase) {
            return $other->merge($this);
        }

        return new self($this->version, $this->group('base') + $this->supplemental()
            + $other->temporal() + $other->environmental() + $this->temporal() + $this->environmental());
    }

    /**
     * Fill gaps only: this vector's metrics all win, the other's temporal /
     * environmental metrics are added where this vector has none.
     */
    public function fill(self|string $other): self
    {
        $other = $this->sibling($other, 'fill');

        return new self($this->version, $this->metrics + $other->temporal() + $other->environmental());
    }

    public function equals(self|string $other): bool
    {
        $other = is_string($other) ? self::parse($other) : $other;

        return $other !== null && $this->toString() === $other->toString();
    }

    /** Canonical form: version prefix, then base / temporal / environmental / supplemental in spec order. */
    public function toString(): string
    {
        if ($this->version === '2.0') {
            return Cvss2::build($this->metrics);
        }

        $parts = ["CVSS:{$this->version}"];
        foreach ($this->metrics() as $key => $value) {
            $parts[] = $key.':'.(self::CASING[$value] ?? $value);
        }

        return implode('/', $parts);
    }

    public function __toString(): string
    {
        return $this->toString();
    }

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return [
            'version' => $this->version,
            'vector' => $this->toString(),
            'base_vector' => $this->baseVector(),
            'base_score' => $this->baseScore(),
            'temporal_score' => $this->temporalScore(),
            'environmental_score' => $this->environmentalScore(),
            'score' => $this->score(),
            'temporal' => $this->temporal(),
            'environmental' => $this->environmental(),
        ];
    }

    /** @param array<string, string> $modifiers temporal/environmental metrics to apply on the base */
    private function scoreFor(array $modifiers): ?float
    {
        $base = $this->baseVector();
        $family = self::family($this->version);
        if ($modifiers === []) {
            return match ($family) {
                '2.0' => Cvss2::baseScore($base),
                '3.x' => (new CvssCalculator)->baseScore($base),
                '4.0' => Cvss4::baseScore($base),
            };
        }

        // The temporal equation (Roundup(Base × E × RL × RC)) is NOT the
        // environmental one with no modified metrics — v3.1's modified-impact
        // term and v2's capped adjusted impact differ from the base
        // equations, so a temporal-only set must take the temporal path.
        $environmental = array_intersect_key($modifiers, array_flip(self::GROUPS[$family]['environmental'])) !== [];

        return match ($family) {
            '2.0' => $environmental ? (Cvss2::environmental($base, $modifiers)['score'] ?? null) : Cvss2::temporalScore($base, $modifiers),
            '3.x' => $environmental ? ((new CvssCalculator)->environmental($base, $modifiers)['score'] ?? null) : (new CvssCalculator)->temporalScore($base, $modifiers),
            '4.0' => Cvss4::environmental($base, $modifiers)['score'] ?? null, // v4 scores E natively
        };
    }

    /** @return array<string, string> */
    private function group(string $group): array
    {
        $out = [];
        foreach (self::GROUPS[self::family($this->version)][$group] as $key) {
            if (isset($this->metrics[$key])) {
                $out[$key] = $this->metrics[$key];
            }
        }

        return $out;
    }

    private function groupOf(string $key): string
    {
        foreach (self::GROUPS[self::family($this->version)] as $group => $keys) {
            if (in_array($key, $keys, true)) {
                return $group;
            }
        }

        throw new \InvalidArgumentException("Unknown CVSS v{$this->version} metric '{$key}'.");
    }

    private function sibling(self|string $other, string $operation): self
    {
        $parsed = is_string($other) ? self::parse($other) : $other;
        if ($parsed === null) {
            throw new \InvalidArgumentException("Cannot {$operation}: '{$other}' is not a valid CVSS vector.");
        }
        if ($parsed->majorVersion() !== $this->majorVersion()) {
            throw new \InvalidArgumentException(sprintf(
                'Cannot %s a CVSS v%s vector into a v%s one — the metric groups are not compatible.',
                $operation, $parsed->version(), $this->version,
            ));
        }

        return $parsed;
    }

    private static function family(string $version): string
    {
        return $version[0] === '3' ? '3.x' : $version;
    }
}
