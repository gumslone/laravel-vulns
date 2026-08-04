<?php

declare(strict_types=1);

namespace Gumslone\Vulns;

/**
 * Normalized severity across all sources. Mirrors the CVSS qualitative
 * rating scale; `Unknown` is for advisories with neither a score nor a label.
 */
enum Severity: string
{
    case Critical = 'critical';
    case High = 'high';
    case Medium = 'medium';
    case Low = 'low';
    case Unknown = 'unknown';

    public static function fromCvssScore(?float $score): self
    {
        return match (true) {
            $score === null => self::Unknown,
            $score >= 9.0 => self::Critical,
            $score >= 7.0 => self::High,
            $score >= 4.0 => self::Medium,
            $score > 0.0 => self::Low,
            default => self::Unknown,
        };
    }

    /** Case-insensitive label mapping ("MODERATE", "important", …). */
    public static function fromLabel(?string $label): self
    {
        return match (strtolower(trim((string) $label))) {
            'critical' => self::Critical,
            'high', 'important' => self::High,
            'medium', 'moderate' => self::Medium,
            'low', 'minor' => self::Low,
            default => self::Unknown,
        };
    }

    /** Numeric weight for ordering (critical highest). */
    public function weight(): int
    {
        return match ($this) {
            self::Critical => 4,
            self::High => 3,
            self::Medium => 2,
            self::Low => 1,
            self::Unknown => 0,
        };
    }
}
