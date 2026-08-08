<?php

declare(strict_types=1);

namespace Gumslone\Vulns;

use Gumslone\Vulns\Data\VulnerabilityData;

/**
 * The classified difference between two snapshots of the same advisory —
 * what a re-query changed and how much it matters. Build one with
 * VulnChange::between($previous, $current) after refreshing a stored
 * vulnerability, then route on ->impact(): major changes (rescores in either
 * direction, severity shifts, range edits, a fix appearing) should reopen
 * triage; minor ones (wording, references) can update silently.
 */
final class VulnChange
{
    /**
     * @param  ChangeType[]  $changes
     * @param  array<string, array{0: mixed, 1: mixed}>  $details  field => [from, to]
     */
    private function __construct(
        public readonly string $vulnId,
        public readonly array $changes,
        public readonly array $details,
    ) {}

    public static function between(VulnerabilityData $previous, VulnerabilityData $current): self
    {
        $changes = [];
        $details = [];

        // Compare like with like: v4-to-v4 when both snapshots carry v4,
        // else v3-to-v3 — never a v4 score against a v3 one, the scales are
        // calibrated differently.
        if ($previous->cvssV4Score !== null && $current->cvssV4Score !== null) {
            [$oldScore, $newScore, $detailKey] = [$previous->cvssV4Score, $current->cvssV4Score, 'cvss_v4_score'];
        } else {
            [$oldScore, $newScore, $detailKey] = [$previous->cvssV3Score, $current->cvssV3Score, 'cvss_v3_score'];
        }
        // A source dropping its score (value → null) is data loss upstream,
        // not a rescore — only value-to-value and first-time scores classify.
        if ($newScore !== null && $newScore !== $oldScore) {
            $changes[] = $oldScore === null || $newScore > $oldScore
                ? ChangeType::ScoreIncreased
                : ChangeType::ScoreDecreased;
            $details[$detailKey] = [$oldScore, $newScore];
        }

        if ($current->severity !== Severity::Unknown && $current->severity !== $previous->severity) {
            $changes[] = $previous->severity === Severity::Unknown
                || $current->severity->weight() > $previous->severity->weight()
                ? ChangeType::SeverityRaised
                : ChangeType::SeverityLowered;
            $details['severity'] = [$previous->severity->value, $current->severity->value];
        }

        if ($current->affectedRanges !== [] && $current->affectedRanges !== $previous->affectedRanges) {
            $changes[] = ChangeType::RangesChanged;
        }

        $newFixes = array_diff($current->fixedVersions, $previous->fixedVersions);
        if (($current->isFixed && ! $previous->isFixed) || $newFixes !== []) {
            $changes[] = ChangeType::FixAvailable;
            if ($newFixes !== []) {
                $details['fixed_versions'] = [$previous->fixedVersions, $current->fixedVersions];
            }
        }

        if (self::textChanged($previous->summary, $current->summary)
            || self::textChanged($previous->details, $current->details)) {
            $changes[] = ChangeType::DescriptionUpdated;
        }

        if ($current->references !== [] && self::setChanged($previous->references, $current->references)) {
            $changes[] = ChangeType::ReferencesUpdated;
        }

        if (self::setChanged($previous->aliases, $current->aliases)) {
            $changes[] = ChangeType::AliasesUpdated;
        }

        if ($current->cwes !== [] && self::setChanged($previous->cwes, $current->cwes)) {
            $changes[] = ChangeType::MetadataUpdated;
        }

        return new self($current->vulnId, $changes, $details);
    }

    /** The heaviest impact among all detected changes. */
    public function impact(): ChangeImpact
    {
        $impact = ChangeImpact::None;
        foreach ($this->changes as $change) {
            if ($change->impact()->weight() > $impact->weight()) {
                $impact = $change->impact();
            }
        }

        return $impact;
    }

    public function hasChanges(): bool
    {
        return $this->changes !== [];
    }

    public function isMajor(): bool
    {
        return $this->impact() === ChangeImpact::Major;
    }

    public function has(ChangeType $type): bool
    {
        return in_array($type, $this->changes, true);
    }

    /**
     * Human-readable one-liner for logs and notifications, e.g.
     * "score increased (5.0 → 8.1), description updated".
     */
    public function summary(): string
    {
        if ($this->changes === []) {
            return 'no changes';
        }

        return implode(', ', array_map(function (ChangeType $change): string {
            $label = str_replace('_', ' ', $change->value);

            $score = $this->details['cvss_v4_score'] ?? $this->details['cvss_v3_score'] ?? null;

            return match ($change) {
                ChangeType::ScoreIncreased, ChangeType::ScoreDecreased => sprintf(
                    '%s (%s → %s)', $label, $score[0] ?? '—', $score[1] ?? '—',
                ),
                ChangeType::SeverityRaised, ChangeType::SeverityLowered => sprintf(
                    '%s (%s → %s)', $label,
                    $this->details['severity'][0] ?? '—', $this->details['severity'][1] ?? '—',
                ),
                default => $label,
            };
        }, $this->changes));
    }

    private static function textChanged(?string $old, ?string $new): bool
    {
        return $new !== null && trim($new) !== trim($old ?? '');
    }

    /** Order-insensitive comparison for list fields sources emit unordered. */
    private static function setChanged(array $old, array $new): bool
    {
        $normalize = function (array $items): array {
            $out = array_map(fn ($i) => is_scalar($i) ? (string) $i : json_encode($i), $items);
            sort($out);

            return $out;
        };

        return $normalize($old) !== $normalize($new);
    }
}
