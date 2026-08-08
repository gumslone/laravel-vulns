<?php

declare(strict_types=1);

namespace Gumslone\Vulns;

/**
 * What specifically changed between two snapshots of the same advisory.
 * A downgrade is deliberately as major as an upgrade: it can release an
 * SLA-tracked assessment, which is a decision someone should look at —
 * not something to slip through unnoticed.
 */
enum ChangeType: string
{
    case ScoreIncreased = 'score_increased';
    case ScoreDecreased = 'score_decreased';
    case SeverityRaised = 'severity_raised';
    case SeverityLowered = 'severity_lowered';
    case RangesChanged = 'ranges_changed';
    case FixAvailable = 'fix_available';
    case KnownExploited = 'known_exploited';
    case ExploitationLikely = 'exploitation_likely';
    case EpssChanged = 'epss_changed';
    case DescriptionUpdated = 'description_updated';
    case ReferencesUpdated = 'references_updated';
    case AliasesUpdated = 'aliases_updated';
    case MetadataUpdated = 'metadata_updated';

    public function impact(): ChangeImpact
    {
        return match ($this) {
            self::ScoreIncreased,
            self::ScoreDecreased,
            self::SeverityRaised,
            self::SeverityLowered,
            self::RangesChanged,
            self::FixAvailable,
            // Landing in CISA KEV, or EPSS crossing the 0.1 triage
            // threshold, changes what "this can wait" means.
            self::KnownExploited,
            self::ExploitationLikely => ChangeImpact::Major,
            default => ChangeImpact::Minor,
        };
    }
}
