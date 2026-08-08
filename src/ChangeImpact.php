<?php

declare(strict_types=1);

namespace Gumslone\Vulns;

/**
 * How much a change to an advisory matters to a consumer. Major changes
 * (a rescore in either direction, a severity shift, new affected ranges, a
 * fix appearing) can flip triage decisions; minor ones (wording, references)
 * are informational.
 */
enum ChangeImpact: string
{
    case None = 'none';
    case Minor = 'minor';
    case Major = 'major';

    public function weight(): int
    {
        return match ($this) {
            self::None => 0,
            self::Minor => 1,
            self::Major => 2,
        };
    }
}
