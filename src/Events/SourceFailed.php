<?php

declare(strict_types=1);

namespace Gumslone\Vulns\Events;

/**
 * A source threw, or answered only partially (rate-limited package, page cap,
 * advisory details unavailable). Results from that source are missing or
 * incomplete — worth a metric or an alert when it keeps happening.
 */
final class SourceFailed
{
    public function __construct(
        public readonly string $source,
        public readonly string $message,
        /** true = the source still delivered results; false = it delivered nothing */
        public readonly bool $partial = false,
    ) {}
}
