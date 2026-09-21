<?php

declare(strict_types=1);

namespace Gumslone\Vulns\Events;

use Gumslone\Vulns\SearchReport;

/** A batch search finished: results, failures and coverage in one report. */
final class SearchCompleted
{
    public function __construct(public readonly SearchReport $report) {}
}
