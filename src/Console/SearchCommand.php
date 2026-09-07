<?php

declare(strict_types=1);

namespace Gumslone\Vulns\Console;

use Gumslone\Vulns\Data\VulnerabilityData;
use Gumslone\Vulns\VulnSearch;
use Illuminate\Console\Command;

/**
 * Look an identifier up from the terminal:
 *
 *   php artisan vulns:search CVE-2021-44228
 *   php artisan vulns:search pkg:npm/lodash@4.17.20 --source=osv --source=nvd
 *   php artisan vulns:search 'cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*' --json
 *
 * Exits non-zero when a source failed (results may be incomplete) or the
 * query is unrecognisable — never when advisories were simply found.
 */
class SearchCommand extends Command
{
    protected $signature = 'vulns:search
        {query : An advisory id (CVE/GHSA/EUVD), a purl, a CPE 2.3, a commit sha or a package URL}
        {--source=* : Query only these sources (osv, nvd, github, …)}
        {--latest : Let the most recently modified record win the merge}
        {--json : Print the full records as JSON}';

    protected $description = 'Search every enabled vulnerability source for an id, purl, CPE, commit or URL';

    public function handle(VulnSearch $search): int
    {
        try {
            if ($this->option('source') !== []) {
                $search = $search->only($this->option('source'));
            }
            if ($this->option('latest')) {
                $search = $search->preferLatest();
            }
            $results = $search->searchAny((string) $this->argument('query'));
        } catch (\InvalidArgumentException $e) {
            $this->components->error($e->getMessage());

            return self::INVALID;
        }

        // In JSON mode failures live in the document, so stdout stays
        // parseable when piped; the exit code flags them either way.
        if (! $this->option('json')) {
            foreach ($search->errors() as $source => $error) {
                $this->components->warn("{$source}: {$error}");
            }
        }

        if ($this->option('json')) {
            $this->line((string) json_encode([
                'results' => array_map(fn (VulnerabilityData $v) => $v->toArray(), $results),
                'errors' => (object) $search->errors(),
            ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
        } elseif ($results === []) {
            $this->components->info($search->errors() === []
                ? 'No advisories found.'
                : 'No advisories found — but a source failed, so this is inconclusive.');
        } else {
            $this->table(
                ['Id', 'Severity', 'Score', 'Vector', 'EPSS', 'Exploited', 'Fixed in', 'Link'],
                array_map(fn (VulnerabilityData $v) => [
                    $v->vulnId,
                    $v->severity->value,
                    $v->effectiveCvssScore() ?? '—',
                    $v->cvss()?->baseVector() ?? '—',
                    $v->epssScore === null ? '—' : number_format($v->epssScore, 3),
                    $v->isActivelyExploited() ? 'yes' : ($v->exploitMaturity()->value === 'none' ? 'no' : $v->exploitMaturity()->value),
                    implode(', ', array_slice($v->fixedVersions, 0, 3)) ?: '—',
                    $v->sourceUrl,
                ], $results),
            );
        }

        return $search->errors() === [] ? self::SUCCESS : self::FAILURE;
    }
}
