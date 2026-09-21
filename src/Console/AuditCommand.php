<?php

declare(strict_types=1);

namespace Gumslone\Vulns\Console;

use Gumslone\Vulns\Data\PackageData;
use Gumslone\Vulns\Data\VulnerabilityData;
use Gumslone\Vulns\Export\SarifExporter;
use Gumslone\Vulns\Severity;
use Gumslone\Vulns\Support\LockfileReader;
use Gumslone\Vulns\Support\VersionRange;
use Gumslone\Vulns\VulnSearch;
use Illuminate\Console\Command;

/**
 * Audit THIS application's dependencies against every enabled source:
 *
 *   php artisan vulns:audit                          # composer.lock + package-lock.json
 *   php artisan vulns:audit --no-dev --min-severity=high
 *   php artisan vulns:audit --format=sarif > vulns.sarif
 *   php artisan vulns:audit --lock=frontend/package-lock.json
 *
 * Exit codes — made for CI: 0 nothing at or above the threshold, 1 findings,
 * 2 bad input, 3 nothing found BUT a source failed (inconclusive — never a
 * green build on an outage; pass --ignore-errors to accept it).
 */
class AuditCommand extends Command
{
    public const INCONCLUSIVE = 3;

    protected $signature = 'vulns:audit
        {--lock=* : Lockfile(s) to audit (default: composer.lock and package-lock.json in the project root)}
        {--no-dev : Skip development dependencies}
        {--min-severity=low : Report (and fail on) advisories at or above: low, medium, high, critical}
        {--source=* : Query only these sources (osv, github, nvd, …)}
        {--format=table : table, json or sarif}
        {--include-withdrawn : Include withdrawn / rejected advisories}
        {--ignore-errors : Exit 0 when nothing was found even though a source failed}';

    protected $description = 'Audit the application\'s composer.lock / package-lock.json for known vulnerabilities';

    public function handle(VulnSearch $search): int
    {
        $threshold = Severity::tryFrom(strtolower((string) $this->option('min-severity')));
        $format = strtolower((string) $this->option('format'));
        if ($threshold === null || $threshold === Severity::Unknown || ! in_array($format, ['table', 'json', 'sarif'], true)) {
            $this->components->error('Use --min-severity=low|medium|high|critical and --format=table|json|sarif.');

            return self::INVALID;
        }

        try {
            if ($this->option('source') !== []) {
                $search = $search->only($this->option('source'));
            }
            [$packages, $locations] = $this->packages();
        } catch (\InvalidArgumentException $e) {
            $this->components->error($e->getMessage());

            return self::INVALID;
        }

        $report = $search->report($packages);

        // Unscored advisories are kept: "unknown" is not "harmless".
        $findings = [];
        foreach ($report->results as $key => $vulns) {
            $kept = array_values(array_filter($vulns, fn (VulnerabilityData $v) => ($this->option('include-withdrawn') || ! $v->isWithdrawn)
                && ($v->severity === Severity::Unknown || $v->severity->weight() >= $threshold->weight())));
            if ($kept !== []) {
                $findings[$key] = $kept;
            }
        }

        match ($format) {
            'json' => $this->line((string) json_encode([
                'packages' => count($packages),
                'findings' => array_map(fn (array $vulns, $key) => [
                    'package' => $packages[$key]->name, 'version' => $packages[$key]->version, 'ecosystem' => $packages[$key]->ecosystem,
                    'dev' => $packages[$key]->isDevDependency, 'lockfile' => $locations[$key],
                    'advisories' => array_map(fn (VulnerabilityData $v) => $v->toArray(), $vulns),
                ], $findings, array_keys($findings)),
                'errors' => (object) $report->errors,
                'inconclusive' => array_map(fn ($key) => $packages[$key]->name, $report->inconclusiveKeys()),
            ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)),
            'sarif' => $this->line((string) json_encode(SarifExporter::export($packages, $findings, $locations), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)),
            default => $this->renderTable($packages, $findings, $report->errors),
        };

        if ($findings !== []) {
            return self::FAILURE;
        }

        return $report->isComplete() || $this->option('ignore-errors') ? self::SUCCESS : self::INCONCLUSIVE;
    }

    /** @return array{0: array<string, PackageData>, 1: array<string, string>} [packages, lockfile per package key] */
    private function packages(): array
    {
        $locks = $this->option('lock');
        if ($locks === []) {
            $locks = array_values(array_filter(
                [base_path('composer.lock'), base_path('package-lock.json')],
                'is_file',
            ));
            if ($locks === []) {
                throw new \InvalidArgumentException('No composer.lock or package-lock.json in '.base_path().' — pass --lock=path.');
            }
        }

        $packages = [];
        $locations = [];
        foreach ($locks as $lock) {
            $path = is_file($lock) ? $lock : base_path($lock);
            foreach (LockfileReader::read($path, ! $this->option('no-dev')) as $key => $package) {
                $packages[$key] = $package;
                $locations[$key] = ltrim(str_replace(base_path(), '', (string) realpath($path)), '/\\') ?: basename($path);
            }
        }

        return [$packages, $locations];
    }

    /**
     * @param  array<string, PackageData>  $packages
     * @param  array<string, VulnerabilityData[]>  $findings
     * @param  array<string, string>  $errors
     */
    private function renderTable(array $packages, array $findings, array $errors): void
    {
        foreach ($errors as $source => $error) {
            $this->components->warn("{$source}: {$error}");
        }

        if ($findings === []) {
            $this->components->info(sprintf(
                $errors === [] ? 'No known vulnerabilities in %d packages.' : 'Nothing found in %d packages — but a source failed, so this is inconclusive.',
                count($packages),
            ));

            return;
        }

        $rows = [];
        foreach ($findings as $key => $vulns) {
            foreach ($vulns as $v) {
                $rows[] = [
                    $packages[$key]->name.($packages[$key]->isDevDependency ? ' (dev)' : ''),
                    $packages[$key]->version,
                    $v->vulnId,
                    $v->severity->value,
                    $v->effectiveCvssScore() ?? '—',
                    $v->isActivelyExploited() ? 'yes' : 'no',
                    VersionRange::recommendedFix($packages[$key]->version, $v->fixedVersions) ?? '—',
                    $v->sourceUrl,
                ];
            }
        }
        usort($rows, fn (array $a, array $b) => [is_float($b[4]) ? $b[4] : -1.0, $a[0]] <=> [is_float($a[4]) ? $a[4] : -1.0, $b[0]]);

        $this->table(['Package', 'Version', 'Advisory', 'Severity', 'Score', 'Exploited', 'Upgrade to', 'Link'], $rows);
        $this->components->error(sprintf(
            '%d advisor%s affecting %d of %d packages.',
            count($rows), count($rows) === 1 ? 'y' : 'ies', count($findings), count($packages),
        ));
    }
}
