<?php

declare(strict_types=1);

namespace Gumslone\Vulns\Console;

use Gumslone\Vulns\Contracts\Source;
use Gumslone\Vulns\VulnSearch;
use Illuminate\Console\Command;

/**
 * Interactive setup: publishes the config, walks through the optional
 * credentials (writing them to .env), optionally enables the built-in
 * search UI, and reports which sources will answer. `--check` runs a live
 * smoke query through every enabled source afterwards.
 */
class InstallCommand extends Command
{
    protected $signature = 'vulns:install {--check : Run a live smoke query through every enabled source}';

    protected $description = 'Publish the vulns config and interactively set up source credentials';

    /** Credential prompts: env key => [question, secret?] */
    private const CREDENTIALS = [
        'NVD_API_KEY' => ['NVD API key (free at nvd.nist.gov/developers — raises 5 req/30s to 50)', true],
        'GITHUB_TOKEN' => ['GitHub token (classic PAT, no scopes — unlocks the Advisory DB GraphQL feed)', true],
        'SNYK_API_TOKEN' => ['Snyk API token (commercial; leave empty to skip)', true],
        'SNYK_ORG_ID' => ['Snyk organisation id', false],
        'OSS_INDEX_USERNAME' => ['Sonatype OSS Index username (free account; required — anonymous access 401s)', false],
        'OSS_INDEX_API_TOKEN' => ['Sonatype OSS Index API token', true],
        'VULNCHECK_API_TOKEN' => ['VulnCheck Community token (free — "NVD++" by-id lookups)', true],
    ];

    public function handle(): int
    {
        $this->components->info('Setting up gumslone/laravel-vulns');

        $this->call('vendor:publish', ['--tag' => 'vulns-config']);

        $env = [];
        if ($this->confirm('Configure source credentials now?', true)) {
            foreach (self::CREDENTIALS as $key => [$question, $secret]) {
                // Skip follow-up fields when their primary was skipped.
                if ($key === 'SNYK_ORG_ID' && empty($env['SNYK_API_TOKEN'])) {
                    continue;
                }
                if ($key === 'OSS_INDEX_API_TOKEN' && empty($env['OSS_INDEX_USERNAME'])) {
                    continue;
                }

                $current = env($key);
                $prompt = $question.($current ? ' [configured — enter to keep]' : ' [enter to skip]');
                $value = $secret ? $this->secret($prompt) : $this->ask($prompt);
                if ($value !== null && trim((string) $value) !== '') {
                    $env[$key] = trim((string) $value);
                }
            }
        }

        if ($this->confirm('Enable the built-in search UI at /vulns? (enable only behind auth in production)', false)) {
            $env['VULNS_UI_ENABLED'] = 'true';
        }

        if ($env !== []) {
            $this->writeEnv($env);
            $this->components->info('Wrote '.count($env).' value(s) to .env');
        }

        $this->sourceSummary($env);

        if ($this->option('check')) {
            return $this->liveCheck();
        }

        $this->components->info('Done. Try: php artisan tinker → app(Gumslone\\Vulns\\VulnSearch::class)->searchAny("CVE-2021-44228")');

        return self::SUCCESS;
    }

    /**
     * Append or replace KEY=value pairs in the application .env — values are
     * quoted, existing keys are updated in place so re-running is idempotent.
     *
     * @param  array<string, string>  $env
     */
    private function writeEnv(array $env): void
    {
        $path = $this->laravel->environmentFilePath();
        $contents = is_file($path) ? (string) file_get_contents($path) : '';

        foreach ($env as $key => $value) {
            if (preg_match('/[\r\n]/', $value)) {
                $this->components->error("Skipping {$key}: value contains a line break.");

                continue;
            }
            // Escape \, " and $ — phpdotenv interpolates ${VAR} inside
            // double quotes, which would silently mutate a secret containing
            // it. The replacement goes through a callback so preg_replace
            // never interprets $0/$1 sequences inside the VALUE.
            $line = $key.'="'.addcslashes($value, '"\\$').'"';
            $contents = preg_match("/^{$key}=.*$/m", $contents)
                ? (string) preg_replace_callback("/^{$key}=.*$/m", fn () => $line, $contents)
                : rtrim($contents, "\n")."\n{$line}\n";
        }

        file_put_contents($path, $contents);
    }

    /** @param array<string, string> $env values just written (config isn't reloaded mid-process) */
    private function sourceSummary(array $env): void
    {
        $this->newLine();
        $this->components->twoColumnDetail('<fg=gray>Source</>', '<fg=gray>Status</>');

        foreach (app()->tagged('vulns.sources') as $source) {
            /** @var Source $source */
            $enabled = $source->isEnabled()
                || match ($source->name()) {
                    // Just-written credentials enable these on the NEXT boot.
                    'snyk' => isset($env['SNYK_API_TOKEN'], $env['SNYK_ORG_ID']),
                    'oss_index' => isset($env['OSS_INDEX_USERNAME'], $env['OSS_INDEX_API_TOKEN']),
                    'vulncheck' => isset($env['VULNCHECK_API_TOKEN']),
                    default => false,
                };

            $this->components->twoColumnDetail(
                $source->name(),
                $enabled ? '<fg=green>enabled</>' : '<fg=yellow>disabled</>',
            );
        }
    }

    private function liveCheck(): int
    {
        $this->newLine();
        $this->components->info('Live check — querying every enabled source for pkg:npm/lodash@4.17.20 …');

        $search = app(VulnSearch::class);
        $failed = false;

        foreach ($search->sources() as $source) {
            /** @var Source $source */
            try {
                $vulns = $search->only($source->name())->searchPurl('pkg:npm/lodash@4.17.20');
                $errors = $search->only($source->name())->errors();
                if ($errors !== []) {
                    $failed = true;
                    $this->components->twoColumnDetail($source->name(), '<fg=red>'.reset($errors).'</>');
                } else {
                    $this->components->twoColumnDetail($source->name(), '<fg=green>'.count($vulns).' advisories</>');
                }
            } catch (\Throwable $e) {
                $failed = true;
                $this->components->twoColumnDetail($source->name(), '<fg=red>'.$e->getMessage().'</>');
            }
        }

        return $failed ? self::FAILURE : self::SUCCESS;
    }
}
