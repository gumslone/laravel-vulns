<?php

declare(strict_types=1);

namespace Gumslone\Vulns;

use Gumslone\Vulns\Contracts\CpeLookup;
use Gumslone\Vulns\Contracts\Source;
use Gumslone\Vulns\Sources\CveSearchSource;
use Gumslone\Vulns\Sources\EuvdSource;
use Gumslone\Vulns\Sources\GitHubAdvisorySource;
use Gumslone\Vulns\Sources\NvdSource;
use Gumslone\Vulns\Sources\OsvSource;
use Gumslone\Vulns\Sources\SnykSource;
use Gumslone\Vulns\Support\CpeResolver;
use Gumslone\Vulns\Support\PurlBuilder;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\ServiceProvider;

/**
 * Wires the framework-free sources into a Laravel app: config from
 * `config/vulns.php`, PSR-3 logging through the app logger, PSR-16 caching
 * through the app cache. Every source is also tagged `vulns.sources` so an
 * app can inject the whole enabled set.
 */
class VulnsServiceProvider extends ServiceProvider
{
    /** Config key => source class. */
    private const SOURCES = [
        'osv' => OsvSource::class,
        'github' => GitHubAdvisorySource::class,
        'nvd' => NvdSource::class,
        'cve_search' => CveSearchSource::class,
        'euvd' => EuvdSource::class,
        'snyk' => SnykSource::class,
    ];

    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/vulns.php', 'vulns');

        $this->app->singleton(CpeResolver::class);
        $this->app->singleton(PurlBuilder::class);

        // Sources take an optional Guzzle client for tests; bind explicitly so
        // the container never auto-injects a BARE client (no base_uri, no
        // retry/timeout) into the nullable parameter and silently breaks them.
        foreach (self::SOURCES as $key => $class) {
            $this->app->bind($class, fn ($app) => match ($class) {
                NvdSource::class, CveSearchSource::class => new $class(
                    $app->make(CpeResolver::class),
                    $app->bound(CpeLookup::class) ? $app->make(CpeLookup::class) : null,
                    null,
                    $this->optionsFor($key),
                    ...$this->deps(),
                ),
                SnykSource::class => new $class(
                    $app->make(PurlBuilder::class),
                    null,
                    $this->optionsFor($key),
                    ...$this->deps(),
                ),
                default => new $class(null, $this->optionsFor($key), ...$this->deps()),
            });
        }

        $this->app->tag(array_values(self::SOURCES), 'vulns.sources');

        // The enabled subset, ready to iterate.
        $this->app->bind('vulns.enabled_sources', fn ($app) => collect($app->tagged('vulns.sources'))
            ->filter(fn (Source $source) => $source->isEnabled())
            ->values()
            ->all());

        $this->app->singleton(\Gumslone\Vulns\Enrichment\ThreatEnricher::class, fn () => new \Gumslone\Vulns\Enrichment\ThreatEnricher(
            null,
            ['epss' => (array) config('vulns.epss', []), 'kev' => (array) config('vulns.kev', [])],
            ...$this->deps(),
        ));

        // The "ask everything" entry point: app(VulnSearch::class).
        $this->app->singleton(VulnSearch::class, fn ($app) => new VulnSearch(
            $app->tagged('vulns.sources'),
            config('vulns.priority'),
            config('vulns.merge', 'priority') === 'latest',
            $app->make(\Gumslone\Vulns\Enrichment\ThreatEnricher::class),
        ));
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__.'/../config/vulns.php' => config_path('vulns.php'),
            ], 'vulns-config');
        }
    }

    /** @return array<string, mixed> */
    private function optionsFor(string $key): array
    {
        return (array) config("vulns.{$key}", []);
    }

    /** @return array{0: \Psr\Log\LoggerInterface, 1: \Psr\SimpleCache\CacheInterface} */
    private function deps(): array
    {
        return [Log::getLogger(), Cache::store()];
    }
}
