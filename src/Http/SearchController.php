<?php

declare(strict_types=1);

namespace Gumslone\Vulns\Http;

use Gumslone\Vulns\VulnSearch;
use Illuminate\Http\Request;

/**
 * The built-in single-page search UI: paste anything searchAny() accepts —
 * a CVE/GHSA/EUVD id, purl, CPE 2.3, commit sha, or package URL — and see
 * the merged, enriched results plus which sources failed. Opt-in via
 * config('vulns.ui.enabled'); put auth middleware in front for production
 * (config('vulns.ui.middleware')).
 */
class SearchController
{
    public function __invoke(Request $request, VulnSearch $search)
    {
        $query = trim((string) $request->query('q', ''));
        $results = [];
        $errors = [];
        $failure = null;
        $elapsed = null;

        if ($query !== '') {
            $start = microtime(true);
            try {
                $results = $search->searchAny($query);
                $errors = $search->errors();
            } catch (\InvalidArgumentException $e) {
                $failure = $e->getMessage();
            } catch (\Throwable $e) {
                $failure = 'Search failed: '.$e->getMessage();
            }
            $elapsed = round((microtime(true) - $start) * 1000);
        }

        return view('vulns::search', [
            'query' => $query,
            'results' => $results,
            'sourceErrors' => $errors,
            'failure' => $failure,
            'elapsedMs' => $elapsed,
            'sources' => array_map(
                fn ($s) => $s->name(),
                $search->sources(),
            ),
        ]);
    }
}
