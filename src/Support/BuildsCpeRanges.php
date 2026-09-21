<?php

declare(strict_types=1);

namespace Gumslone\Vulns\Support;

/**
 * NVD-shaped `configurations` → constraint strings VersionRange can parse,
 * shared by the sources that serve that shape (NVD, VulnCheck) so range
 * evidence merges identically whichever delivered the record.
 */
trait BuildsCpeRanges
{
    /**
     * One entry per vulnerable cpeMatch: bounds become ">= 1.0, < 2.4.7", a
     * version pinned in the CPE becomes "= x", and an UNBOUNDED match
     * (version `*` or `-`, no bounds) becomes "*" — every version. Dropping
     * that one would leave only the pins, and "5.0.0 matches none of them"
     * would then read as provably unaffected.
     *
     * `product` ("vendor:product") lets a consumer judge only the ranges of
     * the product it asked about.
     *
     * @return array<int, array{range: string, product: string, source: string}>
     */
    protected function configurationRanges(array $configurations): array
    {
        $ranges = [];
        foreach ($configurations as $config) {
            foreach ($config['nodes'] ?? [] as $node) {
                foreach ($node['cpeMatch'] ?? [] as $match) {
                    if (($match['vulnerable'] ?? true) === false) {
                        continue;
                    }

                    $clauses = [];
                    foreach ([
                        'versionStartIncluding' => '>=', 'versionStartExcluding' => '>',
                        'versionEndIncluding' => '<=', 'versionEndExcluding' => '<',
                    ] as $key => $op) {
                        if (isset($match[$key]) && $match[$key] !== '') {
                            $clauses[] = "{$op} {$match[$key]}";
                        }
                    }

                    // cpe:2.3:part:vendor:product:version:update:…
                    $cpe = explode(':', (string) ($match['criteria'] ?? ''));
                    if ($clauses === []) {
                        $version = $cpe[5] ?? '*';
                        if ($version === '*' || $version === '-' || $version === '') {
                            $clauses[] = '*';
                        } else {
                            // The update component carries letter/patch
                            // releases ("1.1.1" + "k"); "*"/"-" mean none.
                            $update = $cpe[6] ?? '*';
                            $clauses[] = '= '.$version.(in_array($update, ['*', '-', ''], true) ? '' : $update);
                        }
                    }

                    $ranges[] = [
                        'range' => implode(', ', $clauses),
                        'product' => strtolower(($cpe[3] ?? '').':'.($cpe[4] ?? '')),
                        'source' => $this->name(),
                    ];
                }
            }
        }

        return $ranges;
    }

    /**
     * [score, vector] from NVD-shaped `metrics`. A CVE can carry several
     * assessments per standard — NVD's own ("Primary") and a CNA's
     * ("Secondary"), in no guaranteed order — so the Primary one is
     * preferred and the first listed is only the fallback.
     *
     * @param  string[]  $keys  metric lists to try in order, e.g. ['cvssMetricV31', 'cvssMetricV30']
     * @return array{0: float|null, 1: string|null}
     */
    protected function cvssMetric(array $metrics, array $keys): array
    {
        foreach ($keys as $key) {
            $entries = array_values(array_filter((array) ($metrics[$key] ?? []), fn ($m) => is_array($m) && isset($m['cvssData']['baseScore'])));
            if ($entries === []) {
                continue;
            }
            $primary = array_values(array_filter($entries, fn (array $m) => strcasecmp((string) ($m['type'] ?? ''), 'Primary') === 0));
            $data = ($primary[0] ?? $entries[0])['cvssData'];

            return [(float) $data['baseScore'], $data['vectorString'] ?? null];
        }

        return [null, null];
    }
}
