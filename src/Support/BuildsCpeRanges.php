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
}
