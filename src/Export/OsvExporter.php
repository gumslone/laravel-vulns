<?php

declare(strict_types=1);

namespace Gumslone\Vulns\Export;

use Gumslone\Vulns\Data\VulnerabilityData;

/**
 * A record as an OSV-schema document (https://ossf.github.io/osv-schema/) —
 * the interchange format osv-scanner, deps.dev and most SCA tools read.
 */
final class OsvExporter
{
    /** @return array<string, mixed> */
    public static function export(VulnerabilityData $vuln): array
    {
        $severity = [];
        foreach ([4 => 'CVSS_V4', 3 => 'CVSS_V3', 2 => 'CVSS_V2'] as $version => $type) {
            // OSV's severity score IS the vector; a representative one inferred
            // for a bare score is not the source's statement and stays out.
            $vector = $vuln->reported("cvss_v{$version}_vector");
            if (is_string($vector) && $vector !== '') {
                $severity[] = ['type' => $type, 'score' => $vector];
            }
        }

        // Only OSV-shaped ranges ({type, events}) survive as-is; constraint
        // strings have no lossless OSV form and travel in database_specific.
        $ranges = array_values(array_filter($vuln->affectedRanges, fn ($r) => is_array($r) && isset($r['type'], $r['events'])));
        $constraints = array_values(array_filter(array_map(
            fn ($r) => is_array($r) ? ($r['range'] ?? null) : (is_string($r) ? $r : null),
            $vuln->affectedRanges,
        )));

        return array_filter([
            'schema_version' => '1.6.0',
            'id' => $vuln->vulnId,
            'aliases' => $vuln->aliases,
            'modified' => ($vuln->sourceModifiedAt ?? $vuln->sourcePublishedAt)?->format('Y-m-d\TH:i:s\Z') ?? gmdate('Y-m-d\TH:i:s\Z'),
            'published' => $vuln->sourcePublishedAt?->format('Y-m-d\TH:i:s\Z'),
            'withdrawn' => $vuln->isWithdrawn ? ($vuln->sourceModifiedAt?->format('Y-m-d\TH:i:s\Z') ?? gmdate('Y-m-d\TH:i:s\Z')) : null,
            'summary' => $vuln->summary,
            'details' => $vuln->details,
            'severity' => $severity,
            'affected' => $ranges === [] ? [] : [['ranges' => array_map(
                fn (array $r) => array_diff_key($r, ['product' => true, 'source' => true]),
                $ranges,
            )]],
            'references' => array_values(array_filter(array_map(function ($ref) {
                $url = is_array($ref) ? ($ref['url'] ?? '') : (string) $ref;
                $type = strtoupper((string) (is_array($ref) ? ($ref['type'] ?? '') : ''));

                return $url === '' ? null : [
                    'type' => in_array($type, ['ADVISORY', 'ARTICLE', 'DETECTION', 'DISCUSSION', 'REPORT', 'FIX', 'INTRODUCED', 'PACKAGE', 'EVIDENCE', 'WEB'], true) ? $type : 'WEB',
                    'url' => $url,
                ];
            }, $vuln->references))),
            'database_specific' => array_filter([
                'source' => $vuln->source,
                'severity' => $vuln->severity->value,
                'cwe_ids' => $vuln->cwes,
                'fixed_versions' => $vuln->fixedVersions,
                'version_constraints' => $constraints,
                'epss' => $vuln->epssScore,
                'known_exploited' => $vuln->isKnownExploited ?: null,
            ], fn ($v) => $v !== null && $v !== []),
        ], fn ($v) => $v !== null && $v !== []);
    }
}
