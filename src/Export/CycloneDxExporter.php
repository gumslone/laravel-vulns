<?php

declare(strict_types=1);

namespace Gumslone\Vulns\Export;

use Gumslone\Vulns\Data\VulnerabilityData;
use Gumslone\Vulns\Severity;

/** A record as a CycloneDX 1.6 `vulnerabilities[]` entry (SBOM / VDR / VEX documents). */
final class CycloneDxExporter
{
    /**
     * @param  string[]  $bomRefs  bom-refs (usually purls) of the components it affects
     * @param  array{state?: string, justification?: string, detail?: string}  $analysis  optional VEX analysis
     * @return array<string, mixed>
     */
    public static function export(VulnerabilityData $vuln, array $bomRefs = [], array $analysis = []): array
    {
        $ratings = [];
        foreach ([4 => 'CVSSv4', 3 => null, 2 => 'CVSSv2'] as $version => $method) {
            $score = $vuln->{"cvssV{$version}Score"};
            if ($score === null) {
                continue;
            }
            $vector = $vuln->{"cvssV{$version}Vector"};
            $ratings[] = array_filter([
                'source' => ['name' => $vuln->source],
                'score' => $score,
                'severity' => Severity::fromCvssScore($score)->value,
                'method' => $method ?? (str_starts_with((string) $vector, 'CVSS:3.0') ? 'CVSSv3' : 'CVSSv31'),
                'vector' => $vuln->isInferred("cvss_v{$version}_vector") ? null : $vector,
            ], fn ($v) => $v !== null);
        }
        if ($ratings === [] && $vuln->severity->value !== 'unknown') {
            $ratings[] = ['source' => ['name' => $vuln->source], 'severity' => $vuln->severity->value, 'method' => 'other'];
        }

        return array_filter([
            'bom-ref' => 'vuln-'.$vuln->vulnId,
            'id' => $vuln->vulnId,
            'source' => ['name' => $vuln->source, 'url' => $vuln->sourceUrl],
            'references' => array_map(fn (string $id) => ['id' => $id, 'source' => ['name' => explode('-', $id)[0]]], $vuln->aliases),
            'ratings' => $ratings,
            'cwes' => array_values(array_filter(array_map(
                fn ($cwe) => preg_match('/(\d+)/', (string) $cwe, $m) ? (int) $m[1] : null,
                $vuln->cwes,
            ))),
            'description' => $vuln->summary,
            'detail' => $vuln->details,
            'recommendation' => $vuln->remediationAdvice ?? ($vuln->fixedVersions !== [] ? 'Upgrade to '.implode(' or ', array_slice($vuln->fixedVersions, 0, 3)).'.' : null),
            'advisories' => array_values(array_filter(array_map(
                fn ($ref) => ($url = is_array($ref) ? ($ref['url'] ?? '') : (string) $ref) !== '' ? ['url' => $url] : null,
                $vuln->references,
            ))),
            'published' => $vuln->sourcePublishedAt?->format(DATE_ATOM),
            'updated' => $vuln->sourceModifiedAt?->format(DATE_ATOM),
            'rejected' => $vuln->isWithdrawn ? $vuln->sourceModifiedAt?->format(DATE_ATOM) : null,
            'analysis' => array_filter($analysis),
            'affects' => array_map(fn (string $ref) => ['ref' => $ref], array_values($bomRefs)),
        ], fn ($v) => $v !== null && $v !== []);
    }
}
