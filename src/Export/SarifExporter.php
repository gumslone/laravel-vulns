<?php

declare(strict_types=1);

namespace Gumslone\Vulns\Export;

use Gumslone\Vulns\Data\PackageData;
use Gumslone\Vulns\Data\VulnerabilityData;
use Gumslone\Vulns\Support\VersionRange;

/**
 * Findings as a SARIF 2.1.0 log — what GitHub code scanning, GitLab and Azure
 * DevOps ingest. One rule per advisory, one result per (package, advisory).
 */
final class SarifExporter
{
    /**
     * @param  array<array-key, PackageData>  $packages
     * @param  array<array-key, VulnerabilityData[]>  $results  keyed like $packages
     * @param  array<array-key, string>  $locations  lockfile (repo-relative) each package came from, keyed like $packages
     * @return array<string, mixed>
     */
    public static function export(array $packages, array $results, array $locations = []): array
    {
        $rules = [];
        $sarifResults = [];

        foreach ($results as $key => $vulns) {
            $package = $packages[$key] ?? null;
            if ($package === null) {
                continue;
            }
            foreach ($vulns as $vuln) {
                $score = $vuln->effectiveCvssScore();
                $rules[$vuln->vulnId] ??= [
                    'id' => $vuln->vulnId,
                    'name' => $vuln->vulnId,
                    'shortDescription' => ['text' => $vuln->summary ?: $vuln->vulnId],
                    'fullDescription' => ['text' => $vuln->details ?: ($vuln->summary ?: $vuln->vulnId)],
                    'helpUri' => $vuln->sourceUrl,
                    'properties' => array_filter([
                        // GitHub reads security-severity (the CVSS score, as a string).
                        'security-severity' => $score === null ? null : number_format($score, 1),
                        'tags' => array_values(array_merge(['security', 'vulnerability'], $vuln->cwes)),
                    ], fn ($v) => $v !== null),
                ];

                $fix = VersionRange::recommendedFix($package->version, $vuln->fixedVersions);
                $sarifResults[] = [
                    'ruleId' => $vuln->vulnId,
                    'level' => match ($vuln->severity->value) {
                        'critical', 'high' => 'error',
                        'medium' => 'warning',
                        default => 'note',
                    },
                    'message' => ['text' => sprintf(
                        '%s %s is affected by %s (%s)%s.',
                        $package->name, $package->version ?? '', $vuln->vulnId, $vuln->severity->value,
                        $fix !== null ? " — upgrade to {$fix}" : '',
                    )],
                    'locations' => [['physicalLocation' => [
                        'artifactLocation' => ['uri' => $locations[$key] ?? 'composer.lock'],
                        'region' => ['startLine' => 1],
                    ]]],
                    'partialFingerprints' => ['packageAdvisory' => hash('sha256', ($package->toPurl() ?? $package->name).'|'.$vuln->vulnId)],
                ];
            }
        }

        return [
            '$schema' => 'https://json.schemastore.org/sarif-2.1.0.json',
            'version' => '2.1.0',
            'runs' => [[
                'tool' => ['driver' => [
                    'name' => 'laravel-vulns',
                    'informationUri' => 'https://github.com/gumslone/laravel-vulns',
                    'rules' => array_values($rules),
                ]],
                'results' => $sarifResults,
            ]],
        ];
    }
}
