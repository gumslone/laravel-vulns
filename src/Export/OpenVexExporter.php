<?php

declare(strict_types=1);

namespace Gumslone\Vulns\Export;

use Gumslone\Vulns\Data\VulnerabilityData;

/**
 * OpenVEX 0.2.0 documents: your verdict ("not_affected", "fixed", …) on an
 * advisory for a product, in the format scanners use to suppress findings.
 */
final class OpenVexExporter
{
    public const STATUSES = ['not_affected', 'affected', 'fixed', 'under_investigation'];

    public const JUSTIFICATIONS = [
        'component_not_present', 'vulnerable_code_not_present', 'vulnerable_code_not_in_execute_path',
        'vulnerable_code_cannot_be_controlled_by_adversary', 'inline_mitigations_already_exist',
    ];

    /**
     * @param  string[]  $products  purls the verdict applies to
     * @return array<string, mixed>
     */
    public static function statement(
        VulnerabilityData $vuln,
        array $products,
        string $status,
        ?string $justification = null,
        ?string $impactStatement = null,
        ?string $actionStatement = null,
    ): array {
        if (! in_array($status, self::STATUSES, true)) {
            throw new \InvalidArgumentException("Unknown VEX status '{$status}'. Use one of: ".implode(', ', self::STATUSES).'.');
        }
        if ($justification !== null && ! in_array($justification, self::JUSTIFICATIONS, true)) {
            throw new \InvalidArgumentException("Unknown VEX justification '{$justification}'.");
        }
        // The specification's own rules — a verdict must carry its reason.
        if ($status === 'not_affected' && $justification === null && ($impactStatement === null || trim($impactStatement) === '')) {
            throw new \InvalidArgumentException('A not_affected statement needs a justification or an impact statement.');
        }
        if ($status === 'affected' && ($actionStatement === null || trim($actionStatement) === '')) {
            throw new \InvalidArgumentException('An affected statement needs an action statement.');
        }

        return array_filter([
            'vulnerability' => array_filter(['name' => $vuln->vulnId, 'aliases' => $vuln->aliases, '@id' => $vuln->sourceUrl]),
            'products' => array_map(fn (string $purl) => ['@id' => $purl], array_values($products)),
            'status' => $status,
            'justification' => $status === 'not_affected' ? $justification : null,
            'impact_statement' => $impactStatement,
            'action_statement' => $actionStatement,
        ], fn ($v) => $v !== null && $v !== []);
    }

    /**
     * @param  array<int, array<string, mixed>>  $statements  from statement()
     * @return array<string, mixed>
     */
    public static function document(array $statements, string $author, ?string $id = null, int $version = 1): array
    {
        return [
            '@context' => 'https://openvex.dev/ns/v0.2.0',
            '@id' => $id ?? 'https://openvex.dev/docs/public/vex-'.hash('sha256', (string) json_encode($statements)),
            'author' => $author,
            'timestamp' => gmdate('Y-m-d\TH:i:s\Z'),
            'version' => $version,
            'statements' => array_values($statements),
        ];
    }
}
