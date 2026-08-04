<?php

declare(strict_types=1);

namespace Gumslone\Vulns\Data;

/**
 * Lightweight DTO representing a package discovered during manifest parsing.
 * This is the intermediate form before the record is persisted as OssPackage.
 */
final class PackageData
{
    public function __construct(
        public readonly string $name,
        public readonly ?string $version,
        public readonly string $ecosystem,
        public readonly ?string $namespace = null,
        public readonly ?string $purl = null,
        public readonly bool $isDirect = true,
        public readonly bool $isDevDependency = false,
        public readonly ?string $scope = null,
        public readonly ?string $versionConstraint = null,
        public readonly ?string $downloadUrl = null,
        public readonly ?string $homepageUrl = null,
        public readonly ?string $repositoryUrl = null,
        public readonly ?string $declaredLicense = null,
        public readonly ?string $gitCommitHash = null,
        public readonly ?string $manifestFile = null,
        public readonly ?string $manifestChecksum = null,
        public readonly array $extra = [],
        /** @var string[] Names of packages this one requires (per its lockfile entry). */
        public readonly array $dependsOn = [],
    ) {}

    public static function fromArray(array $data): self
    {
        return new self(
            name: $data['name'],
            version: $data['version'] ?? null,
            ecosystem: $data['ecosystem'],
            namespace: $data['namespace'] ?? null,
            purl: $data['purl'] ?? null,
            isDirect: $data['is_direct'] ?? true,
            isDevDependency: $data['is_dev_dependency'] ?? false,
            scope: $data['scope'] ?? null,
            versionConstraint: $data['version_constraint'] ?? null,
            downloadUrl: $data['download_url'] ?? null,
            homepageUrl: $data['homepage_url'] ?? null,
            repositoryUrl: $data['repository_url'] ?? null,
            declaredLicense: $data['declared_license'] ?? null,
            gitCommitHash: $data['git_commit_hash'] ?? null,
            manifestFile: $data['manifest_file'] ?? null,
            manifestChecksum: $data['manifest_checksum'] ?? null,
            extra: $data['extra'] ?? [],
            dependsOn: $data['depends_on'] ?? [],
        );
    }

    public function toArray(): array
    {
        return [
            'name' => $this->name,
            'version' => $this->version,
            'ecosystem' => $this->ecosystem,
            'namespace' => $this->namespace,
            'purl' => $this->purl,
            'is_direct' => $this->isDirect,
            'is_dev_dependency' => $this->isDevDependency,
            'scope' => $this->scope,
            'version_constraint' => $this->versionConstraint,
            'download_url' => $this->downloadUrl,
            'homepage_url' => $this->homepageUrl,
            'repository_url' => $this->repositoryUrl,
            'declared_license' => $this->declaredLicense,
            'git_commit_hash' => $this->gitCommitHash,
            'manifest_file' => $this->manifestFile,
            'manifest_checksum' => $this->manifestChecksum,
            'extra' => $this->extra,
            'depends_on' => $this->dependsOn,
        ];
    }
}
