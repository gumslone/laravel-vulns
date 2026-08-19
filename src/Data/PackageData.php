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
        /** Explicit CPE 2.3 for CPE-driven sources (NVD, CVE-Search); when
         *  absent they derive one from the purl/name via CpeResolver. */
        public readonly ?string $cpe23 = null,
    ) {}

    /**
     * Build a query target from a Package URL:
     * `pkg:composer/vrana/adminer@5.5.1`. The purl's type becomes the
     * ecosystem, and namespaced types keep the "namespace/name" convention
     * ecosystem sources expect.
     */
    public static function fromPurl(string $purl): self
    {
        $parts = (new \Gumslone\Vulns\Support\PurlBuilder)->parse($purl);
        $namespace = $parts['namespace'] ?? null;
        $name = $parts['name'];

        $version = $parts['version'] ?? null;
        $type = $parts['type'];

        // A forge purl whose version is a hex sha is a commit pin (built from
        // a commit page or a commit archive URL) — carry the commit so OSV
        // can match it against advisory git ranges.
        $commit = in_array($type, ['github', 'gitlab', 'bitbucket'], true)
            && $version !== null && preg_match('/^[0-9a-f]{7,64}$/i', $version)
            ? strtolower($version)
            : null;

        return new self(
            name: $namespace !== null && $namespace !== '' ? "{$namespace}/{$name}" : $name,
            version: $version,
            ecosystem: self::ecosystemForPurlType($type),
            namespace: $namespace,
            purl: $purl,
            gitCommitHash: $commit,
        );
    }

    /**
     * A queryable package from any package-ish URL — a forge commit page, or
     * (with gumslone/laravel-package-url installed) a download / release /
     * archive / registry URL: GitHub release and zip links, GitLab
     * /-/archive/, codeload, npm tarballs, PyPI wheels, ….
     */
    public static function fromUrl(string $url): self
    {
        $url = trim($url);

        // The purl package speaks every registry/forge URL dialect — use it
        // when the host app has it installed (a `suggest`, not a hard
        // dependency, to keep this core light).
        if (class_exists(\Gumslone\PackageUrl\Purl::class)) {
            $purl = (new \Gumslone\PackageUrl\Purl)->fromUrl($url);
            if ($purl !== null) {
                return self::fromPurl((string) $purl);
            }
        }

        // Native fallback: forge commit pages and bare shas. A commit URL on
        // an unknown (self-hosted) forge still yields the bare-commit query
        // OSV can answer.
        if (($sha = self::commitFromUrl($url)) !== null) {
            try {
                return self::fromCommit($url);
            } catch (\InvalidArgumentException) {
                return self::fromCommit($sha);
            }
        }

        throw new \InvalidArgumentException(
            "Could not derive package coordinates from '{$url}'."
            .(class_exists(\Gumslone\PackageUrl\Purl::class)
                ? ''
                : ' Install gumslone/laravel-package-url to convert download/release/registry URLs.'),
        );
    }

    /**
     * Build a query target from a CPE 2.3 string:
     * `cpe:2.3:a:prasathmani:tiny_file_manager:2.6:*:*:*:*:*:*:*`. Only the
     * CPE-driven sources (NVD, CVE-Search) can answer these.
     */
    /**
     * A queryable package from a git commit — a bare sha, or a
     * GitHub/GitLab/Bitbucket commit URL. OSV resolves commits directly
     * against advisory git ranges, so even a repo-less bare sha is a valid
     * query; a URL additionally yields forge coordinates the other sources
     * can use.
     */
    /**
     * The bare commit sha out of a forge commit link (GitHub, GitLab incl.
     * /-/commit/, Bitbucket), or the input itself when it already is a sha.
     * Null when the string carries no commit id.
     */
    public static function commitFromUrl(string $commitOrUrl): ?string
    {
        $commitOrUrl = trim($commitOrUrl);
        if (preg_match('/^[0-9a-f]{7,64}$/i', $commitOrUrl)) {
            return strtolower($commitOrUrl);
        }
        if (preg_match('#/(?:-/)?commits?/([0-9a-f]{7,64})#i', $commitOrUrl)) {
            return strtolower(preg_replace('#.*/(?:-/)?commits?/([0-9a-f]{7,64}).*#i', '$1', $commitOrUrl));
        }

        return null;
    }

    /**
     * The forge web page for this package's pinned commit — the inverse of
     * fromCommit(). Null without a commit or forge coordinates. GitLab's
     * route lives behind its /-/ separator.
     */
    public function toCommitUrl(): ?string
    {
        if ($this->gitCommitHash === null || $this->repositoryUrl === null) {
            return null;
        }

        $repo = rtrim($this->repositoryUrl, '/');
        $route = str_contains($repo, 'gitlab') ? '/-/commit/' : '/commit/';

        return $repo.$route.$this->gitCommitHash;
    }

    public static function fromCommit(string $commitOrUrl): self
    {
        $commitOrUrl = trim($commitOrUrl);

        // Forge commit URL: …/<owner>/<repo>/(-/)?commit(s)?/<sha>
        if (preg_match(
            '#^https?://(?:www\.)?(github\.com|gitlab\.com|bitbucket\.org)/([^/]+)/([^/]+?)(?:/-)?/commits?/([0-9a-f]{7,64})#i',
            $commitOrUrl,
            $m,
        )) {
            $type = match (strtolower($m[1])) {
                'github.com' => 'github',
                'gitlab.com' => 'gitlab',
                default => 'bitbucket',
            };
            $owner = strtolower($m[2]);
            $repo = strtolower($m[3]);
            $sha = strtolower($m[4]);

            return new self(
                name: $repo,
                version: $sha,
                ecosystem: $type,
                namespace: $owner,
                purl: "pkg:{$type}/{$owner}/{$repo}@{$sha}",
                repositoryUrl: "https://{$m[1]}/{$owner}/{$repo}",
                gitCommitHash: $sha,
            );
        }

        if (preg_match('/^[0-9a-f]{7,64}$/i', $commitOrUrl)) {
            $sha = strtolower($commitOrUrl);

            return new self(
                name: $sha,
                version: null,
                ecosystem: 'git',
                gitCommitHash: $sha,
            );
        }

        throw new \InvalidArgumentException(
            "Not a git commit: '{$commitOrUrl}'. Pass a 7-64 char hex sha or a forge commit URL.",
        );
    }

    /**
     * The package's purl — the explicit one when set, else built from its
     * coordinates. Null when there aren't enough coordinates to build one.
     */
    public function toPurl(): ?string
    {
        if ($this->purl !== null) {
            return $this->purl;
        }

        try {
            return (new \Gumslone\Vulns\Support\PurlBuilder)->fromPackageArray($this->toArray()) ?: null;
        } catch (\Throwable) {
            return null;
        }
    }

    /**
     * The package's CPE 2.3 — the explicit one when set, else derived from
     * the purl / coordinates (heuristic vendor inference; bind a
     * Contracts\CpeLookup for curated mappings via the sources instead).
     *
     * A commit-URL package converts (owner → vendor, repo → product,
     * sha → version); a BARE commit sha has no vendor/product identity, so
     * it returns null rather than a hash-as-vendor CPE that matches nothing.
     */
    public function toCpe23(): ?string
    {
        if ($this->cpe23 !== null) {
            return $this->cpe23;
        }

        if ($this->ecosystem === 'git' && preg_match('/^[0-9a-f]{7,64}$/', $this->name)) {
            return null;
        }

        return (new \Gumslone\Vulns\Support\CpeResolver)->resolveCpe23($this);
    }

    public static function fromCpe(string $cpe23): self
    {
        $f = explode(':', $cpe23);
        $product = $f[4] ?? '';
        $version = ($f[5] ?? '*');

        return new self(
            name: $product !== '' ? $product : $cpe23,
            version: in_array($version, ['*', '-', ''], true) ? null : $version,
            ecosystem: 'generic',
            cpe23: $cpe23,
        );
    }

    /** PURL types whose name OSSaur-style ecosystems spell differently. */
    private static function ecosystemForPurlType(string $type): string
    {
        return match ($type) {
            'pypi' => 'pip',
            'maven' => 'maven',
            'golang' => 'go',
            'cargo' => 'cargo',
            'gem' => 'gem',
            default => $type,
        };
    }

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
            cpe23: $data['cpe23'] ?? null,
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
            'cpe23' => $this->cpe23,
        ];
    }
}
