<?php

declare(strict_types=1);

namespace Gumslone\Vulns\Support;

/**
 * Builds and parses Package URLs (PURLs) per the PURL specification.
 * https://github.com/package-url/purl-spec
 */
class PurlBuilder
{
    /**
     * Build a PURL string.
     *
     * pkg:type/namespace/name@version
     * e.g. pkg:composer/symfony/console@7.1.0
     *      pkg:npm/%40babel/core@7.25.0
     *      pkg:pypi/requests@2.32.3
     */
    public function build(
        string $type,
        string $name,
        ?string $version = null,
        ?string $namespace = null,
        array $qualifiers = [],
        ?string $subpath = null,
    ): string {
        $type = strtolower($type);

        // Encode namespace and name per spec. A namespace can hold several
        // '/'-separated segments (e.g. the Go module path "github.com/x") — each
        // segment is encoded individually and the separators are preserved, so
        // the result is canonical (pkg:golang/github.com/x/y, not github.com%2Fx).
        $encodedNamespace = '';
        if ($namespace !== null && $namespace !== '') {
            $encodedNamespace = implode('/', array_map(
                fn (string $segment): string => $this->encodeSegment($segment),
                explode('/', $namespace),
            )).'/';
        }
        $encodedName = $this->encodeSegment($name);

        $purl = "pkg:{$type}/{$encodedNamespace}{$encodedName}";

        if ($version) {
            $purl .= '@'.$this->encodeSegment($version);
        }

        if ($qualifiers) {
            $qs = [];
            foreach ($qualifiers as $k => $v) {
                $qs[] = strtolower($k).'='.rawurlencode($v);
            }
            sort($qs);
            $purl .= '?'.implode('&', $qs);
        }

        if ($subpath) {
            $purl .= '#'.$subpath;
        }

        return $purl;
    }

    /**
     * Parse a PURL string into its components.
     *
     * @return array{type:string, namespace:?string, name:string, version:?string, qualifiers:array, subpath:?string}
     */
    public function parse(string $purl): array
    {
        // Remove "pkg:" prefix
        if (! str_starts_with($purl, 'pkg:')) {
            throw new \InvalidArgumentException("Invalid PURL: missing 'pkg:' scheme — $purl");
        }
        $remainder = substr($purl, 4);

        // Extract subpath
        $subpath = null;
        if (($hashPos = strpos($remainder, '#')) !== false) {
            $subpath = substr($remainder, $hashPos + 1);
            $remainder = substr($remainder, 0, $hashPos);
        }

        // Extract qualifiers
        $qualifiers = [];
        if (($qPos = strpos($remainder, '?')) !== false) {
            parse_str(substr($remainder, $qPos + 1), $qualifiers);
            $remainder = substr($remainder, 0, $qPos);
        }

        // Extract version. Only an '@' AFTER the last '/' separates a
        // version — an earlier '@' belongs to an unencoded npm scope
        // ('pkg:npm/@babel/core'), and splitting there would misread the
        // package name as a version.
        $version = null;
        $atPos = strrpos($remainder, '@');
        $slashPos = strrpos($remainder, '/');
        if ($atPos !== false && ($slashPos === false || $atPos > $slashPos)) {
            $version = rawurldecode(substr($remainder, $atPos + 1));
            $remainder = substr($remainder, 0, $atPos);
        }

        // type/namespace/name
        $parts = explode('/', $remainder, 3);
        $type = strtolower(array_shift($parts));
        $name = rawurldecode(array_pop($parts));
        $namespace = $parts ? rawurldecode(implode('/', $parts)) : null;

        return compact('type', 'namespace', 'name', 'version', 'qualifiers', 'subpath');
    }

    /**
     * Compute a stable SHA-256 checksum for a normalised PURL.
     * Used for deduplication and caching.
     */
    public function checksum(string $purl): string
    {
        return hash('sha256', strtolower($purl));
    }

    /**
     * Build PURL from a PackageData or OssPackage array.
     */
    public function fromPackageArray(array $pkg): string
    {
        $typeMap = [
            'composer' => 'composer',
            'npm' => 'npm',
            'pip' => 'pypi',
            'pypi' => 'pypi',
            'maven' => 'maven',
            'gradle' => 'maven',
            'nuget' => 'nuget',
            'go' => 'golang',
            'golang' => 'golang',
            'cargo' => 'cargo',
            'gem' => 'gem',
            'cocoapods' => 'cocoapods',
            'generic' => 'generic',
        ];

        $type = $typeMap[$pkg['ecosystem']] ?? $pkg['ecosystem'];
        $namespace = $pkg['namespace'] ?? null;
        $name = $pkg['name'];
        $version = $pkg['version'] ?? null;

        // For Maven the name is "groupId:artifactId" — split it into
        // namespace (groupId) + name (artifactId).
        if ($type === 'maven' && str_contains($name, ':')) {
            [$mavenGroup, $name] = explode(':', $name, 2);
            $namespace ??= $mavenGroup;
        }

        // Namespaced ecosystems store "vendor/name" as one string; without an
        // explicit namespace the whole thing would be percent-encoded into a
        // single segment (pkg:composer/vrana%2Fadminer) that matches nothing —
        // not the curated purl2cpe catalog, not any other tool's PURL.
        if (($namespace === null || $namespace === '')
            && str_contains($name, '/')
            && in_array($type, ['composer', 'npm', 'golang', 'github'], true)) {
            [$namespace, $name] = explode('/', $name, 2);
        }

        // Callers commonly store the name as "namespace/name" (composer,
        // npm, golang).
        // When the namespace is also supplied on its own, strip the duplicated
        // prefix so the PURL is canonical — pkg:npm/%40babel/core, not the
        // doubled-up pkg:npm/%40babel/%40babel%2Fcore that never matches the
        // curated purl2cpe catalog (nor any other tool's canonical PURL).
        if ($namespace !== null && $namespace !== '' && str_starts_with($name, $namespace.'/')) {
            $name = substr($name, strlen($namespace) + 1);
        }

        return $this->build($type, $name, $version, $namespace);
    }

    private function encodeSegment(string $segment): string
    {
        // percent-encode everything except unreserved chars and @ : /
        return rawurlencode($segment);
    }
}
