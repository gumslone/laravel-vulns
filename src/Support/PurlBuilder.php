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
        $type = strtolower(trim($type));
        if (! preg_match('/^[a-z][a-z0-9.+-]*$/', $type)) {
            throw new \InvalidArgumentException("Invalid purl type '{$type}'.");
        }
        $name = trim($name);
        if ($name === '') {
            throw new \InvalidArgumentException('A purl needs a package name.');
        }
        [$namespace, $name] = $this->normalise($type, $namespace, $name);

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

        // "0" is a version (if ($version) would drop it).
        if ($version !== null && $version !== '') {
            // ':' stays literal in the canonical form (Debian epochs, RHSA-style versions).
            $purl .= '@'.str_replace('%3A', ':', $this->encodeSegment($version));
        }

        $qs = [];
        foreach ($qualifiers as $k => $v) {
            // Empty values are dropped and keys lowercased, per the spec.
            if (! is_scalar($v) || (string) $v === '') {
                continue;
            }
            $qs[strtolower((string) $k)] = str_replace('%3A', ':', rawurlencode((string) $v));
        }
        if ($qs !== []) {
            ksort($qs);
            $purl .= '?'.implode('&', array_map(fn ($k, $v) => "{$k}={$v}", array_keys($qs), $qs));
        }

        if ($subpath !== null && ($segments = $this->subpathSegments($subpath)) !== []) {
            $purl .= '#'.implode('/', array_map($this->encodeSegment(...), $segments));
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
        // "pkg://type/…" is tolerated: leading slashes are not significant.
        $remainder = ltrim(substr($purl, 4), '/');

        // Extract subpath
        $subpath = null;
        if (($hashPos = strpos($remainder, '#')) !== false) {
            $subpath = implode('/', $this->subpathSegments(rawurldecode(substr($remainder, $hashPos + 1)))) ?: null;
            $remainder = substr($remainder, 0, $hashPos);
        }

        // Extract qualifiers — split by hand: parse_str() rewrites keys
        // ("vcs.url" → "vcs_url"), turns "+" into a space and "a[]=1" into
        // an array.
        $qualifiers = [];
        if (($qPos = strpos($remainder, '?')) !== false) {
            foreach (explode('&', substr($remainder, $qPos + 1)) as $pair) {
                [$key, $value] = array_pad(explode('=', $pair, 2), 2, '');
                $key = strtolower(trim($key));
                if ($key !== '' && $value !== '') {
                    $qualifiers[$key] = rawurldecode($value);
                }
            }
            ksort($qualifiers);
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
            $version = $version === '' ? null : $version;
            $remainder = substr($remainder, 0, $atPos);
        }

        // type / namespace… / name — the name is the LAST segment, everything
        // between it and the type is the namespace (a Go module path has
        // several: pkg:golang/github.com/gin-gonic/gin).
        $parts = array_values(array_filter(explode('/', $remainder), fn (string $p) => $p !== ''));
        $type = strtolower((string) array_shift($parts));
        if (! preg_match('/^[a-z][a-z0-9.+-]*$/', $type)) {
            throw new \InvalidArgumentException("Invalid purl '{$purl}': '{$type}' is not a valid type.");
        }
        if ($parts === []) {
            throw new \InvalidArgumentException("Invalid purl '{$purl}': no package name after the type.");
        }
        $name = rawurldecode((string) array_pop($parts));
        $namespace = $parts ? implode('/', array_map('rawurldecode', $parts)) : null;
        [$namespace, $name] = $this->normalise($type, $namespace, $name);

        return compact('type', 'namespace', 'name', 'version', 'qualifiers', 'subpath');
    }

    /**
     * Compute a stable SHA-256 checksum for a normalised PURL.
     * Used for deduplication and caching.
     */
    public function checksum(string $purl): string
    {
        // Canonicalised rather than lowercased wholesale: case only folds
        // where the type says names are case-insensitive, so two packages
        // whose names differ by case elsewhere don't collide.
        try {
            $p = $this->parse($purl);
            $purl = $this->build($p['type'], $p['name'], $p['version'], $p['namespace'], $p['qualifiers'], $p['subpath']);
        } catch (\InvalidArgumentException) {
            $purl = strtolower($purl);
        }

        return hash('sha256', $purl);
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
            && in_array($type, ['composer', 'npm', 'golang', 'github', 'gitlab', 'bitbucket'], true)) {
            // The name is the LAST segment: a Go module path keeps its whole
            // prefix as the namespace (github.com/gin-gonic + gin).
            $cut = strrpos($name, '/');
            [$namespace, $name] = [substr($name, 0, $cut), substr($name, $cut + 1)];
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

    /**
     * Per-type canonical casing/spelling from the purl type definitions:
     * names are case-insensitive on these registries, so one package must
     * not end up with two purls.
     *
     * @return array{0: ?string, 1: string} [namespace, name]
     */
    private function normalise(string $type, ?string $namespace, string $name): array
    {
        $namespace = $namespace === null ? null : trim($namespace, '/');

        return match ($type) {
            'pypi' => [$namespace, str_replace('_', '-', strtolower($name))],
            'github', 'bitbucket', 'gitlab', 'composer', 'npm', 'deb', 'rpm', 'apk', 'alpm', 'hex', 'pub' => [$namespace === null ? null : strtolower($namespace), strtolower($name)],
            default => [$namespace, $name],
        };
    }

    /** @return string[] subpath segments, without empty, "." and ".." entries */
    private function subpathSegments(string $subpath): array
    {
        return array_values(array_filter(
            explode('/', trim($subpath, '/')),
            fn (string $segment) => $segment !== '' && $segment !== '.' && $segment !== '..',
        ));
    }

    private function encodeSegment(string $segment): string
    {
        // percent-encode everything except unreserved chars and @ : /
        return rawurlencode($segment);
    }
}
