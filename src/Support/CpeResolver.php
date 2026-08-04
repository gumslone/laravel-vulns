<?php

declare(strict_types=1);

namespace Gumslone\Vulns\Support;

use Gumslone\Vulns\Data\PackageData;

/**
 * Resolves Common Platform Enumeration (CPE) identifiers for packages.
 * Supports both CPE 2.2 and CPE 2.3 (structured binding) formats.
 *
 * CPE 2.3 FS: cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
 * CPE 2.2 URI: cpe:/a:vendor:product:version
 */
class CpeResolver
{
    /**
     * Attempt to build a CPE 2.3 string for a package.
     * Returns null if not enough information is available.
     */
    public function resolveCpe23(PackageData $pkg): ?string
    {
        $vendor = $this->normaliseVendor($pkg);
        $product = $this->normaliseProduct($pkg->name);
        $version = $pkg->version ? $this->normaliseVersion($pkg->version) : '*';

        if (! $vendor || ! $product) {
            return null;
        }

        return implode(':', [
            'cpe', '2.3', 'a',
            $vendor, $product, $version,
            '*', '*', '*', '*', '*', '*', '*',
        ]);
    }

    /**
     * Build the legacy CPE 2.2 URI format.
     */
    public function resolveCpe22(PackageData $pkg): ?string
    {
        $vendor = $this->normaliseVendor($pkg);
        $product = $this->normaliseProduct($pkg->name);
        $version = $pkg->version ? $this->normaliseVersion($pkg->version) : '';

        if (! $vendor || ! $product) {
            return null;
        }

        return "cpe:/a:{$vendor}:{$product}".($version ? ":{$version}" : '');
    }

    /**
     * Determine vendor from package namespace or known mappings.
     */
    private function normaliseVendor(PackageData $pkg): ?string
    {
        // Namespace is the best source of vendor info
        if ($pkg->namespace) {
            return $this->sanitise($this->vendorFromNamespace($pkg->namespace));
        }

        // For composer, the vendor is the first part of name
        if ($pkg->ecosystem === 'composer' && str_contains($pkg->name, '/')) {
            return $this->sanitise(explode('/', $pkg->name)[0]);
        }

        // For npm scoped packages @scope/name
        if ($pkg->ecosystem === 'npm' && str_starts_with($pkg->name, '@')) {
            $scope = explode('/', ltrim($pkg->name, '@'))[0];

            return $this->sanitise($scope);
        }

        // Fallback: use the short product name as vendor
        return $this->sanitise(explode('/', $pkg->name)[0] ?? $pkg->name);
    }

    /**
     * Turn a package namespace into a plausible CPE vendor.
     *
     * For VCS-host-style namespaces (Go modules, e.g. "github.com/gin-gonic"),
     * the NVD vendor is the repo OWNER after the host — "gin-gonic", not the
     * host string "github.com_gin-gonic" which matches no NVD record. Other
     * namespaces (composer vendor, npm scope, Maven groupId) pass through.
     */
    private function vendorFromNamespace(string $namespace): string
    {
        $segments = explode('/', $namespace);

        // First segment is a hostname (contains a dot) with an owner after it.
        if (count($segments) > 1 && str_contains($segments[0], '.')) {
            return $segments[1];
        }

        return $namespace;
    }

    private function normaliseProduct(string $name): string
    {
        // Strip namespace/scope prefix
        $parts = explode('/', $name);
        $name = end($parts);
        // Strip npm @ scope
        $name = ltrim($name, '@');

        return $this->sanitise($name);
    }

    private function normaliseVersion(string $version): string
    {
        return \Gumslone\Vulns\Support\Version::normalize($version);
    }

    /**
     * Sanitise a CPE component: lowercase and replace non-alphanumeric with
     * underscore. Leading/trailing underscores are trimmed so an npm scope
     * like "@alloc" yields "alloc", not "_alloc" (internal underscores such
     * as in "linux_kernel" are preserved).
     */
    private function sanitise(string $value): string
    {
        return trim((string) preg_replace('/[^a-z0-9._\-]/', '_', strtolower($value)), '_');
    }

    /**
     * Validate a CPE 2.3 string.
     */
    public function isValidCpe23(string $cpe): bool
    {
        return (bool) preg_match(
            '/^cpe:2\.3:[aho\*\-](?::[a-z0-9\-\.\_\*\+]+){10}$/i',
            $cpe
        );
    }

    /**
     * Parse a CPE 2.3 string into components.
     *
     * @return array{part:string, vendor:string, product:string, version:string, ...}
     */
    public function parse23(string $cpe): array
    {
        $keys = ['cpe', 'spec', 'part', 'vendor', 'product', 'version', 'update', 'edition', 'language', 'sw_edition', 'target_sw', 'target_hw', 'other'];
        $parts = explode(':', $cpe);
        $result = [];
        foreach ($keys as $i => $key) {
            $result[$key] = $parts[$i] ?? '*';
        }

        return $result;
    }
}
