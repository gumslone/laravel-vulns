<?php

declare(strict_types=1);

namespace Gumslone\Vulns\Support;

use Gumslone\Vulns\Data\PackageData;

/**
 * Reads the two lockfiles a PHP application ships with — composer.lock and
 * npm's package-lock.json (v1, v2 and v3) — into PackageData, so an app can
 * audit itself without a scanner. Anything else belongs to a real SCA tool.
 */
final class LockfileReader
{
    /**
     * @return array<string, PackageData> keyed "ecosystem:name@version" (duplicates collapse)
     *
     * @throws \InvalidArgumentException when the file is missing, unreadable or not a known lockfile
     */
    public static function read(string $path, bool $includeDev = true): array
    {
        if (! is_file($path) || ! is_readable($path)) {
            throw new \InvalidArgumentException("Lockfile not found: {$path}");
        }

        $data = json_decode((string) file_get_contents($path), true);
        if (! is_array($data)) {
            throw new \InvalidArgumentException("Not a JSON lockfile: {$path}");
        }

        return match (true) {
            isset($data['packages']) && array_is_list($data['packages']) => self::composer($data, $includeDev),
            isset($data['lockfileVersion']) => self::npm($data, $includeDev),
            default => throw new \InvalidArgumentException("Unrecognised lockfile (expected composer.lock or package-lock.json): {$path}"),
        };
    }

    /** @return array<string, PackageData> */
    private static function composer(array $lock, bool $includeDev): array
    {
        $packages = [];
        foreach ($includeDev ? ['packages', 'packages-dev'] : ['packages'] as $section) {
            foreach (is_array($lock[$section] ?? null) ? $lock[$section] : [] as $entry) {
                $name = is_array($entry) ? trim((string) ($entry['name'] ?? '')) : '';
                $version = is_array($entry) ? Version::normalize((string) ($entry['version'] ?? '')) : '';
                // "dev-main" style branch aliases carry no comparable version.
                if ($name === '' || $version === '' || str_starts_with($version, 'dev-')) {
                    continue;
                }
                $packages["composer:{$name}@{$version}"] = new PackageData(
                    name: $name, version: $version, ecosystem: 'composer', isDevDependency: $section === 'packages-dev',
                );
            }
        }

        return $packages;
    }

    /** @return array<string, PackageData> */
    private static function npm(array $lock, bool $includeDev): array
    {
        $packages = [];
        $add = function (string $name, mixed $entry) use (&$packages, $includeDev): void {
            $version = is_array($entry) ? trim((string) ($entry['version'] ?? '')) : '';
            $dev = is_array($entry) && ! empty($entry['dev']);
            // Links, git and file dependencies have no registry version.
            if ($name === '' || ! preg_match('/^\d/', $version) || ($dev && ! $includeDev) || ! empty($entry['link'])) {
                return;
            }
            $packages["npm:{$name}@{$version}"] = new PackageData(name: $name, version: $version, ecosystem: 'npm', isDevDependency: $dev);
        };

        // v2/v3: a flat map keyed by install path ("node_modules/a/node_modules/@scope/b").
        foreach (is_array($lock['packages'] ?? null) ? $lock['packages'] : [] as $path => $entry) {
            if (is_string($path) && ($at = strrpos($path, 'node_modules/')) !== false) {
                $add(substr($path, $at + strlen('node_modules/')), $entry);
            }
        }

        // v1 (and the v2 compatibility block): nested `dependencies`.
        $walk = function (array $dependencies) use (&$walk, $add): void {
            foreach ($dependencies as $name => $entry) {
                $add((string) $name, $entry);
                if (is_array($entry['dependencies'] ?? null)) {
                    $walk($entry['dependencies']);
                }
            }
        };
        if ($packages === [] && is_array($lock['dependencies'] ?? null)) {
            $walk($lock['dependencies']);
        }

        return $packages;
    }
}
