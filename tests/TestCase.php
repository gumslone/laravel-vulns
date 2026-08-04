<?php

declare(strict_types=1);

namespace Gumslone\Vulns\Tests;

use Gumslone\Vulns\VulnsServiceProvider;
use Orchestra\Testbench\TestCase as BaseTestCase;

abstract class TestCase extends BaseTestCase
{
    protected function getPackageProviders($app): array
    {
        return [VulnsServiceProvider::class];
    }
}
