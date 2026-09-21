<?php

declare(strict_types=1);
use Gumslone\Vulns\Tests\TestCase;

// Feature tests boot the Testbench application; Unit tests stay plain.
uses(TestCase::class)->in('Feature');
