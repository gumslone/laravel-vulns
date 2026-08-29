<?php

declare(strict_types=1);

// Feature tests boot the Testbench application; Unit tests stay plain.
uses(Gumslone\Vulns\Tests\TestCase::class)->in('Feature');
