<?php

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Unit\Entities;

use Enlivenapp\FlightShield\Traits\Activatable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(Activatable::class)]
class ActivatableTraitTest extends TestCase
{
    private function makeObject(bool $initialActive = false): object
    {
        return new class ($initialActive) {
            use Activatable;

            public bool $active;

            public function __construct(bool $active)
            {
                $this->active = $active;
            }
        };
    }

    #[Test]
    public function isActivatedReturnsFalseByDefault(): void
    {
        $obj = $this->makeObject(false);

        $this->assertFalse($obj->isActivated());
    }

    #[Test]
    public function isActivatedReturnsTrueWhenActiveIsTrue(): void
    {
        $obj = $this->makeObject(true);

        $this->assertTrue($obj->isActivated());
    }

    #[Test]
    public function isNotActivatedReturnsTrueWhenNotActive(): void
    {
        $obj = $this->makeObject(false);

        $this->assertTrue($obj->isNotActivated());
    }

    #[Test]
    public function isNotActivatedReturnsFalseWhenActive(): void
    {
        $obj = $this->makeObject(true);

        $this->assertFalse($obj->isNotActivated());
    }

    #[Test]
    public function activateSetsActiveTrueAndIsActivatedReturnsTrue(): void
    {
        $obj = $this->makeObject(false);
        $obj->activate();

        $this->assertTrue($obj->isActivated());
        $this->assertTrue($obj->active);
    }

    #[Test]
    public function deactivateSetsActiveFalseAndIsActivatedReturnsFalse(): void
    {
        $obj = $this->makeObject(true);
        $obj->deactivate();

        $this->assertFalse($obj->isActivated());
        $this->assertFalse($obj->active);
    }

    #[Test]
    public function activateThenDeactivateRoundtrip(): void
    {
        $obj = $this->makeObject(false);
        $obj->activate();
        $this->assertTrue($obj->isActivated());

        $obj->deactivate();
        $this->assertFalse($obj->isActivated());
    }
}
