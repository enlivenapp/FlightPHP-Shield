<?php

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Unit\Entities;

use Enlivenapp\FlightShield\Traits\Bannable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(Bannable::class)]
class BannableTraitTest extends TestCase
{
    private function makeObject(): object
    {
        return new class {
            use Bannable;

            public ?string $status         = null;
            public ?string $status_message = null;
        };
    }

    #[Test]
    public function isBannedReturnsFalseByDefault(): void
    {
        $obj = $this->makeObject();

        $this->assertFalse($obj->isBanned());
    }

    #[Test]
    public function banSetStatusToBanned(): void
    {
        $obj = $this->makeObject();
        $obj->ban();

        $this->assertSame('banned', $obj->status);
    }

    #[Test]
    public function banMakesIsBannedReturnTrue(): void
    {
        $obj = $this->makeObject();
        $obj->ban();

        $this->assertTrue($obj->isBanned());
    }

    #[Test]
    public function banWithMessageStoresMessage(): void
    {
        $obj = $this->makeObject();
        $obj->ban('Violation of terms');

        $this->assertSame('Violation of terms', $obj->status_message);
    }

    #[Test]
    public function banWithoutMessageLeavesMessageNull(): void
    {
        $obj = $this->makeObject();
        $obj->ban();

        $this->assertNull($obj->status_message);
    }

    #[Test]
    public function getBanMessageReturnsNullWhenNotBanned(): void
    {
        $obj = $this->makeObject();

        $this->assertNull($obj->getBanMessage());
    }

    #[Test]
    public function getBanMessageReturnsMessageAfterBan(): void
    {
        $obj = $this->makeObject();
        $obj->ban('Spamming');

        $this->assertSame('Spamming', $obj->getBanMessage());
    }

    #[Test]
    public function unBanResetsStatus(): void
    {
        $obj = $this->makeObject();
        $obj->ban('Test');
        $obj->unBan();

        $this->assertNull($obj->status);
    }

    #[Test]
    public function unBanResetsStatusMessage(): void
    {
        $obj = $this->makeObject();
        $obj->ban('Test');
        $obj->unBan();

        $this->assertNull($obj->status_message);
    }

    #[Test]
    public function unBanMakesIsBannedReturnFalse(): void
    {
        $obj = $this->makeObject();
        $obj->ban();
        $obj->unBan();

        $this->assertFalse($obj->isBanned());
    }

    #[Test]
    public function banReturnsSameInstance(): void
    {
        $obj      = $this->makeObject();
        $returned = $obj->ban();

        $this->assertSame($obj, $returned);
    }

    #[Test]
    public function unBanReturnsSameInstance(): void
    {
        $obj      = $this->makeObject();
        $returned = $obj->unBan();

        $this->assertSame($obj, $returned);
    }
}
