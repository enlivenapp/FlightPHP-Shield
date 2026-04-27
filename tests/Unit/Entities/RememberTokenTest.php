<?php

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Unit\Entities;

use Enlivenapp\FlightShield\Models\RememberToken;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(RememberToken::class)]
class RememberTokenTest extends TestCase
{
    /**
     * Build a RememberToken without invoking the ActiveRecord constructor
     * (which requires a PDO connection).
     */
    private function makeToken(): RememberToken
    {
        /** @var RememberToken $token */
        $token = $this->getMockBuilder(RememberToken::class)
            ->disableOriginalConstructor()
            ->onlyMethods([])
            ->getMock();

        return $token;
    }

    #[Test]
    public function isExpiredReturnsTrueForPastDate(): void
    {
        $token          = $this->makeToken();
        $token->expires = '2000-01-01 00:00:00';

        $this->assertTrue($token->isExpired());
    }

    #[Test]
    public function isExpiredReturnsFalseForFutureDate(): void
    {
        $token          = $this->makeToken();
        $token->expires = '2099-12-31 23:59:59';

        $this->assertFalse($token->isExpired());
    }

    #[Test]
    public function isExpiredReturnsTrueForDateOneSecondAgo(): void
    {
        $token          = $this->makeToken();
        $oneSecondAgo   = (new \DateTimeImmutable())->modify('-1 second')->format('Y-m-d H:i:s');
        $token->expires = $oneSecondAgo;

        $this->assertTrue($token->isExpired());
    }

    #[Test]
    public function isExpiredReturnsFalseForDateOneHourInFuture(): void
    {
        $token          = $this->makeToken();
        $futureDate     = (new \DateTimeImmutable())->modify('+1 hour')->format('Y-m-d H:i:s');
        $token->expires = $futureDate;

        $this->assertFalse($token->isExpired());
    }
}
