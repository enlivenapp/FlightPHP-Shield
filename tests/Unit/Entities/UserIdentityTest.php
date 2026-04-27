<?php

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Unit\Entities;

use Enlivenapp\FlightShield\Models\UserIdentity;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(UserIdentity::class)]
class UserIdentityTest extends TestCase
{
    /**
     * Build a UserIdentity without invoking the ActiveRecord constructor
     * (which requires a PDO connection).
     */
    private function makeIdentity(): UserIdentity
    {
        /** @var UserIdentity $identity */
        $identity = $this->getMockBuilder(UserIdentity::class)
            ->disableOriginalConstructor()
            ->onlyMethods([])
            ->getMock();

        return $identity;
    }

    #[Test]
    public function constantTypeEmailPassword(): void
    {
        $this->assertSame('email_password', UserIdentity::TYPE_EMAIL_PASSWORD);
    }

    #[Test]
    public function constantTypeMagicLink(): void
    {
        $this->assertSame('magic-link', UserIdentity::TYPE_MAGIC_LINK);
    }

    #[Test]
    public function constantTypeEmail2FA(): void
    {
        $this->assertSame('email_2fa', UserIdentity::TYPE_EMAIL_2FA);
    }

    #[Test]
    public function constantTypeEmailActivate(): void
    {
        $this->assertSame('email_activate', UserIdentity::TYPE_EMAIL_ACTIVATE);
    }

    #[Test]
    public function constantTypeAccessToken(): void
    {
        $this->assertSame('access_token', UserIdentity::TYPE_ACCESS_TOKEN);
    }

    #[Test]
    public function constantTypeHmacToken(): void
    {
        $this->assertSame('hmac_sha256', UserIdentity::TYPE_HMAC_TOKEN);
    }

    #[Test]
    public function isExpiredReturnsFalseWhenExpiresIsNull(): void
    {
        $identity          = $this->makeIdentity();
        $identity->expires = null;

        $this->assertFalse($identity->isExpired());
    }

    #[Test]
    public function isExpiredReturnsTrueForPastDate(): void
    {
        $identity          = $this->makeIdentity();
        $identity->expires = '2000-01-01 00:00:00';

        $this->assertTrue($identity->isExpired());
    }

    #[Test]
    public function isExpiredReturnsFalseForFutureDate(): void
    {
        $identity          = $this->makeIdentity();
        $identity->expires = '2099-12-31 23:59:59';

        $this->assertFalse($identity->isExpired());
    }

    #[Test]
    public function debugInfoExcludesSecret(): void
    {
        $identity          = $this->makeIdentity();
        $identity->secret  = 'password-hash';
        $identity->secret2 = 'second-secret';

        $debug = $identity->__debugInfo();

        $this->assertArrayNotHasKey('secret', $debug);
    }

    #[Test]
    public function debugInfoExcludesSecret2(): void
    {
        $identity          = $this->makeIdentity();
        $identity->secret  = 'password-hash';
        $identity->secret2 = 'second-secret';

        $debug = $identity->__debugInfo();

        $this->assertArrayNotHasKey('secret2', $debug);
    }

    #[Test]
    public function debugInfoIncludesNonSensitiveFields(): void
    {
        $identity          = $this->makeIdentity();
        $identity->id      = 1;
        $identity->user_id = 5;
        $identity->type    = UserIdentity::TYPE_EMAIL_PASSWORD;
        $identity->secret  = 'hidden';

        $debug = $identity->__debugInfo();

        $this->assertArrayHasKey('id', $debug);
        $this->assertArrayHasKey('user_id', $debug);
        $this->assertArrayHasKey('type', $debug);
    }
}
