<?php

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Unit\Entities;

use Enlivenapp\FlightShield\Models\AccessToken;
use Enlivenapp\FlightShield\Models\UserIdentity;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(AccessToken::class)]
class AccessTokenTest extends TestCase
{
    /**
     * Build a UserIdentity stub without invoking the ActiveRecord constructor.
     */
    private function makeIdentity(): UserIdentity
    {
        /** @var UserIdentity $identity */
        $identity = $this->getMockBuilder(UserIdentity::class)
            ->disableOriginalConstructor()
            ->onlyMethods([])
            ->getMock();

        $identity->id           = 1;
        $identity->user_id      = 42;
        $identity->name         = 'My Token';
        $identity->secret       = 'abc123';
        $identity->secret2      = null;
        $identity->expires      = null;
        $identity->last_used_at = null;
        $identity->created_at   = '2026-01-01 00:00:00';
        $identity->updated_at   = '2026-01-02 00:00:00';
        $identity->extra        = null;

        return $identity;
    }

    #[Test]
    public function fromIdentityMapsAllFields(): void
    {
        $identity = $this->makeIdentity();
        $token    = AccessToken::fromIdentity($identity);

        $this->assertSame(1, $token->id);
        $this->assertSame(42, $token->user_id);
        $this->assertSame('My Token', $token->name);
        $this->assertSame('abc123', $token->secret);
        $this->assertNull($token->secret2);
        $this->assertNull($token->expires);
        $this->assertNull($token->last_used_at);
        $this->assertSame('2026-01-01 00:00:00', $token->created_at);
        $this->assertSame('2026-01-02 00:00:00', $token->updated_at);
    }

    #[Test]
    public function fromIdentityWithJsonExtraDecodesScopes(): void
    {
        $identity        = $this->makeIdentity();
        $identity->extra = json_encode(['read', 'write']);

        $token = AccessToken::fromIdentity($identity);

        $this->assertSame(['read', 'write'], $token->getScopes());
    }

    #[Test]
    public function fromIdentityWithNullExtraLeavesEmptyScopes(): void
    {
        $identity        = $this->makeIdentity();
        $identity->extra = null;

        $token = AccessToken::fromIdentity($identity);

        $this->assertSame([], $token->getScopes());
    }

    #[Test]
    public function fromIdentityWithNonArrayJsonExtraLeavesEmptyScopes(): void
    {
        $identity        = $this->makeIdentity();
        $identity->extra = json_encode('just a string');

        $token = AccessToken::fromIdentity($identity);

        $this->assertSame([], $token->getScopes());
    }

    #[Test]
    public function fromIdentityWithAssocJsonExtraSetsScopes(): void
    {
        $identity        = $this->makeIdentity();
        // json_decode with assoc=true returns array even for objects
        $identity->extra = json_encode(['key' => 'value']);

        $token = AccessToken::fromIdentity($identity);

        // is_array(['key'=>'value']) is true, so scopes get set
        $this->assertIsArray($token->getScopes());
        $this->assertNotEmpty($token->getScopes());
    }

    #[Test]
    public function canReturnsTrueForMatchingScope(): void
    {
        $token = new AccessToken();
        $token->setScopes(['read', 'write']);

        $this->assertTrue($token->can('read'));
        $this->assertTrue($token->can('write'));
    }

    #[Test]
    public function canReturnsFalseForNonMatchingScope(): void
    {
        $token = new AccessToken();
        $token->setScopes(['read']);

        $this->assertFalse($token->can('delete'));
    }

    #[Test]
    public function canReturnsTrueWithWildcardScope(): void
    {
        $token = new AccessToken();
        $token->setScopes(['*']);

        $this->assertTrue($token->can('anything'));
        $this->assertTrue($token->can('read'));
        $this->assertTrue($token->can('delete'));
    }

    #[Test]
    public function cantIsInverseOfCan(): void
    {
        $token = new AccessToken();
        $token->setScopes(['read']);

        $this->assertFalse($token->cant('read'));
        $this->assertTrue($token->cant('write'));
    }

    #[Test]
    public function cantReturnsFalseWithWildcardScope(): void
    {
        $token = new AccessToken();
        $token->setScopes(['*']);

        $this->assertFalse($token->cant('anything'));
    }

    #[Test]
    public function getScopesReturnsEmptyArrayByDefault(): void
    {
        $token = new AccessToken();

        $this->assertSame([], $token->getScopes());
    }

    #[Test]
    public function setScopesAndGetScopes(): void
    {
        $token = new AccessToken();
        $token->setScopes(['admin', 'user']);

        $this->assertSame(['admin', 'user'], $token->getScopes());
    }

    #[Test]
    public function isExpiredReturnsFalseWhenExpiresIsNull(): void
    {
        $token          = new AccessToken();
        $token->expires = null;

        $this->assertFalse($token->isExpired());
    }

    #[Test]
    public function isExpiredReturnsTrueForPastDate(): void
    {
        $token          = new AccessToken();
        $token->expires = '2000-01-01 00:00:00';

        $this->assertTrue($token->isExpired());
    }

    #[Test]
    public function isExpiredReturnsFalseForFutureDate(): void
    {
        $token          = new AccessToken();
        $token->expires = '2099-12-31 23:59:59';

        $this->assertFalse($token->isExpired());
    }

    #[Test]
    public function debugInfoHidesSecretAndSecret2AndRawToken(): void
    {
        $token           = new AccessToken();
        $token->id       = 1;
        $token->user_id  = 5;
        $token->name     = 'Test';
        $token->secret   = 'super-secret';
        $token->secret2  = 'super-secret2';
        $token->rawToken = 'raw-token-value';

        $debug = $token->__debugInfo();

        $this->assertArrayNotHasKey('secret', $debug);
        $this->assertArrayNotHasKey('secret2', $debug);
        $this->assertArrayNotHasKey('rawToken', $debug);
    }

    #[Test]
    public function debugInfoIncludesNonSensitiveFields(): void
    {
        $token          = new AccessToken();
        $token->id      = 7;
        $token->user_id = 3;
        $token->name    = 'Visible Token';
        $token->secret  = 'hidden';
        $token->secret2 = null;

        $debug = $token->__debugInfo();

        $this->assertArrayHasKey('id', $debug);
        $this->assertArrayHasKey('user_id', $debug);
        $this->assertArrayHasKey('name', $debug);
    }
}
