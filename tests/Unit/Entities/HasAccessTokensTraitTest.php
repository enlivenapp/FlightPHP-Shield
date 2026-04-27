<?php

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Unit\Entities;

use Enlivenapp\FlightShield\Models\AccessToken;
use Enlivenapp\FlightShield\Traits\HasAccessTokens;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(HasAccessTokens::class)]
class HasAccessTokensTraitTest extends TestCase
{
    private function makeObject(): object
    {
        return new class {
            use HasAccessTokens;
        };
    }

    private function makeToken(array $scopes = [], ?string $expires = null): AccessToken
    {
        $token          = new AccessToken();
        $token->id      = 1;
        $token->user_id = 1;
        $token->name    = 'test';
        $token->secret  = 'secret';
        $token->secret2 = null;
        $token->expires = $expires;
        $token->setScopes($scopes);

        return $token;
    }

    #[Test]
    public function currentAccessTokenIsNullByDefault(): void
    {
        $obj = $this->makeObject();

        $this->assertNull($obj->currentAccessToken());
    }

    #[Test]
    public function setAccessTokenStoresToken(): void
    {
        $obj   = $this->makeObject();
        $token = $this->makeToken();
        $obj->setAccessToken($token);

        $this->assertSame($token, $obj->currentAccessToken());
    }

    #[Test]
    public function setAccessTokenReturnsSameInstance(): void
    {
        $obj      = $this->makeObject();
        $token    = $this->makeToken();
        $returned = $obj->setAccessToken($token);

        $this->assertSame($obj, $returned);
    }

    #[Test]
    public function setAccessTokenWithNullClearsToken(): void
    {
        $obj   = $this->makeObject();
        $token = $this->makeToken();
        $obj->setAccessToken($token);
        $obj->setAccessToken(null);

        $this->assertNull($obj->currentAccessToken());
    }

    #[Test]
    public function tokenCanReturnsFalseWhenNoToken(): void
    {
        $obj = $this->makeObject();

        $this->assertFalse($obj->tokenCan('read'));
    }

    #[Test]
    public function tokenCanReturnsTrueWhenTokenHasScope(): void
    {
        $obj   = $this->makeObject();
        $token = $this->makeToken(['read', 'write']);
        $obj->setAccessToken($token);

        $this->assertTrue($obj->tokenCan('read'));
    }

    #[Test]
    public function tokenCanReturnsFalseWhenTokenLacksScope(): void
    {
        $obj   = $this->makeObject();
        $token = $this->makeToken(['read']);
        $obj->setAccessToken($token);

        $this->assertFalse($obj->tokenCan('delete'));
    }

    #[Test]
    public function tokenCanReturnsTrueWithWildcardScope(): void
    {
        $obj   = $this->makeObject();
        $token = $this->makeToken(['*']);
        $obj->setAccessToken($token);

        $this->assertTrue($obj->tokenCan('anything'));
    }

    #[Test]
    public function tokenCantReturnsTrueWhenNoToken(): void
    {
        $obj = $this->makeObject();

        $this->assertTrue($obj->tokenCant('read'));
    }

    #[Test]
    public function tokenCantReturnsFalseWhenTokenHasScope(): void
    {
        $obj   = $this->makeObject();
        $token = $this->makeToken(['read']);
        $obj->setAccessToken($token);

        $this->assertFalse($obj->tokenCant('read'));
    }

    #[Test]
    public function tokenCantReturnsTrueWhenTokenLacksScope(): void
    {
        $obj   = $this->makeObject();
        $token = $this->makeToken(['read']);
        $obj->setAccessToken($token);

        $this->assertTrue($obj->tokenCant('delete'));
    }

    #[Test]
    public function isAccessTokenExpiredReturnsFalseForNullExpiry(): void
    {
        $obj   = $this->makeObject();
        $token = $this->makeToken([], null);

        $this->assertFalse($obj->isAccessTokenExpired($token));
    }

    #[Test]
    public function isAccessTokenExpiredReturnsTrueForPastDate(): void
    {
        $obj   = $this->makeObject();
        $token = $this->makeToken([], '2000-01-01 00:00:00');

        $this->assertTrue($obj->isAccessTokenExpired($token));
    }

    #[Test]
    public function isAccessTokenExpiredReturnsFalseForFutureDate(): void
    {
        $obj   = $this->makeObject();
        $token = $this->makeToken([], '2099-12-31 23:59:59');

        $this->assertFalse($obj->isAccessTokenExpired($token));
    }
}
