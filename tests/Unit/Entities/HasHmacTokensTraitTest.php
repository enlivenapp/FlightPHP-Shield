<?php

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Unit\Entities;

use Enlivenapp\FlightShield\Models\AccessToken;
use Enlivenapp\FlightShield\Traits\HasHmacTokens;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(HasHmacTokens::class)]
class HasHmacTokensTraitTest extends TestCase
{
    private function makeObject(): object
    {
        return new class {
            use HasHmacTokens;
        };
    }

    private function makeToken(array $scopes = [], ?string $expires = null): AccessToken
    {
        $token          = new AccessToken();
        $token->id      = 1;
        $token->user_id = 1;
        $token->name    = 'hmac-test';
        $token->secret  = 'hmac-secret';
        $token->secret2 = null;
        $token->expires = $expires;
        $token->setScopes($scopes);

        return $token;
    }

    #[Test]
    public function currentHmacTokenIsNullByDefault(): void
    {
        $obj = $this->makeObject();

        $this->assertNull($obj->currentHmacToken());
    }

    #[Test]
    public function setHmacTokenStoresToken(): void
    {
        $obj   = $this->makeObject();
        $token = $this->makeToken();
        $obj->setHmacToken($token);

        $this->assertSame($token, $obj->currentHmacToken());
    }

    #[Test]
    public function setHmacTokenReturnsSameInstance(): void
    {
        $obj      = $this->makeObject();
        $token    = $this->makeToken();
        $returned = $obj->setHmacToken($token);

        $this->assertSame($obj, $returned);
    }

    #[Test]
    public function setHmacTokenWithNullClearsToken(): void
    {
        $obj   = $this->makeObject();
        $token = $this->makeToken();
        $obj->setHmacToken($token);
        $obj->setHmacToken(null);

        $this->assertNull($obj->currentHmacToken());
    }

    #[Test]
    public function hmacTokenCanReturnsFalseWhenNoToken(): void
    {
        $obj = $this->makeObject();

        $this->assertFalse($obj->hmacTokenCan('read'));
    }

    #[Test]
    public function hmacTokenCanReturnsTrueWhenTokenHasScope(): void
    {
        $obj   = $this->makeObject();
        $token = $this->makeToken(['read', 'write']);
        $obj->setHmacToken($token);

        $this->assertTrue($obj->hmacTokenCan('read'));
    }

    #[Test]
    public function hmacTokenCanReturnsFalseWhenTokenLacksScope(): void
    {
        $obj   = $this->makeObject();
        $token = $this->makeToken(['read']);
        $obj->setHmacToken($token);

        $this->assertFalse($obj->hmacTokenCan('delete'));
    }

    #[Test]
    public function hmacTokenCanReturnsTrueWithWildcardScope(): void
    {
        $obj   = $this->makeObject();
        $token = $this->makeToken(['*']);
        $obj->setHmacToken($token);

        $this->assertTrue($obj->hmacTokenCan('anything'));
    }

    #[Test]
    public function hmacTokenCantReturnsTrueWhenNoToken(): void
    {
        $obj = $this->makeObject();

        $this->assertTrue($obj->hmacTokenCant('read'));
    }

    #[Test]
    public function hmacTokenCantReturnsFalseWhenTokenHasScope(): void
    {
        $obj   = $this->makeObject();
        $token = $this->makeToken(['read']);
        $obj->setHmacToken($token);

        $this->assertFalse($obj->hmacTokenCant('read'));
    }

    #[Test]
    public function hmacTokenCantReturnsTrueWhenTokenLacksScope(): void
    {
        $obj   = $this->makeObject();
        $token = $this->makeToken(['read']);
        $obj->setHmacToken($token);

        $this->assertTrue($obj->hmacTokenCant('delete'));
    }

    #[Test]
    public function isHmacTokenExpiredReturnsFalseForNullExpiry(): void
    {
        $obj   = $this->makeObject();
        $token = $this->makeToken([], null);

        $this->assertFalse($obj->isHmacTokenExpired($token));
    }

    #[Test]
    public function isHmacTokenExpiredReturnsTrueForPastDate(): void
    {
        $obj   = $this->makeObject();
        $token = $this->makeToken([], '2000-01-01 00:00:00');

        $this->assertTrue($obj->isHmacTokenExpired($token));
    }

    #[Test]
    public function isHmacTokenExpiredReturnsFalseForFutureDate(): void
    {
        $obj   = $this->makeObject();
        $token = $this->makeToken([], '2099-12-31 23:59:59');

        $this->assertFalse($obj->isHmacTokenExpired($token));
    }
}
