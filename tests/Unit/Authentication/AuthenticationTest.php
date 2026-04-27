<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Unit\Authentication;

use Enlivenapp\FlightShield\Authentication\Authentication;
use Enlivenapp\FlightShield\Authentication\AuthenticatorInterface;
use Enlivenapp\FlightShield\Authentication\Authenticators\AccessTokens;
use Enlivenapp\FlightShield\Authentication\Authenticators\Session;
use Enlivenapp\FlightShield\Exceptions\AuthenticationException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(Authentication::class)]
class AuthenticationTest extends TestCase
{
    private function makeApp(): \flight\Engine
    {
        return new \flight\Engine();
    }

    private function makeConfig(): array
    {
        return [
            'default_authenticator' => 'session',
            'authenticators'        => [
                'session' => Session::class,
                'tokens'  => AccessTokens::class,
            ],
            'session'   => ['field' => 'user'],
            'passwords' => ['algorithm' => PASSWORD_BCRYPT, 'cost' => 4],
        ];
    }

    private function makeAuthentication(): Authentication
    {
        return new Authentication($this->makeApp(), $this->makeConfig());
    }

    // -----------------------------------------------------------------
    // factory() with null uses default_authenticator
    // -----------------------------------------------------------------

    #[Test]
    public function factoryWithNullReturnsDefaultAuthenticator(): void
    {
        $auth = $this->makeAuthentication();

        $authenticator = $auth->factory(null);

        $this->assertInstanceOf(AuthenticatorInterface::class, $authenticator);
        $this->assertInstanceOf(Session::class, $authenticator);
    }

    #[Test]
    public function factoryWithNoArgumentReturnsDefaultAuthenticator(): void
    {
        $auth = $this->makeAuthentication();

        $authenticator = $auth->factory();

        $this->assertInstanceOf(Session::class, $authenticator);
    }

    // -----------------------------------------------------------------
    // factory() with explicit aliases
    // -----------------------------------------------------------------

    #[Test]
    public function factoryWithSessionAliasReturnsSessionInstance(): void
    {
        $auth = $this->makeAuthentication();

        $authenticator = $auth->factory('session');

        $this->assertInstanceOf(Session::class, $authenticator);
    }

    #[Test]
    public function factoryWithTokensAliasReturnsAccessTokensInstance(): void
    {
        $auth = $this->makeAuthentication();

        $authenticator = $auth->factory('tokens');

        $this->assertInstanceOf(AccessTokens::class, $authenticator);
    }

    // -----------------------------------------------------------------
    // factory() with unknown alias throws
    // -----------------------------------------------------------------

    #[Test]
    public function factoryWithUnknownAliasThrowsAuthenticationException(): void
    {
        $auth = $this->makeAuthentication();

        $this->expectException(AuthenticationException::class);
        $auth->factory('unknown');
    }

    #[Test]
    public function factoryUnknownExceptionMessageContainsAlias(): void
    {
        $auth = $this->makeAuthentication();

        try {
            $auth->factory('nonexistent');
            $this->fail('Expected AuthenticationException was not thrown');
        } catch (AuthenticationException $e) {
            $this->assertStringContainsString('nonexistent', $e->getMessage());
        }
    }

    // -----------------------------------------------------------------
    // Caching — same alias returns same instance
    // -----------------------------------------------------------------

    #[Test]
    public function sameAliasReturnsCachedInstance(): void
    {
        $auth = $this->makeAuthentication();

        $first  = $auth->factory('session');
        $second = $auth->factory('session');

        $this->assertSame($first, $second);
    }

    #[Test]
    public function nullAliasReturnsCachedDefaultInstance(): void
    {
        $auth = $this->makeAuthentication();

        $first  = $auth->factory(null);
        $second = $auth->factory(null);

        $this->assertSame($first, $second);
    }

    #[Test]
    public function nullAliasAndExplicitDefaultAliasReturnSameInstance(): void
    {
        $auth = $this->makeAuthentication();

        // null resolves to 'session', so both calls must return the same object
        $viaNull    = $auth->factory(null);
        $viaExplicit = $auth->factory('session');

        $this->assertSame($viaNull, $viaExplicit);
    }

    // -----------------------------------------------------------------
    // Different aliases return different instances
    // -----------------------------------------------------------------

    #[Test]
    public function differentAliasesReturnDifferentInstances(): void
    {
        $auth = $this->makeAuthentication();

        $session = $auth->factory('session');
        $tokens  = $auth->factory('tokens');

        $this->assertNotSame($session, $tokens);
    }
}
