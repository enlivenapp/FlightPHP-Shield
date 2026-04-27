<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Unit;

use Enlivenapp\FlightShield\Auth;
use Enlivenapp\FlightShield\Authentication\AuthenticatorInterface;
use Enlivenapp\FlightShield\Authentication\Authenticators\AccessTokens;
use Enlivenapp\FlightShield\Authentication\Authenticators\Session;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(Auth::class)]
class AuthTest extends TestCase
{
    private function makeAuth(): Auth
    {
        $app = new \flight\Engine();
        $config = [
            'default_authenticator' => 'session',
            'authenticators' => [
                'session' => Session::class,
                'tokens'  => AccessTokens::class,
            ],
            'session'   => ['field' => 'user'],
            'passwords' => ['algorithm' => PASSWORD_BCRYPT, 'cost' => 4],
        ];

        return new Auth($app, $config);
    }

    #[Test]
    public function setAuthenticatorReturnsSelf(): void
    {
        $auth = $this->makeAuth();

        $this->assertSame($auth, $auth->setAuthenticator('session'));
    }

    #[Test]
    public function getAuthenticatorReturnsDefaultWhenNoneSet(): void
    {
        $auth = $this->makeAuth();

        $authenticator = $auth->getAuthenticator();

        $this->assertInstanceOf(AuthenticatorInterface::class, $authenticator);
        $this->assertInstanceOf(Session::class, $authenticator);
    }

    #[Test]
    public function setAuthenticatorTokensThenGetAuthenticatorReturnsAccessTokens(): void
    {
        $auth = $this->makeAuth();
        $auth->setAuthenticator('tokens');

        $authenticator = $auth->getAuthenticator();

        $this->assertInstanceOf(AccessTokens::class, $authenticator);
    }

    #[Test]
    public function userReturnsNullWhenNotLoggedIn(): void
    {
        $auth = $this->makeAuth();

        $this->assertNull($auth->user());
    }

    #[Test]
    public function idReturnsNullWhenNotLoggedIn(): void
    {
        $auth = $this->makeAuth();

        $this->assertNull($auth->id());
    }

    #[Test]
    public function loggedInReturnsFalseWhenNotLoggedIn(): void
    {
        $auth = $this->makeAuth();

        $this->assertFalse($auth->loggedIn());
    }

    #[Test]
    public function logoutDoesNotThrow(): void
    {
        $auth = $this->makeAuth();

        $auth->logout();

        // No exception means success
        $this->assertTrue(true);
    }

    #[Test]
    public function recordActiveDateDoesNotThrow(): void
    {
        $auth = $this->makeAuth();

        $auth->recordActiveDate();

        // No exception means success
        $this->assertTrue(true);
    }

    #[Test]
    public function setAuthenticatorNullUsesDefault(): void
    {
        $auth = $this->makeAuth();
        // First switch to tokens
        $auth->setAuthenticator('tokens');
        $this->assertInstanceOf(AccessTokens::class, $auth->getAuthenticator());

        // Now reset to null — should resolve to the default (session)
        $auth->setAuthenticator(null);

        $this->assertInstanceOf(Session::class, $auth->getAuthenticator());
    }
}
