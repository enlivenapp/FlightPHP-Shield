<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Integration\Middlewares;

use Enlivenapp\FlightShield\Auth;
use Enlivenapp\FlightShield\Middlewares\ForcePasswordResetMiddleware;
use Enlivenapp\FlightShield\Tests\TestHelper;
use PDO;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Users flagged for a password reset are pushed to the reset page.
 */
#[CoversClass(ForcePasswordResetMiddleware::class)]
class ForcePasswordResetMiddlewareTest extends TestCase
{
    private const CONFIG_KEY = 'enlivenapp.flight-shield';

    protected PDO $pdo;
    protected AuthSpyEngine $app;
    protected Auth $auth;

    protected function setUp(): void
    {
        $this->pdo = TestHelper::createDatabase();
        TestHelper::resetFlight();
        TestHelper::registerFlightDb($this->pdo);

        $_SESSION = [];

        $config = TestHelper::getConfig();
        $this->app = new AuthSpyEngine();
        $this->app->set(self::CONFIG_KEY, $config);
        $this->auth = new Auth($this->app, $config);
        $this->app->authStub = $this->auth;
    }

    protected function tearDown(): void
    {
        TestHelper::resetFlight();
        $_SESSION = [];
    }

    #[Test]
    public function anonymousUserPassesThrough(): void
    {
        (new ForcePasswordResetMiddleware($this->app))->before();

        $this->assertSame([], $this->app->redirects);
        $this->assertFalse($this->app->haltCalled);
    }

    #[Test]
    public function userWithoutTheFlagPassesThrough(): void
    {
        $user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);
        $this->auth->setAuthenticator('session')->login($user);

        (new ForcePasswordResetMiddleware($this->app))->before();

        $this->assertSame([], $this->app->redirects);
    }

    #[Test]
    public function flaggedUserIsSentToTheResetPage(): void
    {
        $user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);
        $this->pdo->exec("UPDATE auth_identities SET force_reset = 1 WHERE user_id = {$user->id}");
        $this->auth->setAuthenticator('session')->login($user);

        (new ForcePasswordResetMiddleware($this->app))->before();

        $this->assertSame(['/auth/reset-password'], $this->app->redirects);
    }
}
