<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Integration\Middlewares;

use Enlivenapp\FlightShield\Auth;
use Enlivenapp\FlightShield\Middlewares\ChainAuthMiddleware;
use Enlivenapp\FlightShield\Tests\TestHelper;
use PDO;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The chain guard tries each authenticator, then falls back to a redirect or
 * a 401 depending on what the client accepts.
 */
#[CoversClass(ChainAuthMiddleware::class)]
class ChainAuthMiddlewareTest extends TestCase
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
        unset($_SERVER['HTTP_ACCEPT']);
    }

    #[Test]
    public function loggedInChainPassesThrough(): void
    {
        $user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);
        $this->auth->setAuthenticator('session')->login($user);

        (new ChainAuthMiddleware($this->app))->before();

        $this->assertFalse($this->app->haltCalled);
        $this->assertSame([], $this->app->redirects);
        $this->assertSame([], $this->app->jsonCalls);
    }

    #[Test]
    public function allAuthenticatorsFailingRedirectsToLogin(): void
    {
        (new ChainAuthMiddleware($this->app))->before();

        $this->assertSame(['/auth/login'], $this->app->redirects);
        $this->assertTrue($this->app->haltCalled);
    }

    #[Test]
    public function jsonClientGetsA401Instead(): void
    {
        $_SERVER['HTTP_ACCEPT'] = 'application/json';

        (new ChainAuthMiddleware($this->app))->before();

        $this->assertCount(1, $this->app->jsonCalls);
        $this->assertSame(401, $this->app->jsonCalls[0]['code']);
        $this->assertSame([], $this->app->redirects);
    }
}
