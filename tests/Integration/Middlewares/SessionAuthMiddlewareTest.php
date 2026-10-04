<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Integration\Middlewares;

use Enlivenapp\FlightShield\Auth;
use Enlivenapp\FlightShield\Authentication\Actions\Email2FA;
use Enlivenapp\FlightShield\Middlewares\SessionAuthMiddleware;
use Enlivenapp\FlightShield\Models\User;
use Enlivenapp\FlightShield\Tests\TestHelper;
use PDO;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The session guard: anonymous users go to login, pending users go to their
 * action page, and banned or inactive users get logged out.
 */
#[CoversClass(SessionAuthMiddleware::class)]
class SessionAuthMiddlewareTest extends TestCase
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
        $config['actions']['login'] = Email2FA::class;

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

    private function makeUser(bool $active = true): User
    {
        return TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', $active);
    }

    #[Test]
    public function anonymousUserIsRedirectedToLogin(): void
    {
        (new SessionAuthMiddleware($this->app))->before();

        $this->assertTrue($this->app->haltCalled);
        $this->assertSame(303, $this->app->haltCode);
        $this->assertSame(['/auth/login'], $this->app->redirects);
    }

    #[Test]
    public function pendingTwoFactorUserIsSentToTheActionPage(): void
    {
        $user = $this->makeUser();
        $this->auth->setAuthenticator('session')->getAuthenticator()->startAction(Email2FA::class, $user);

        (new SessionAuthMiddleware($this->app))->before();

        $this->assertSame(['/auth/2fa'], $this->app->redirects);
        $this->assertTrue($this->app->haltCalled);
    }

    #[Test]
    public function pendingUserWithAnotherActionGoesToLogin(): void
    {
        // No login action configured, so getAction() resolves to null and the
        // pending branch falls back to the login redirect.
        $config = TestHelper::getConfig();
        $this->app->set(self::CONFIG_KEY, $config);
        $auth = new Auth($this->app, $config);
        $this->app->authStub = $auth;

        $user = $this->makeUser();
        $auth->setAuthenticator('session')->getAuthenticator()->startAction(Email2FA::class, $user);

        (new SessionAuthMiddleware($this->app))->before();

        $this->assertSame(['/auth/login'], $this->app->redirects);
        $this->assertTrue($this->app->haltCalled);
    }

    #[Test]
    public function bannedUserIsLoggedOut(): void
    {
        $user = $this->makeUser();
        $user->status = 'banned';
        $this->auth->setAuthenticator('session')->login($user);

        (new SessionAuthMiddleware($this->app))->before();

        $this->assertSame(['/auth/login'], $this->app->redirects);
        $this->assertTrue($this->app->haltCalled);
        $this->assertFalse($this->auth->setAuthenticator('session')->loggedIn());
    }

    #[Test]
    public function inactiveUserIsLoggedOut(): void
    {
        $user = $this->makeUser(false);
        $this->auth->setAuthenticator('session')->login($user);

        (new SessionAuthMiddleware($this->app))->before();

        $this->assertSame(['/auth/login'], $this->app->redirects);
        $this->assertTrue($this->app->haltCalled);
    }

    #[Test]
    public function activeUserPassesThroughAndRecordsActiveDate(): void
    {
        $user = $this->makeUser();
        $this->auth->setAuthenticator('session')->login($user);

        (new SessionAuthMiddleware($this->app))->before();

        $this->assertFalse($this->app->haltCalled);
        $this->assertSame([], $this->app->redirects);

        $stored = $this->pdo->query("SELECT last_active FROM users WHERE id = {$user->id}")->fetchColumn();
        $this->assertNotNull($stored);
    }
}
