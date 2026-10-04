<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Integration\Middlewares;

use Enlivenapp\FlightShield\Auth;
use Enlivenapp\FlightShield\Middlewares\GroupMiddleware;
use Enlivenapp\FlightShield\Tests\TestHelper;
use PDO;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The group guard requires one of the configured groups.
 */
#[CoversClass(GroupMiddleware::class)]
class GroupMiddlewareTest extends TestCase
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
        $config['redirects']['group_denied'] = '/no-group';

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
    public function anonymousUserIsRedirectedToLogin(): void
    {
        (new GroupMiddleware($this->app, 'admin'))->before();

        $this->assertSame(['/auth/login'], $this->app->redirects);
        $this->assertTrue($this->app->haltCalled);
    }

    #[Test]
    public function userInTheGroupPasses(): void
    {
        $user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);
        $user->addGroup('admin');
        $this->auth->setAuthenticator('session')->login($user);

        (new GroupMiddleware($this->app, 'admin'))->before();

        $this->assertFalse($this->app->haltCalled);
        $this->assertSame([], $this->app->redirects);
    }

    #[Test]
    public function anyOfTheConfiguredGroupsIsEnough(): void
    {
        $user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);
        $user->addGroup('staff');
        $this->auth->setAuthenticator('session')->login($user);

        (new GroupMiddleware($this->app, 'admin', 'staff'))->before();

        $this->assertFalse($this->app->haltCalled);
    }

    #[Test]
    public function userOutsideTheGroupIsDenied(): void
    {
        $user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);
        $this->auth->setAuthenticator('session')->login($user);

        (new GroupMiddleware($this->app, 'admin'))->before();

        $this->assertSame(['/no-group'], $this->app->redirects);
        $this->assertTrue($this->app->haltCalled);
    }
}
