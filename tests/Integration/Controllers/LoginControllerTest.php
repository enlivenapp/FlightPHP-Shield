<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Integration\Controllers;

use Enlivenapp\FlightShield\Auth;
use Enlivenapp\FlightShield\Controllers\LoginController;
use Enlivenapp\FlightShield\Tests\TestHelper;
use PDO;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The login controller: form, credential handling, activation forward and
 * the protected redirects.
 */
#[CoversClass(LoginController::class)]
class LoginControllerTest extends TestCase
{
    private const CONFIG_KEY = 'enlivenapp.flight-shield';

    protected PDO $pdo;
    protected ControllerSpyEngine $app;
    protected Auth $auth;
    protected array $config;

    protected function setUp(): void
    {
        $this->pdo = TestHelper::createDatabase();
        TestHelper::resetFlight();
        TestHelper::registerFlightDb($this->pdo);

        $_SESSION = [];

        $this->config = TestHelper::getConfig();
        $this->app = new ControllerSpyEngine();
        $this->app->set(self::CONFIG_KEY, $this->config);
        $this->auth = new Auth($this->app, $this->config);
        $this->app->authStub = $this->auth;
        $this->post(['email' => '', 'password' => '']);
    }

    protected function tearDown(): void
    {
        TestHelper::resetFlight();
        $_SESSION = [];
    }

    private function controller(): LoginController
    {
        return new LoginController($this->app, self::CONFIG_KEY);
    }

    /**
     * @param array<string, mixed> $data
     */
    private function post(array $data): void
    {
        $this->app->requestStub = (object) ['data' => (object) $data];
    }

    private function useConfig(array $config): void
    {
        $this->config = $config;
        $this->app->set(self::CONFIG_KEY, $config);
        $this->auth = new Auth($this->app, $config);
        $this->app->authStub = $this->auth;
    }

    // -----------------------------------------------------------------
    // showLogin()
    // -----------------------------------------------------------------

    #[Test]
    public function showLoginRendersTheFormForAnonymousUsers(): void
    {
        $this->controller()->showLogin();

        $this->assertSame('login', $this->app->rendered[0]['template']);
        $this->assertSame([], $this->app->redirects);
    }

    #[Test]
    public function showLoginRedirectsALoggedInUserToTheDefaultTarget(): void
    {
        $user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);
        $this->auth->setAuthenticator('session')->login($user);

        $this->controller()->showLogin();

        $this->assertSame(['/'], $this->app->redirects);
    }

    #[Test]
    public function showLoginSendsAnAdminToTheAdminTarget(): void
    {
        $config = $this->config;
        $config['redirects']['after_login_admin'] = '/admin';
        $this->useConfig($config);

        $user = TestHelper::createUser($this->pdo, 'admin@example.com', 'Str0ng!Passw0rd', 'admin', true);
        $user->addPermission('admin.access');
        $this->auth->setAuthenticator('session')->login($user);

        $this->controller()->showLogin();

        $this->assertSame(['/admin'], $this->app->redirects);
    }

    // -----------------------------------------------------------------
    // processLogin()
    // -----------------------------------------------------------------

    #[Test]
    public function processLoginRendersAnErrorForBadCredentials(): void
    {
        TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);
        $this->post(['email' => 'user@example.com', 'password' => 'wrong']);

        $this->controller()->processLogin();

        $this->assertSame('login', $this->app->rendered[0]['template']);
        $this->assertArrayHasKey('error', $this->app->rendered[0]['data']);
        $this->assertSame([], $this->app->redirects);
    }

    #[Test]
    public function processLoginRedirectsOnSuccess(): void
    {
        TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);
        $this->post(['email' => 'user@example.com', 'password' => 'Str0ng!Passw0rd']);

        $this->controller()->processLogin();

        $this->assertSame(['/'], $this->app->redirects);
    }

    #[Test]
    public function processLoginSendsAnAdminToTheAdminTarget(): void
    {
        $config = $this->config;
        $config['redirects']['after_login_admin'] = '/admin';
        $this->useConfig($config);

        $user = TestHelper::createUser($this->pdo, 'admin@example.com', 'Str0ng!Passw0rd', 'admin', true);
        $user->addPermission('admin.access');
        $this->post(['email' => 'admin@example.com', 'password' => 'Str0ng!Passw0rd']);

        $this->controller()->processLogin();

        $this->assertSame(['/admin'], $this->app->redirects);
    }

    #[Test]
    public function processLoginForwardsAnUnactivatedAccountToActivation(): void
    {
        TestHelper::createUser($this->pdo, 'pending@example.com', 'Str0ng!Passw0rd', 'pending', false);
        $this->post(['email' => 'pending@example.com', 'password' => 'Str0ng!Passw0rd']);

        $this->controller()->processLogin();

        $this->assertSame(['/auth/activate'], $this->app->redirects);
        $this->assertSame([], $this->app->rendered);
    }

    #[Test]
    public function processLoginAcceptsAUsernameWhenConfigured(): void
    {
        $config = $this->config;
        $config['valid_login_fields'] = ['username'];
        $this->useConfig($config);

        TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'bob', true);
        $this->post(['username' => 'bob', 'password' => 'Str0ng!Passw0rd']);

        $this->controller()->processLogin();

        $this->assertSame(['/'], $this->app->redirects);
    }

    // -----------------------------------------------------------------
    // logout()
    // -----------------------------------------------------------------

    #[Test]
    public function logoutClearsTheSessionAndRedirects(): void
    {
        $user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);
        $this->auth->setAuthenticator('session')->login($user);

        $this->controller()->logout();

        $this->assertSame(['/auth/login'], $this->app->redirects);
        $this->assertFalse($this->auth->setAuthenticator('session')->loggedIn());
    }
}
