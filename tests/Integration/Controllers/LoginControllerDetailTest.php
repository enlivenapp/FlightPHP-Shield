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
 * The login controller's remaining branches: the username field swap, the
 * remember-me cookie, the pending 2FA redirect, and the redirect defaults.
 */
#[CoversClass(LoginController::class)]
class LoginControllerDetailTest extends TestCase
{
    private const CONFIG_KEY = 'enlivenapp.flight-shield';

    protected PDO $pdo;
    protected ControllerSpyEngine $app;
    protected Auth $auth;

    /** @var array<string, mixed> */
    protected array $config;

    protected function setUp(): void
    {
        $this->pdo = TestHelper::createDatabase();
        TestHelper::resetFlight();
        TestHelper::registerFlightDb($this->pdo);

        $_SESSION = [];
        unset($_COOKIE['remember']);

        $now = (new \DateTimeImmutable())->format('Y-m-d H:i:s');
        $this->pdo->exec("INSERT INTO auth_groups (alias, title, created_at, updated_at) VALUES ('user', 'User', '{$now}', '{$now}')");

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
        unset($_COOKIE['remember']);
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

    /**
     * @param array<string, mixed> $config
     */
    private function useConfig(array $config): void
    {
        $this->config = $config;
        $this->app->set(self::CONFIG_KEY, $config);
        $this->auth = new Auth($this->app, $config);
        $this->app->authStub = $this->auth;
    }

    private function makeUser(string $email = 'user@example.com', string $username = 'user'): \Enlivenapp\FlightShield\Models\User
    {
        return TestHelper::createUser($this->pdo, $email, 'Str0ng!Passw0rd', $username, true);
    }

    // -----------------------------------------------------------------
    // showLogin()
    // -----------------------------------------------------------------

    #[Test]
    public function showLoginCarriesTheConfig(): void
    {
        $this->controller()->showLogin();

        $this->assertArrayHasKey('config', $this->app->rendered[0]['data']);
    }

    #[Test]
    public function showLoginRendersTheLoginTemplate(): void
    {
        $this->controller()->showLogin();

        $this->assertSame('login', $this->app->rendered[0]['template']);
    }

    #[Test]
    public function showLoginFallsBackToTheRootRedirect(): void
    {
        $user = $this->makeUser();
        $this->auth->setAuthenticator('session')->login($user);

        $config = $this->config;
        unset($config['redirects']['after_login']);
        $this->useConfig($config);

        $this->controller()->showLogin();

        $this->assertSame(['/'], $this->app->redirects);
    }

    #[Test]
    public function showLoginIgnoresTheAdminRedirectForANonAdmin(): void
    {
        $user = $this->makeUser();
        $this->auth->setAuthenticator('session')->login($user);

        $config = $this->config;
        $config['redirects']['after_login_admin'] = '/admin';
        $this->useConfig($config);

        $this->controller()->showLogin();

        $this->assertSame(['/'], $this->app->redirects);
    }

    #[Test]
    public function showLoginIgnoresTheAdminRedirectWhenNotConfigured(): void
    {
        $admin = $this->makeUser('admin@example.com', 'admin');
        $admin->addPermission('admin.access');
        $this->auth->setAuthenticator('session')->login($admin);

        $config = $this->config;
        unset($config['redirects']['after_login_admin']);
        $this->useConfig($config);

        $this->controller()->showLogin();

        $this->assertSame(['/'], $this->app->redirects);
    }

    // -----------------------------------------------------------------
    // processLogin(): the username swap
    // -----------------------------------------------------------------

    #[Test]
    public function processLoginUsesTheUsernameWhenConfigured(): void
    {
        $this->makeUser('user@example.com', 'bob');

        $config = $this->config;
        $config['valid_login_fields'] = ['email', 'username'];
        $this->useConfig($config);

        $this->post(['username' => 'bob', 'password' => 'Str0ng!Passw0rd']);
        $this->controller()->processLogin();

        $this->assertSame(['/'], $this->app->redirects);
    }

    #[Test]
    public function processLoginIgnoresTheUsernameWhenNotConfigured(): void
    {
        $this->makeUser('user@example.com', 'bob');

        $config = $this->config;
        $config['valid_login_fields'] = ['email'];
        $this->useConfig($config);

        $this->post(['username' => 'bob', 'password' => 'Str0ng!Passw0rd']);
        $this->controller()->processLogin();

        $this->assertSame('login', $this->app->rendered[0]['template']);
    }

    #[Test]
    public function processLoginFallsBackToTheEmailField(): void
    {
        $this->makeUser('user@example.com', 'bob');

        $config = $this->config;
        unset($config['valid_login_fields']);
        $this->useConfig($config);

        $this->post(['email' => 'user@example.com', 'password' => 'Str0ng!Passw0rd']);
        $this->controller()->processLogin();

        $this->assertSame(['/'], $this->app->redirects);
    }

    #[Test]
    public function processLoginKeepsTheEmailWhenTheUsernameIsEmpty(): void
    {
        $this->makeUser('user@example.com', 'bob');

        $config = $this->config;
        $config['valid_login_fields'] = ['email', 'username'];
        $this->useConfig($config);

        $this->post(['email' => 'user@example.com', 'username' => '', 'password' => 'Str0ng!Passw0rd']);
        $this->controller()->processLogin();

        $this->assertSame(['/'], $this->app->redirects);
    }

    // -----------------------------------------------------------------
    // processLogin(): the error payload
    // -----------------------------------------------------------------

    #[Test]
    public function theErrorPayloadCarriesTheReason(): void
    {
        $this->makeUser();

        $this->post(['email' => 'user@example.com', 'password' => 'wrong-password']);
        $this->controller()->processLogin();

        $this->assertSame('Invalid credentials.', $this->app->rendered[0]['data']['error']);
    }

    #[Test]
    public function theErrorPayloadCarriesTheConfig(): void
    {
        $this->makeUser();

        $this->post(['email' => 'user@example.com', 'password' => 'wrong-password']);
        $this->controller()->processLogin();

        $this->assertArrayHasKey('config', $this->app->rendered[0]['data']);
    }

    #[Test]
    public function aMissingEmailIsTreatedAsEmpty(): void
    {
        $this->post(['password' => 'Str0ng!Passw0rd']);
        $this->controller()->processLogin();

        $this->assertSame('login', $this->app->rendered[0]['template']);
    }

    #[Test]
    public function aMissingPasswordIsTreatedAsEmpty(): void
    {
        $this->post(['email' => 'user@example.com']);
        $this->controller()->processLogin();

        $this->assertSame('login', $this->app->rendered[0]['template']);
    }

    // -----------------------------------------------------------------
    // processLogin(): the activation forward
    // -----------------------------------------------------------------

    #[Test]
    public function anUnactivatedAccountUsesTheConfiguredActivateRedirect(): void
    {
        TestHelper::createUser($this->pdo, 'pending@example.com', 'Str0ng!Passw0rd', 'pending', false);

        $config = $this->config;
        $config['redirects']['activate'] = '/custom/activate';
        $this->useConfig($config);

        $this->post(['email' => 'pending@example.com', 'password' => 'Str0ng!Passw0rd']);
        $this->controller()->processLogin();

        $this->assertSame(['/custom/activate'], $this->app->redirects);
    }

    #[Test]
    public function anUnactivatedAccountFallsBackToTheDefaultActivateRedirect(): void
    {
        TestHelper::createUser($this->pdo, 'pending@example.com', 'Str0ng!Passw0rd', 'pending', false);

        $config = $this->config;
        unset($config['redirects']['activate']);
        $this->useConfig($config);

        $this->post(['email' => 'pending@example.com', 'password' => 'Str0ng!Passw0rd']);
        $this->controller()->processLogin();

        $this->assertSame(['/auth/activate'], $this->app->redirects);
    }

    // -----------------------------------------------------------------
    // processLogin(): the redirect defaults
    // -----------------------------------------------------------------

    #[Test]
    public function aSuccessfulLoginFallsBackToTheRootRedirect(): void
    {
        $this->makeUser();

        $config = $this->config;
        unset($config['redirects']['after_login']);
        $this->useConfig($config);

        $this->post(['email' => 'user@example.com', 'password' => 'Str0ng!Passw0rd']);
        $this->controller()->processLogin();

        $this->assertSame(['/'], $this->app->redirects);
    }

    #[Test]
    public function aSuccessfulLoginIgnoresTheAdminRedirectForANonAdmin(): void
    {
        $this->makeUser();

        $config = $this->config;
        $config['redirects']['after_login_admin'] = '/admin';
        $this->useConfig($config);

        $this->post(['email' => 'user@example.com', 'password' => 'Str0ng!Passw0rd']);
        $this->controller()->processLogin();

        $this->assertSame(['/'], $this->app->redirects);
    }

    #[Test]
    public function aSuccessfulLoginIgnoresTheAdminRedirectWhenNotConfigured(): void
    {
        $admin = $this->makeUser('admin@example.com', 'admin');
        $admin->addPermission('admin.access');

        $config = $this->config;
        unset($config['redirects']['after_login_admin']);
        $this->useConfig($config);

        $this->post(['email' => 'admin@example.com', 'password' => 'Str0ng!Passw0rd']);
        $this->controller()->processLogin();

        $this->assertSame(['/'], $this->app->redirects);
    }

    // -----------------------------------------------------------------
    // processLogin(): remember me
    // -----------------------------------------------------------------

    #[Test]
    public function rememberMeIssuesATokenWhenRequested(): void
    {
        $this->makeUser();

        $this->post(['email' => 'user@example.com', 'password' => 'Str0ng!Passw0rd', 'remember' => '1']);
        $this->controller()->processLogin();

        $this->assertSame(
            1,
            (int) $this->pdo->query('SELECT COUNT(*) FROM auth_remember_tokens')->fetchColumn()
        );
    }

    #[Test]
    public function rememberMeIsSkippedWhenNotRequested(): void
    {
        $this->makeUser();

        $this->post(['email' => 'user@example.com', 'password' => 'Str0ng!Passw0rd']);
        $this->controller()->processLogin();

        $this->assertSame(
            0,
            (int) $this->pdo->query('SELECT COUNT(*) FROM auth_remember_tokens')->fetchColumn()
        );
    }

    #[Test]
    public function anEmptyRememberValueIsSkipped(): void
    {
        $this->makeUser();

        $this->post(['email' => 'user@example.com', 'password' => 'Str0ng!Passw0rd', 'remember' => '']);
        $this->controller()->processLogin();

        $this->assertSame(
            0,
            (int) $this->pdo->query('SELECT COUNT(*) FROM auth_remember_tokens')->fetchColumn()
        );
    }

    // -----------------------------------------------------------------
    // logout()
    // -----------------------------------------------------------------

    #[Test]
    public function logoutUsesTheConfiguredRedirect(): void
    {
        $config = $this->config;
        $config['redirects']['after_logout'] = '/goodbye';
        $this->useConfig($config);

        $this->controller()->logout();

        $this->assertSame(['/goodbye'], $this->app->redirects);
    }

    #[Test]
    public function logoutFallsBackToTheRootRedirect(): void
    {
        $config = $this->config;
        unset($config['redirects']['after_logout']);
        $this->useConfig($config);

        $this->controller()->logout();

        $this->assertSame(['/'], $this->app->redirects);
    }

    #[Test]
    public function logoutClearsTheSession(): void
    {
        $user = $this->makeUser();
        $this->auth->setAuthenticator('session')->login($user);

        $this->controller()->logout();

        $this->assertFalse($this->auth->setAuthenticator('session')->loggedIn());
    }
}
