<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Integration\Controllers;

use Enlivenapp\FlightShield\Auth;
use Enlivenapp\FlightShield\Controllers\RegisterController;
use Enlivenapp\FlightShield\Tests\TestHelper;
use PDO;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The register controller: the allow_registration gate, validation errors
 * and the success view.
 */
#[CoversClass(RegisterController::class)]
class RegisterControllerTest extends TestCase
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

        $now = (new \DateTimeImmutable())->format('Y-m-d H:i:s');
        $this->pdo->exec("INSERT INTO auth_groups (alias, title, created_at, updated_at) VALUES ('user', 'User', '{$now}', '{$now}')");

        $this->config = TestHelper::getConfig();
        $this->app = new ControllerSpyEngine();
        $this->app->set(self::CONFIG_KEY, $this->config);
        $this->auth = new Auth($this->app, $this->config);
        $this->app->authStub = $this->auth;
        $this->post([]);
    }

    protected function tearDown(): void
    {
        TestHelper::resetFlight();
        $_SESSION = [];
    }

    private function controller(): RegisterController
    {
        return new RegisterController($this->app, self::CONFIG_KEY);
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

    private function validFields(): array
    {
        return [
            'email'            => 'new@example.com',
            'password'         => 'Str0ng!Passw0rd',
            'password_confirm' => 'Str0ng!Passw0rd',
        ];
    }

    // -----------------------------------------------------------------
    // showRegister()
    // -----------------------------------------------------------------

    #[Test]
    public function showRegisterRendersTheForm(): void
    {
        $this->controller()->showRegister();

        $this->assertSame('register', $this->app->rendered[0]['template']);
    }

    #[Test]
    public function showRegisterRedirectsWhenRegistrationIsDisabled(): void
    {
        $config = $this->config;
        $config['allow_registration'] = false;
        $this->useConfig($config);

        $this->controller()->showRegister();

        $this->assertSame(['/'], $this->app->redirects);
    }

    #[Test]
    public function showRegisterRedirectsALoggedInUser(): void
    {
        $user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);
        $this->auth->setAuthenticator('session')->login($user);

        $this->controller()->showRegister();

        $this->assertSame(['/'], $this->app->redirects);
    }

    // -----------------------------------------------------------------
    // processRegister()
    // -----------------------------------------------------------------

    #[Test]
    public function processRegisterCreatesTheAccountAndShowsSuccess(): void
    {
        $this->post($this->validFields());

        $this->controller()->processRegister();

        $this->assertSame('register_success', $this->app->rendered[0]['template']);
        $this->assertSame(1, (int) $this->pdo->query('SELECT COUNT(*) FROM users')->fetchColumn());
    }

    #[Test]
    public function processRegisterRendersErrorsForAWeakPassword(): void
    {
        $this->post([
            'email'            => 'new@example.com',
            'password'         => 'short',
            'password_confirm' => 'short',
        ]);

        $this->controller()->processRegister();

        $this->assertSame('register', $this->app->rendered[0]['template']);
        $this->assertNotEmpty($this->app->rendered[0]['data']['errors']);
        $this->assertSame(0, (int) $this->pdo->query('SELECT COUNT(*) FROM users')->fetchColumn());
    }

    #[Test]
    public function processRegisterRedirectsWhenRegistrationIsDisabled(): void
    {
        $config = $this->config;
        $config['allow_registration'] = false;
        $this->useConfig($config);

        $this->post($this->validFields());

        $this->controller()->processRegister();

        $this->assertSame(['/'], $this->app->redirects);
        $this->assertSame(0, (int) $this->pdo->query('SELECT COUNT(*) FROM users')->fetchColumn());
    }
}
