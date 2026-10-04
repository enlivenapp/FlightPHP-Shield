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
 * The register controller's payloads: the render data, the error list
 * shape, the old-email echo, and the field trimming.
 */
#[CoversClass(RegisterController::class)]
class RegisterControllerDetailTest extends TestCase
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

    /**
     * @return array<string, string>
     */
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
    public function showRegisterCarriesTheConfig(): void
    {
        $this->controller()->showRegister();

        $this->assertArrayHasKey('config', $this->app->rendered[0]['data']);
    }

    #[Test]
    public function showRegisterRendersTheRegisterTemplate(): void
    {
        $this->controller()->showRegister();

        $this->assertSame('register', $this->app->rendered[0]['template']);
    }

    #[Test]
    public function showRegisterRedirectsToRootWhenDisabled(): void
    {
        $config = $this->config;
        $config['allow_registration'] = false;
        $this->useConfig($config);

        $this->controller()->showRegister();

        $this->assertSame(['/'], $this->app->redirects);
    }

    #[Test]
    public function showRegisterUsesTheConfiguredAfterLoginRedirect(): void
    {
        $user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);
        $this->auth->setAuthenticator('session')->login($user);

        $config = $this->config;
        $config['redirects']['after_login'] = '/dashboard';
        $this->useConfig($config);

        $this->controller()->showRegister();

        $this->assertSame(['/dashboard'], $this->app->redirects);
    }

    #[Test]
    public function showRegisterFallsBackToTheRootRedirect(): void
    {
        $user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);
        $this->auth->setAuthenticator('session')->login($user);

        $config = $this->config;
        unset($config['redirects']['after_login']);
        $this->useConfig($config);

        $this->controller()->showRegister();

        $this->assertSame(['/'], $this->app->redirects);
    }

    #[Test]
    public function showRegisterAllowsRegistrationByDefault(): void
    {
        $config = $this->config;
        unset($config['allow_registration']);
        $this->useConfig($config);

        $this->controller()->showRegister();

        $this->assertSame([], $this->app->redirects);
        $this->assertSame('register', $this->app->rendered[0]['template']);
    }

    // -----------------------------------------------------------------
    // processRegister()
    // -----------------------------------------------------------------

    #[Test]
    public function processRegisterRendersTheSuccessTemplate(): void
    {
        $this->post($this->validFields());

        $this->controller()->processRegister();

        $this->assertSame('register_success', $this->app->rendered[0]['template']);
    }

    #[Test]
    public function processRegisterCarriesTheConfigOnSuccess(): void
    {
        $this->post($this->validFields());

        $this->controller()->processRegister();

        $this->assertArrayHasKey('config', $this->app->rendered[0]['data']);
    }

    #[Test]
    public function processRegisterRedirectsToRootWhenDisabled(): void
    {
        $config = $this->config;
        $config['allow_registration'] = false;
        $this->useConfig($config);

        $this->post($this->validFields());
        $this->controller()->processRegister();

        $this->assertSame(['/'], $this->app->redirects);
        $this->assertSame([], $this->app->rendered);
    }

    #[Test]
    public function processRegisterAllowsRegistrationByDefault(): void
    {
        $config = $this->config;
        unset($config['allow_registration']);
        $this->useConfig($config);

        $this->post($this->validFields());
        $this->controller()->processRegister();

        $this->assertSame('register_success', $this->app->rendered[0]['template']);
    }

    // -----------------------------------------------------------------
    // The error payload
    // -----------------------------------------------------------------

    #[Test]
    public function theErrorPayloadIsAList(): void
    {
        $fields = $this->validFields();
        $fields['password_confirm'] = 'SomethingElse1!';
        $this->post($fields);

        $this->controller()->processRegister();

        $errors = $this->app->rendered[0]['data']['errors'];
        $this->assertIsArray($errors);
        $this->assertSame(array_values($errors), $errors);
    }

    #[Test]
    public function theErrorPayloadEchoesTheEmail(): void
    {
        $fields = $this->validFields();
        $fields['password_confirm'] = 'SomethingElse1!';
        $this->post($fields);

        $this->controller()->processRegister();

        $this->assertSame('new@example.com', $this->app->rendered[0]['data']['old']['email']);
    }

    #[Test]
    public function theErrorPayloadCarriesTheConfig(): void
    {
        $fields = $this->validFields();
        $fields['password_confirm'] = 'SomethingElse1!';
        $this->post($fields);

        $this->controller()->processRegister();

        $this->assertArrayHasKey('config', $this->app->rendered[0]['data']);
    }

    #[Test]
    public function theErrorPayloadRendersTheRegisterTemplate(): void
    {
        $fields = $this->validFields();
        $fields['password_confirm'] = 'SomethingElse1!';
        $this->post($fields);

        $this->controller()->processRegister();

        $this->assertSame('register', $this->app->rendered[0]['template']);
    }

    #[Test]
    public function theEmailIsTrimmedBeforeRegistration(): void
    {
        $fields = $this->validFields();
        $fields['email'] = '  new@example.com  ';
        $this->post($fields);

        $this->controller()->processRegister();

        // The controller trims before calling register(), so the padded
        // value succeeds and the account is created.
        $this->assertSame('register_success', $this->app->rendered[0]['template']);
        $this->assertSame(
            1,
            (int) $this->pdo->query("SELECT COUNT(*) FROM auth_identities WHERE secret = 'new@example.com'")->fetchColumn()
        );
    }

    #[Test]
    public function aMissingEmailIsTreatedAsEmpty(): void
    {
        $this->post([
            'password'         => 'Str0ng!Passw0rd',
            'password_confirm' => 'Str0ng!Passw0rd',
        ]);

        $this->controller()->processRegister();

        $this->assertSame('', $this->app->rendered[0]['data']['old']['email']);
    }

    #[Test]
    public function aMissingPasswordIsTreatedAsEmpty(): void
    {
        $this->post(['email' => 'new@example.com']);

        $this->controller()->processRegister();

        $this->assertSame('register', $this->app->rendered[0]['template']);
        $this->assertNotEmpty($this->app->rendered[0]['data']['errors']);
    }

    #[Test]
    public function aMissingConfirmationIsTreatedAsEmpty(): void
    {
        $this->post([
            'email'    => 'new@example.com',
            'password' => 'Str0ng!Passw0rd',
        ]);

        $this->controller()->processRegister();

        $this->assertSame('register', $this->app->rendered[0]['template']);
        $this->assertNotEmpty($this->app->rendered[0]['data']['errors']);
    }
}
