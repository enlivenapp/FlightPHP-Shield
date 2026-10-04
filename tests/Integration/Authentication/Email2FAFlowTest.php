<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Integration\Authentication;

use Enlivenapp\FlightShield\Authentication\Actions\Email2FA;
use Enlivenapp\FlightShield\Authentication\Authenticators\Session;
use Enlivenapp\FlightShield\Models\User;
use Enlivenapp\FlightShield\Models\UserIdentity;
use Enlivenapp\FlightShield\Tests\TestHelper;
use flight\Engine;
use PDO;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

class Flow2FAView
{
    /** @var array<int, array{template: string, data: array<string, mixed>}> */
    public array $fetched = [];

    public function fetch(string $template, array $data = []): string
    {
        $this->fetched[] = ['template' => $template, 'data' => $data];

        return '';
    }
}

class Flow2FAAuthenticator
{
    public ?User $pendingUser = null;
    public ?User $currentUser = null;
    public bool $checkActionResult = true;

    public function getPendingUser(): ?User
    {
        return $this->pendingUser;
    }

    public function getUser(): ?User
    {
        return $this->currentUser ?? $this->pendingUser;
    }

    public function checkAction(?UserIdentity $identity, ?string $token): bool
    {
        return $this->checkActionResult;
    }
}

class Flow2FAAuth
{
    public function __construct(private Flow2FAAuthenticator $authenticator)
    {
    }

    public function getAuthenticator(): Flow2FAAuthenticator
    {
        return $this->authenticator;
    }

    public function user(): ?User
    {
        return $this->authenticator->getUser();
    }
}

class Flow2FASession
{
    private array $data = [];

    public function has(string $key): bool
    {
        return isset($this->data[$key]);
    }

    public function set(string $key, mixed $value): void
    {
        $this->data[$key] = $value;
    }

    public function get(string $key): mixed
    {
        return $this->data[$key] ?? null;
    }
}

class Flow2FAEngine extends Engine
{
    public ?Flow2FAAuth $authStub = null;
    public Flow2FAAuthenticator $authenticatorStub;
    public Flow2FASession $sessionStub;
    public Flow2FAView $viewSpy;
    public mixed $requestStub = null;

    /** @var string[] */
    public array $redirects = [];

    public bool $haltCalled = false;

    private array $store = [];

    public function __construct()
    {
        $this->authenticatorStub = new Flow2FAAuthenticator();
        $this->sessionStub = new Flow2FASession();
        $this->viewSpy = new Flow2FAView();
        $this->authStub = new Flow2FAAuth($this->authenticatorStub);
    }

    public function auth(): Flow2FAAuth
    {
        return $this->authStub;
    }

    public function session(): Flow2FASession
    {
        return $this->sessionStub;
    }

    public function view(): Flow2FAView
    {
        return $this->viewSpy;
    }

    public function request(): mixed
    {
        return $this->requestStub;
    }

    public function db(): mixed
    {
        return \Flight::db();
    }

    public function set($key, $value = null): void
    {
        $this->store[$key] = $value;
    }

    public function get(?string $key = null)
    {
        return $this->store[$key] ?? null;
    }

    public function redirect(string $url, int $code = 303): void
    {
        $this->redirects[] = $url;
    }

    public function halt(int $code = 200, string $message = '', bool $actuallyExit = true): void
    {
        $this->haltCalled = true;
    }
}

/**
 * The 2FA action's show() and verify() paths.
 */
#[CoversClass(Email2FA::class)]
class Email2FAFlowTest extends TestCase
{
    private const CONFIG_KEY = 'enlivenapp.flight-shield';

    protected PDO $pdo;
    protected Flow2FAEngine $app;
    protected User $user;
    protected array $config;

    /** @var array<int, array{to: string, subject: string, body: string}> */
    protected array $sent = [];

    protected function setUp(): void
    {
        $this->pdo = TestHelper::createDatabase();
        TestHelper::resetFlight();
        TestHelper::registerFlightDb($this->pdo);

        $_SESSION = [];
        $_SERVER['REMOTE_ADDR'] = '10.0.0.1';

        $this->sent = [];
        $this->config = TestHelper::getConfig();
        $this->config['email_sender'] = function (string $to, string $subject, string $body): void {
            $this->sent[] = ['to' => $to, 'subject' => $subject, 'body' => $body];
        };

        $this->app = new Flow2FAEngine();
        $this->app->set(self::CONFIG_KEY, $this->config);
        $this->app->requestStub = (object) ['data' => (object) [], 'query' => (object) []];

        $this->user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);
        $this->app->authenticatorStub->pendingUser = $this->user;
    }

    protected function tearDown(): void
    {
        TestHelper::resetFlight();
        $_SESSION = [];
        unset($_SERVER['REMOTE_ADDR'], $_SERVER['HTTP_USER_AGENT']);
    }

    private function seedCode(string $rawToken, string $expires = '+1 hour'): void
    {
        $now = new \DateTimeImmutable();

        $identity = new UserIdentity($this->pdo);
        $identity->user_id    = $this->user->id;
        $identity->type       = Session::ID_TYPE_EMAIL_2FA;
        $identity->name       = 'login';
        $identity->secret     = hash('sha256', $rawToken);
        $identity->expires    = $now->modify($expires)->format('Y-m-d H:i:s');
        $identity->created_at = $now->format('Y-m-d H:i:s');
        $identity->updated_at = $now->format('Y-m-d H:i:s');
        $identity->insert();
    }

    // -----------------------------------------------------------------
    // show()
    // -----------------------------------------------------------------

    #[Test]
    public function showSendsACodeAndRendersTheForm(): void
    {
        (new Email2FA())->show($this->app);

        $this->assertCount(1, $this->sent);
        $fetched = $this->app->viewSpy->fetched;
        $this->assertSame('2fa_verify', $fetched[count($fetched) - 1]['template']);
        $this->assertSame(
            1,
            (int) $this->pdo->query("SELECT COUNT(*) FROM auth_identities WHERE type = 'email_2fa'")->fetchColumn()
        );
    }

    #[Test]
    public function show404sForARobot(): void
    {
        $_SERVER['HTTP_USER_AGENT'] = 'Googlebot/2.1';

        (new Email2FA())->show($this->app);

        $this->assertTrue($this->app->haltCalled);
        $this->assertSame([], $this->sent);
    }

    #[Test]
    public function showThrowsWithoutAPendingUser(): void
    {
        $this->app->authenticatorStub->pendingUser = null;

        $this->expectException(\RuntimeException::class);

        (new Email2FA())->show($this->app);
    }

    // -----------------------------------------------------------------
    // verify()
    // -----------------------------------------------------------------

    #[Test]
    public function verifyRedirectsAfterACorrectCode(): void
    {
        $this->seedCode('123456');
        $this->app->requestStub = (object) ['data' => (object) ['token' => '123456'], 'query' => (object) []];

        (new Email2FA())->verify($this->app);

        $this->assertSame(['/'], $this->app->redirects);
    }

    #[Test]
    public function verifySendsAnAdminToTheAdminRedirect(): void
    {
        $admin = TestHelper::createUser($this->pdo, 'admin@example.com', 'Str0ng!Passw0rd', 'admin', true);
        $admin->addPermission('admin.access');
        $this->app->authenticatorStub->pendingUser = $admin;
        $this->user = $admin;

        $this->config['redirects']['after_login_admin'] = '/admin';
        $this->app->set(self::CONFIG_KEY, $this->config);

        $this->seedCode('123456');
        $this->app->requestStub = (object) ['data' => (object) ['token' => '123456'], 'query' => (object) []];

        (new Email2FA())->verify($this->app);

        $this->assertSame(['/admin'], $this->app->redirects);
    }

    #[Test]
    public function verifyRendersAnErrorForAWrongCode(): void
    {
        $this->seedCode('123456');
        $this->app->authenticatorStub->checkActionResult = false;
        $this->app->requestStub = (object) ['data' => (object) ['token' => '000000'], 'query' => (object) []];

        (new Email2FA())->verify($this->app);

        $this->assertSame('2fa_verify', $this->app->viewSpy->fetched[0]['template']);
        $this->assertSame('Invalid 2FA code.', $this->app->viewSpy->fetched[0]['data']['error']);
        $this->assertSame([], $this->app->redirects);
    }

    #[Test]
    public function verifyRendersAnErrorWhenNoCodeExists(): void
    {
        $this->app->requestStub = (object) ['data' => (object) ['token' => '123456'], 'query' => (object) []];

        (new Email2FA())->verify($this->app);

        $this->assertSame('No 2FA code found. Please log in again.', $this->app->viewSpy->fetched[0]['data']['error']);
    }

    #[Test]
    public function verifyRendersAnErrorForAnExpiredCode(): void
    {
        $this->seedCode('123456', '-1 hour');
        $this->app->requestStub = (object) ['data' => (object) ['token' => '123456'], 'query' => (object) []];

        (new Email2FA())->verify($this->app);

        $this->assertSame('The 2FA code has expired. Please log in again.', $this->app->viewSpy->fetched[0]['data']['error']);
    }

    #[Test]
    public function verify404sForARobot(): void
    {
        $_SERVER['HTTP_USER_AGENT'] = 'Googlebot/2.1';

        (new Email2FA())->verify($this->app);

        $this->assertTrue($this->app->haltCalled);
        $this->assertSame([], $this->app->redirects);
    }

    #[Test]
    public function getTypeIsTheTwoFactorType(): void
    {
        $this->assertSame(Session::ID_TYPE_EMAIL_2FA, (new Email2FA())->getType());
    }
}
