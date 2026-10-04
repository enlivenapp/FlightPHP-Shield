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
use Enlivenapp\FlightShield\Tests\TestHelper;
use flight\Engine;
use PDO;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Spy view: records fetch() calls instead of rendering.
 */
class Spy2FAView
{
    /** @var array<int, array{template: string, data: array<string, mixed>}> */
    public array $fetched = [];

    public function fetch(string $template, array $data = []): string
    {
        $this->fetched[] = ['template' => $template, 'data' => $data];

        return '';
    }
}

/**
 * Email2FA only needs getPendingUser() from the authenticator.
 */
class Spy2FAAuthenticator
{
    public function __construct(private User $user)
    {
    }

    public function getPendingUser(): User
    {
        return $this->user;
    }
}

class Spy2FAAuth
{
    public function __construct(private Spy2FAAuthenticator $authenticator)
    {
    }

    public function getAuthenticator(): Spy2FAAuthenticator
    {
        return $this->authenticator;
    }
}

/**
 * Spy engine: captures view() calls, hands in a pending user and the db.
 */
class Spy2FAEngine extends Engine
{
    private array $store = [];
    public Spy2FAView $viewSpy;
    public ?Spy2FAAuth $authStub = null;

    public function __construct()
    {
        $this->viewSpy = new Spy2FAView();
    }

    public function set($key, $value = null): void
    {
        $this->store[$key] = $value;
    }

    public function get(?string $key = null)
    {
        return $this->store[$key] ?? null;
    }

    public function db(): mixed
    {
        return \Flight::db();
    }

    public function view(): Spy2FAView
    {
        return $this->viewSpy;
    }

    public function auth(): Spy2FAAuth
    {
        return $this->authStub;
    }
}

/**
 * The 2FA resend endpoint: mail only when the server-side cooldown has
 * elapsed, and the cooldown length comes from config.
 */
#[CoversClass(Email2FA::class)]
class Email2FAResendTest extends TestCase
{
    private const CONFIG_KEY = 'enlivenapp.flight-shield';

    protected PDO $pdo;
    protected Spy2FAEngine $app;
    protected User $user;

    /** @var array<int, array{to: string, subject: string, body: string}> */
    protected array $sent = [];

    protected function setUp(): void
    {
        $this->pdo = TestHelper::createDatabase();
        TestHelper::resetFlight();
        TestHelper::registerFlightDb($this->pdo);

        $_SESSION = [];
        $_SERVER['REMOTE_ADDR'] = '10.0.0.1';

        $this->user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);

        $this->sent = [];
        $this->app = $this->makeEngine();
    }

    protected function tearDown(): void
    {
        TestHelper::resetFlight();
        $_SESSION = [];
        unset($_SERVER['REMOTE_ADDR'], $_SERVER['HTTP_USER_AGENT']);
    }

    private function makeEngine(array $overrides = []): Spy2FAEngine
    {
        $config = array_merge(TestHelper::getConfig(), $overrides);
        $config['email_sender'] = function (string $to, string $subject, string $body): void {
            $this->sent[] = ['to' => $to, 'subject' => $subject, 'body' => $body];
        };

        $app = new Spy2FAEngine();
        $app->set(self::CONFIG_KEY, $config);
        $app->authStub = new Spy2FAAuth(new Spy2FAAuthenticator($this->user));

        return $app;
    }

    /**
     * Seed an email_2fa identity created $ageSeconds ago.
     */
    private function seedCode(int $ageSeconds): void
    {
        $createdAt = (new \DateTimeImmutable())->modify("-{$ageSeconds} seconds")->format('Y-m-d H:i:s');

        $stmt = $this->pdo->prepare(
            'INSERT INTO auth_identities (user_id, type, name, secret, secret2, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)'
        );
        $stmt->execute([
            $this->user->id,
            Session::ID_TYPE_EMAIL_2FA,
            'login',
            '123456',
            password_hash('123456', PASSWORD_BCRYPT, ['cost' => 4]),
            $createdAt,
            $createdAt,
        ]);
    }

    /**
     * Data from the last 2fa_verify render (the email template renders too).
     */
    private function lastVerifyRender(Spy2FAEngine $app): array
    {
        $verify = array_values(array_filter(
            $app->viewSpy->fetched,
            static fn (array $fetch): bool => $fetch['template'] === '2fa_verify'
        ));

        return $verify[count($verify) - 1]['data'];
    }

    #[Test]
    public function resendInsideTheCooldownSendsNothing(): void
    {
        $this->seedCode(10);

        (new Email2FA())->handle($this->app);

        $this->assertSame([], $this->sent);
        $data = $this->lastVerifyRender($this->app);
        $this->assertArrayHasKey('error', $data);
        $this->assertStringContainsString('Please wait', $data['error']);
    }

    #[Test]
    public function resendAfterTheCooldownSendsANewCode(): void
    {
        $this->seedCode(400);

        (new Email2FA())->handle($this->app);

        $this->assertCount(1, $this->sent);
        $this->assertSame('user@example.com', $this->sent[0]['to']);
        $this->assertArrayHasKey('message', $this->lastVerifyRender($this->app));
    }

    #[Test]
    public function cooldownComesFromConfig(): void
    {
        $this->seedCode(10);

        $app = $this->makeEngine(['resend_cooldown' => 0]);
        (new Email2FA())->handle($app);

        $this->assertCount(1, $this->sent);
        $this->assertArrayHasKey('message', $this->lastVerifyRender($app));
    }
}
