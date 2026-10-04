<?php

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Integration\Authentication;

use Enlivenapp\FlightShield\Controllers\ActivationController;
use Enlivenapp\FlightShield\Models\Login;
use Enlivenapp\FlightShield\Tests\TestHelper;
use flight\Engine;
use PDO;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Spy engine: captures render() calls instead of emitting output, and lets
 * the test hand in a request and a db connection.
 */
class SpyActivationEngine extends Engine
{
    /** @var array<int, array{template: string, data: array<string, mixed>}> */
    public array $rendered = [];

    private array $store = [];
    private mixed $requestStub = null;

    public function set($key, $value = null): void
    {
        $this->store[$key] = $value;
    }

    public function get(?string $key = null)
    {
        return $this->store[$key] ?? null;
    }

    public function setRequestStub(mixed $request): void
    {
        $this->requestStub = $request;
    }

    public function request(): mixed
    {
        return $this->requestStub;
    }

    public function db(): mixed
    {
        return \Flight::db();
    }

    public function render(string $template, array $data = []): void
    {
        $this->rendered[] = ['template' => $template, 'data' => $data];
    }

    public function view(): SpyActivationView
    {
        return new SpyActivationView();
    }
}

class SpyActivationView
{
    public function fetch(string $template, array $data = []): string
    {
        return '';
    }
}

/**
 * The activation page: message plus resend form, mail only on submit, a
 * server-side cooldown, and one throttle row per submit.
 */
#[CoversClass(ActivationController::class)]
class ActivationPageTest extends TestCase
{
    private const CONFIG_KEY = 'enlivenapp.flight-shield';

    protected PDO $pdo;

    /** @var array<int, array{to: string, subject: string, body: string}> */
    protected array $sent = [];

    protected function setUp(): void
    {
        $this->pdo = TestHelper::createDatabase();
        TestHelper::resetFlight();
        TestHelper::registerFlightDb($this->pdo);

        $this->sent = [];
        $_SESSION = [];
        $_SERVER['REMOTE_ADDR'] = '10.0.0.1';
    }

    protected function tearDown(): void
    {
        TestHelper::resetFlight();
        $_SESSION = [];
        unset($_SERVER['REMOTE_ADDR'], $_SERVER['HTTP_USER_AGENT']);
    }

    private function makeEngine(?callable $sender = null, array $overrides = []): SpyActivationEngine
    {
        $config = array_merge(TestHelper::getConfig(), $overrides);
        $config['email_sender'] = $sender ?? function (string $to, string $subject, string $body): void {
            $this->sent[] = ['to' => $to, 'subject' => $subject, 'body' => $body];
        };

        $app = new SpyActivationEngine();
        $app->set(self::CONFIG_KEY, $config);

        return $app;
    }

    private function submit(SpyActivationEngine $app, string $email): ActivationController
    {
        $app->setRequestStub((object) [
            'data'  => (object) ['email' => $email],
            'query' => (object) ['email' => ''],
        ]);

        return new ActivationController($app, self::CONFIG_KEY);
    }

    private function resendRows(): int
    {
        return (int) $this->pdo
            ->query("SELECT COUNT(*) FROM auth_logins WHERE id_type = '" . Login::ID_TYPE_ACTIVATION_RESEND . "'")
            ->fetchColumn();
    }

    // -----------------------------------------------------------------
    // The page
    // -----------------------------------------------------------------

    #[Test]
    public function showRendersTheActivationPage(): void
    {
        $app = $this->makeEngine();
        $app->setRequestStub((object) [
            'data'  => (object) ['email' => ''],
            'query' => (object) ['email' => ''],
        ]);

        (new ActivationController($app, self::CONFIG_KEY))->show();

        $this->assertCount(1, $app->rendered);
        $this->assertSame('activate', $app->rendered[0]['template']);
        $this->assertArrayHasKey('message', $app->rendered[0]['data']);
        $this->assertSame([], $this->sent);
        $this->assertSame(0, $this->resendRows());
    }

    // -----------------------------------------------------------------
    // Resend
    // -----------------------------------------------------------------

    #[Test]
    public function resendSendsMailForAnInactiveAccount(): void
    {
        TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', false);

        $app = $this->makeEngine();
        $this->submit($app, 'user@example.com')->resend();

        $this->assertCount(1, $this->sent);
        $this->assertSame('user@example.com', $this->sent[0]['to']);
        $this->assertArrayHasKey('message', $app->rendered[0]['data']);
        $this->assertGreaterThan(0, $app->rendered[0]['data']['cooldown']);
    }

    #[Test]
    public function secondResendWithinTheCooldownSendsNothing(): void
    {
        TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', false);

        $app = $this->makeEngine();
        $controller = $this->submit($app, 'user@example.com');

        $controller->resend();
        $controller->resend();

        $this->assertCount(1, $this->sent);
        $this->assertArrayHasKey('error', $app->rendered[1]['data']);
        $this->assertStringContainsString('Please wait', $app->rendered[1]['data']['error']);
        $this->assertGreaterThan(0, $app->rendered[1]['data']['cooldown']);
    }

    #[Test]
    public function resendCooldownComesFromConfig(): void
    {
        TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', false);

        $app = $this->makeEngine(null, ['resend_cooldown' => 0]);
        $controller = $this->submit($app, 'user@example.com');

        $controller->resend();
        $controller->resend();

        $this->assertCount(2, $this->sent);
        $this->assertSame(0, $app->rendered[1]['data']['cooldown']);
    }

    #[Test]
    public function unknownActiveAndBannedAddressesGetTheSameMessageAndNoMail(): void
    {
        TestHelper::createUser($this->pdo, 'active@example.com', 'Str0ng!Passw0rd', 'active', true);
        $banned = TestHelper::createUser($this->pdo, 'banned@example.com', 'Str0ng!Passw0rd', 'banned', false);
        $this->pdo->exec("UPDATE users SET status = 'banned' WHERE id = {$banned->id}");

        foreach (['ghost@example.com', 'active@example.com', 'banned@example.com'] as $email) {
            $app = $this->makeEngine();
            $this->submit($app, $email)->resend();

            $this->assertSame([], $this->sent, "no mail for {$email}");
            $this->assertArrayHasKey('message', $app->rendered[0]['data'], "message for {$email}");
            $this->assertArrayNotHasKey('error', $app->rendered[0]['data'], "no error for {$email}");
        }
    }

    #[Test]
    public function emptyEmailAsksForOne(): void
    {
        $app = $this->makeEngine();
        $this->submit($app, '')->resend();

        $this->assertSame([], $this->sent);
        $this->assertSame('Enter your email address.', $app->rendered[0]['data']['error']);
    }

    #[Test]
    public function mailFailureIsReportedRatherThanClaimingSuccess(): void
    {
        TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', false);

        $app = $this->makeEngine(function (): void {
            throw new \RuntimeException('mail transport down');
        });
        $this->submit($app, 'user@example.com')->resend();

        $this->assertArrayHasKey('error', $app->rendered[0]['data']);
        $this->assertStringContainsString('could not send', $app->rendered[0]['data']['error']);
    }

    // -----------------------------------------------------------------
    // Throttle counter
    // -----------------------------------------------------------------

    #[Test]
    public function everySubmitIsCountedIncludingBadAddresses(): void
    {
        $app = $this->makeEngine();

        $this->submit($app, 'ghost@example.com')->resend();
        $this->submit($app, 'another@ghost.example')->resend();
        $this->submit($app, '')->resend();

        $this->assertSame(3, $this->resendRows());
    }

    #[Test]
    public function throttleCounterIgnoresRecordLoginAttemptSetting(): void
    {
        $app = $this->makeEngine(null, ['record_login_attempt' => 'none']);
        $this->submit($app, 'ghost@example.com')->resend();

        $this->assertSame(1, $this->resendRows());
        $this->assertSame([], $this->sent);
    }
}
