<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

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

class DetailActivationEngine extends Engine
{
    /** @var array<int, array{template: string, data: array<string, mixed>}> */
    public array $rendered = [];

    public mixed $requestStub = null;

    private array $store = [];

    public function set($key, $value = null): void
    {
        $this->store[$key] = $value;
    }

    public function get(?string $key = null)
    {
        return $this->store[$key] ?? null;
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

    /**
     * Stub view so EmailActivator::begin() can fetch its email template
     * without hitting the real Flight view loader.
     */
    public function view(): object
    {
        return new class {
            public function fetch(string $template, array $data = []): string
            {
                return '';
            }
        };
    }
}

/**
 * The activation page's render payloads: the defaults, the old-email
 * echo, the cooldown value, and the throttle identifier.
 */
#[CoversClass(ActivationController::class)]
class ActivationControllerDetailTest extends TestCase
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

    /**
     * @param array<string, mixed> $overrides
     */
    private function makeEngine(?callable $sender = null, array $overrides = []): DetailActivationEngine
    {
        $config = array_merge(TestHelper::getConfig(), $overrides);
        $config['email_sender'] = $sender ?? function (string $to, string $subject, string $body): void {
            $this->sent[] = ['to' => $to, 'subject' => $subject, 'body' => $body];
        };

        $app = new DetailActivationEngine();
        $app->set(self::CONFIG_KEY, $config);

        return $app;
    }

    /**
     * @param array<string, mixed> $query
     * @param array<string, mixed> $data
     */
    private function submit(DetailActivationEngine $app, string $email, array $query = []): ActivationController
    {
        $app->requestStub = (object) [
            'data'  => (object) ['email' => $email],
            'query' => (object) $query,
        ];

        return new ActivationController($app, self::CONFIG_KEY);
    }

    private function resendRows(): int
    {
        return (int) $this->pdo
            ->query("SELECT COUNT(*) FROM auth_logins WHERE id_type = '" . Login::ID_TYPE_ACTIVATION_RESEND . "'")
            ->fetchColumn();
    }

    /**
     * @return array<string, mixed>
     */
    private function onlyResendRow(): array
    {
        $rows = $this->pdo
            ->query("SELECT * FROM auth_logins WHERE id_type = '" . Login::ID_TYPE_ACTIVATION_RESEND . "' ORDER BY id")
            ->fetchAll(PDO::FETCH_ASSOC);
        $this->assertCount(1, $rows);

        return $rows[0];
    }

    // -----------------------------------------------------------------
    // show()
    // -----------------------------------------------------------------

    #[Test]
    public function showEchoesTheQueryEmail(): void
    {
        $app = $this->makeEngine();
        $this->submit($app, '', ['email' => 'from-query@example.com']);

        (new ActivationController($app, self::CONFIG_KEY))->show();

        $this->assertSame('from-query@example.com', $app->rendered[0]['data']['old']['email']);
    }

    #[Test]
    public function showTrimsTheQueryEmail(): void
    {
        $app = $this->makeEngine();
        $this->submit($app, '', ['email' => '  padded@example.com  ']);

        (new ActivationController($app, self::CONFIG_KEY))->show();

        $this->assertSame('padded@example.com', $app->rendered[0]['data']['old']['email']);
    }

    #[Test]
    public function showFallsBackToAnEmptyQueryEmail(): void
    {
        $app = $this->makeEngine();
        $this->submit($app, '');

        (new ActivationController($app, self::CONFIG_KEY))->show();

        $this->assertSame('', $app->rendered[0]['data']['old']['email']);
    }

    #[Test]
    public function showCarriesTheDefaultCooldown(): void
    {
        $app = $this->makeEngine();
        $this->submit($app, '');

        (new ActivationController($app, self::CONFIG_KEY))->show();

        $this->assertSame(0, $app->rendered[0]['data']['cooldown']);
    }

    #[Test]
    public function showCarriesTheConfig(): void
    {
        $app = $this->makeEngine();
        $this->submit($app, '');

        (new ActivationController($app, self::CONFIG_KEY))->show();

        $this->assertArrayHasKey('config', $app->rendered[0]['data']);
    }

    // -----------------------------------------------------------------
    // resend(): the throttle identifier
    // -----------------------------------------------------------------

    #[Test]
    public function theThrottleRowUsesTheSubmittedEmail(): void
    {
        $app = $this->makeEngine();
        $this->submit($app, 'ghost@example.com')->resend();

        $this->assertSame('ghost@example.com', $this->onlyResendRow()['identifier']);
    }

    #[Test]
    public function theThrottleRowUsesUnknownForAnEmptyEmail(): void
    {
        $app = $this->makeEngine();
        $this->submit($app, '')->resend();

        $this->assertSame('unknown', $this->onlyResendRow()['identifier']);
    }

    #[Test]
    public function theThrottleRowIsWrittenBeforeTheEmptyEmailReturn(): void
    {
        $app = $this->makeEngine();
        $this->submit($app, '')->resend();

        $this->assertSame(1, $this->resendRows());
        $this->assertSame('Enter your email address.', $app->rendered[0]['data']['error']);
    }

    #[Test]
    public function theThrottleRowRecordsTheIpAddress(): void
    {
        $_SERVER['REMOTE_ADDR'] = '203.0.113.9';

        $app = $this->makeEngine();
        $this->submit($app, 'ghost@example.com')->resend();

        $this->assertSame('203.0.113.9', $this->onlyResendRow()['ip_address']);
    }

    // -----------------------------------------------------------------
    // resend(): the render payloads
    // -----------------------------------------------------------------

    #[Test]
    public function theEmptyEmailPayloadEchoesTheEmptyValue(): void
    {
        $app = $this->makeEngine();
        $this->submit($app, '')->resend();

        $this->assertSame('', $app->rendered[0]['data']['old']['email']);
    }

    #[Test]
    public function theUnknownAddressPayloadEchoesTheEmail(): void
    {
        $app = $this->makeEngine();
        $this->submit($app, 'ghost@example.com')->resend();

        $this->assertSame('ghost@example.com', $app->rendered[0]['data']['old']['email']);
        $this->assertArrayHasKey('message', $app->rendered[0]['data']);
    }

    #[Test]
    public function theCooldownPayloadCarriesTheRemainingSeconds(): void
    {
        TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', false);

        $app = $this->makeEngine();
        $controller = $this->submit($app, 'user@example.com');

        $controller->resend();
        $controller->resend();

        $this->assertGreaterThan(0, $app->rendered[1]['data']['cooldown']);
        $this->assertLessThanOrEqual(300, $app->rendered[1]['data']['cooldown']);
    }

    #[Test]
    public function theSuccessPayloadCarriesTheConfiguredCooldown(): void
    {
        TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', false);

        $app = $this->makeEngine(null, ['resend_cooldown' => 120]);
        $this->submit($app, 'user@example.com')->resend();

        $this->assertSame(120, $app->rendered[0]['data']['cooldown']);
    }

    #[Test]
    public function theMailFailurePayloadEchoesTheEmail(): void
    {
        TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', false);

        $app = $this->makeEngine(function (): void {
            throw new \RuntimeException('mail transport down');
        });
        $this->submit($app, 'user@example.com')->resend();

        $this->assertSame('user@example.com', $app->rendered[0]['data']['old']['email']);
    }

    #[Test]
    public function theEmailIsTrimmedBeforeTheLookup(): void
    {
        TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', false);

        $app = $this->makeEngine();
        $this->submit($app, '  user@example.com  ')->resend();

        $this->assertCount(1, $this->sent);
        $this->assertSame('user@example.com', $this->sent[0]['to']);
    }

    #[Test]
    public function theTrimmedEmailIsEchoedBack(): void
    {
        TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', false);

        $app = $this->makeEngine();
        $this->submit($app, '  user@example.com  ')->resend();

        $this->assertSame('user@example.com', $app->rendered[0]['data']['old']['email']);
    }

    #[Test]
    public function theSentMessageIsTheSameForEveryOutcome(): void
    {
        TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', false);

        $app = $this->makeEngine();
        $this->submit($app, 'user@example.com')->resend();
        $sentMessage = $app->rendered[0]['data']['message'];

        $app2 = $this->makeEngine();
        $this->submit($app2, 'ghost@example.com')->resend();

        $this->assertSame($sentMessage, $app2->rendered[0]['data']['message']);
    }

    #[Test]
    public function theRenderTemplateIsAlwaysActivate(): void
    {
        $app = $this->makeEngine();
        $this->submit($app, 'ghost@example.com')->resend();

        $this->assertSame('activate', $app->rendered[0]['template']);
    }
}
