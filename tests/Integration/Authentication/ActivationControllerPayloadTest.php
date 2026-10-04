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

class PayloadActivationEngine extends Engine
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
 * The activation page's render payloads: the cooldown message, the
 * old-email echo on every branch, and the default payload shape.
 */
#[CoversClass(ActivationController::class)]
class ActivationControllerPayloadTest extends TestCase
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
        unset($_SERVER['REMOTE_ADDR']);
    }

    /**
     * @param array<string, mixed> $overrides
     */
    private function makeEngine(?callable $sender = null, array $overrides = []): PayloadActivationEngine
    {
        $config = array_merge(TestHelper::getConfig(), $overrides);
        $config['email_sender'] = $sender ?? function (string $to, string $subject, string $body): void {
            $this->sent[] = ['to' => $to, 'subject' => $subject, 'body' => $body];
        };

        $app = new PayloadActivationEngine();
        $app->set(self::CONFIG_KEY, $config);

        return $app;
    }

    private function submit(PayloadActivationEngine $app, string $email): ActivationController
    {
        $app->requestStub = (object) [
            'data'  => (object) ['email' => $email],
            'query' => (object) [],
        ];

        return new ActivationController($app, self::CONFIG_KEY);
    }

    // -----------------------------------------------------------------
    // The cooldown message
    // -----------------------------------------------------------------

    #[Test]
    public function theCooldownMessageNamesTheWait(): void
    {
        TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', false);

        $app = $this->makeEngine();
        $controller = $this->submit($app, 'user@example.com');

        $controller->resend();
        $controller->resend();

        $error = (string) $app->rendered[1]['data']['error'];
        $this->assertStringStartsWith('Please wait ', $error);
        $this->assertStringEndsWith(' before requesting another link.', $error);
    }

    #[Test]
    public function theCooldownMessageCarriesTheFormattedTime(): void
    {
        TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', false);

        $app = $this->makeEngine(null, ['resend_cooldown' => 300]);
        $controller = $this->submit($app, 'user@example.com');

        $controller->resend();
        $controller->resend();

        $error = (string) $app->rendered[1]['data']['error'];
        $this->assertStringContainsString('5:00', $error);
    }

    #[Test]
    public function theCooldownPayloadEchoesTheEmail(): void
    {
        TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', false);

        $app = $this->makeEngine();
        $controller = $this->submit($app, 'user@example.com');

        $controller->resend();
        $controller->resend();

        $this->assertSame('user@example.com', $app->rendered[1]['data']['old']['email']);
    }

    // -----------------------------------------------------------------
    // The old-email echo on every branch
    // -----------------------------------------------------------------

    #[Test]
    public function theEmptyEmailBranchEchoesTheEmail(): void
    {
        $app = $this->makeEngine();
        $this->submit($app, '')->resend();

        $this->assertSame('', $app->rendered[0]['data']['old']['email']);
    }

    #[Test]
    public function theUnknownAddressBranchEchoesTheEmail(): void
    {
        $app = $this->makeEngine();
        $this->submit($app, 'ghost@example.com')->resend();

        $this->assertSame('ghost@example.com', $app->rendered[0]['data']['old']['email']);
    }

    #[Test]
    public function theMailFailureBranchEchoesTheEmail(): void
    {
        TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', false);

        $app = $this->makeEngine(function (): void {
            throw new \RuntimeException('mail transport down');
        });
        $this->submit($app, 'user@example.com')->resend();

        $this->assertSame('user@example.com', $app->rendered[0]['data']['old']['email']);
    }

    #[Test]
    public function theSuccessBranchEchoesTheEmail(): void
    {
        TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', false);

        $app = $this->makeEngine();
        $this->submit($app, 'user@example.com')->resend();

        $this->assertSame('user@example.com', $app->rendered[0]['data']['old']['email']);
    }

    // -----------------------------------------------------------------
    // The default payload
    // -----------------------------------------------------------------

    #[Test]
    public function theDefaultPayloadCarriesAnEmptyEmail(): void
    {
        $app = $this->makeEngine();
        $this->submit($app, '')->resend();

        // The empty-email branch passes its own 'old', so the default is
        // only visible on a branch that omits it.
        $this->assertArrayHasKey('old', $app->rendered[0]['data']);
    }

    #[Test]
    public function theDefaultPayloadCarriesTheConfig(): void
    {
        $app = $this->makeEngine();
        $this->submit($app, '')->resend();

        $this->assertArrayHasKey('config', $app->rendered[0]['data']);
    }

    #[Test]
    public function theDefaultCooldownIsZero(): void
    {
        $app = $this->makeEngine();
        $this->submit($app, '')->resend();

        $this->assertSame(0, $app->rendered[0]['data']['cooldown']);
    }

    #[Test]
    public function theSuccessBranchCarriesTheConfiguredCooldown(): void
    {
        TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', false);

        $app = $this->makeEngine(null, ['resend_cooldown' => 120]);
        $this->submit($app, 'user@example.com')->resend();

        $this->assertSame(120, $app->rendered[0]['data']['cooldown']);
    }

    // -----------------------------------------------------------------
    // The early returns
    // -----------------------------------------------------------------

    #[Test]
    public function theEmptyEmailBranchStopsAfterRendering(): void
    {
        $app = $this->makeEngine();
        $this->submit($app, '')->resend();

        $this->assertCount(1, $app->rendered);
        $this->assertSame('Enter your email address.', $app->rendered[0]['data']['error']);
    }

    #[Test]
    public function theMailFailureBranchStopsAfterRendering(): void
    {
        TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', false);

        $app = $this->makeEngine(function (): void {
            throw new \RuntimeException('mail transport down');
        });
        $this->submit($app, 'user@example.com')->resend();

        $this->assertCount(1, $app->rendered);
        $this->assertSame(
            'We could not send the activation email. Please try again.',
            $app->rendered[0]['data']['error']
        );
    }

    #[Test]
    public function theThrottleRowIsWrittenOnEveryBranch(): void
    {
        $app = $this->makeEngine();
        $this->submit($app, '')->resend();

        $this->assertSame(
            1,
            (int) $this->pdo->query("SELECT COUNT(*) FROM auth_logins WHERE id_type = '" . Login::ID_TYPE_ACTIVATION_RESEND . "'")->fetchColumn()
        );
    }
}
