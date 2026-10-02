<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Integration\Authentication;

use Enlivenapp\FlightShield\Auth;
use Enlivenapp\FlightShield\Authentication\Actions\EmailActivator;
use Enlivenapp\FlightShield\Passwords\CompositionValidator;
use Enlivenapp\FlightShield\Tests\TestHelper;
use PDO;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Auth::register() is the single registration entry point. These tests pin
 * the session-free guarantee: registration must not write session state,
 * whether or not email activation is on.
 */
#[CoversClass(Auth::class)]
class AuthRegistrationTest extends TestCase
{
    protected PDO $pdo;
    protected string $views;

    /** @var array<int, array{to: string, subject: string, body: string}> */
    protected array $sent = [];

    protected function setUp(): void
    {
        $this->pdo = TestHelper::createDatabase();
        TestHelper::resetFlight();
        TestHelper::registerFlightDb($this->pdo);

        $now = (new \DateTimeImmutable())->format('Y-m-d H:i:s');
        $this->pdo->exec(
            "INSERT INTO auth_groups (alias, title, created_at, updated_at) VALUES ('user', 'User', '{$now}', '{$now}')"
        );

        // Isolated templates so the test does not depend on the shipped views.
        $this->views = sys_get_temp_dir() . '/shield-views-' . uniqid();
        mkdir($this->views . '/Email', 0777, true);
        file_put_contents($this->views . '/Email/email_activate_email.php', '<?= $activationUrl ?? "" ?>');
        file_put_contents($this->views . '/Email/email_register_existing.php', 'existing');

        $this->sent = [];
        $_SESSION = [];
    }

    protected function tearDown(): void
    {
        $this->removeDirectory($this->views);
        TestHelper::resetFlight();
        $_SESSION = [];
    }

    private function makeAuth(bool $activation): Auth
    {
        $config = TestHelper::getConfig();
        $config['actions']['register'] = $activation ? EmailActivator::class : null;
        $config['passwords']['validators'] = [CompositionValidator::class];
        $config['email_sender'] = function (string $to, string $subject, string $body): void {
            $this->sent[] = ['to' => $to, 'subject' => $subject, 'body' => $body];
        };

        $app = \Flight::app();
        $app->set('enlivenapp.flight-shield', $config);
        $app->set('flight.views.path', $this->views);
        $app->set('flight.views.extension', '.php');

        return new Auth($app, $config);
    }

    /**
     * @return array<string, string>
     */
    private function fields(string $email = 'new@example.com', string $username = 'newuser'): array
    {
        return [
            'username'         => $username,
            'email'            => $email,
            'password'         => 'Str0ng!Passw0rd',
            'password_confirm' => 'Str0ng!Passw0rd',
        ];
    }

    #[Test]
    public function registersActiveUserWhenActivationIsOff(): void
    {
        $result = $this->makeAuth(false)->register($this->fields());

        $this->assertTrue($result->isOK());
        $this->assertTrue($result->extraInfo()->isActivated());
        $this->assertSame([], $_SESSION);
        $this->assertSame([], $this->sent);
    }

    #[Test]
    public function registersInactiveUserAndSendsActivationMailWhenConfigured(): void
    {
        $result = $this->makeAuth(true)->register($this->fields());

        $this->assertTrue($result->isOK());
        $this->assertFalse($result->extraInfo()->isActivated());
        $this->assertSame([], $_SESSION);

        $this->assertSame(1, $this->countActivations());
        $this->assertCount(1, $this->sent);
        $this->assertSame('Activate Your Account', $this->sent[0]['subject']);
        $this->assertSame('new@example.com', $this->sent[0]['to']);
        $this->assertStringContainsString('/auth/activate/verify?token=', $this->sent[0]['body']);
    }

    #[Test]
    public function duplicateEmailReportsSuccessWithoutSecondAccount(): void
    {
        $auth = $this->makeAuth(false);
        $auth->register($this->fields());

        $this->sent = [];
        $result = $auth->register($this->fields('new@example.com', 'otheruser'));

        $this->assertTrue($result->isOK());
        $this->assertSame(1, (int) $this->pdo->query('SELECT COUNT(*) FROM users')->fetchColumn());
        $this->assertCount(1, $this->sent);
        $this->assertSame('Registration Attempt', $this->sent[0]['subject']);
    }

    #[Test]
    public function mismatchedConfirmationReturnsFieldErrors(): void
    {
        $fields = $this->fields();
        $fields['password_confirm'] = 'SomethingElse1!';

        $result = $this->makeAuth(false)->register($fields);

        $this->assertFalse($result->isOK());
        $this->assertIsArray($result->extraInfo());
        $this->assertNotEmpty($result->extraInfo());
        $this->assertSame(0, (int) $this->pdo->query('SELECT COUNT(*) FROM users')->fetchColumn());
    }

    private function countActivations(): int
    {
        return (int) $this->pdo
            ->query("SELECT COUNT(*) FROM auth_identities WHERE type = 'email_activate'")
            ->fetchColumn();
    }

    private function removeDirectory(string $dir): void
    {
        if (! is_dir($dir)) {
            return;
        }

        foreach (scandir($dir) ?: [] as $entry) {
            if ($entry === '.' || $entry === '..') {
                continue;
            }
            $path = $dir . '/' . $entry;
            is_dir($path) ? $this->removeDirectory($path) : unlink($path);
        }

        rmdir($dir);
    }
}
