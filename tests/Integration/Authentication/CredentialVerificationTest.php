<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Integration\Authentication;

use Enlivenapp\FlightShield\Auth;
use Enlivenapp\FlightShield\Tests\TestHelper;
use PDO;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Auth::verifyCredentials() confirms an email/password pair for other
 * plugins without starting a login. These tests pin the outcome codes and
 * the session-free guarantee.
 */
#[CoversClass(Auth::class)]
class CredentialVerificationTest extends TestCase
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

        $this->views = sys_get_temp_dir() . '/shield-views-' . uniqid();
        mkdir($this->views . '/Email', 0777, true);
        file_put_contents($this->views . '/Email/email_activate_email.php', '<?= $activationUrl ?? "" ?>');

        $this->sent = [];
        $_SESSION = [];
    }

    protected function tearDown(): void
    {
        $this->removeDirectory($this->views);
        TestHelper::resetFlight();
        $_SESSION = [];
    }

    private function makeAuth(?callable $sender = null): Auth
    {
        $config = TestHelper::getConfig();
        $config['email_sender'] = $sender ?? function (string $to, string $subject, string $body): void {
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
    private function credentials(string $email = 'user@example.com', string $password = 'Str0ng!Passw0rd'): array
    {
        return ['email' => $email, 'password' => $password];
    }

    #[Test]
    public function validActivatedCredentialsReturnTheUser(): void
    {
        TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);

        $result = $this->makeAuth()->verifyCredentials($this->credentials());

        $this->assertTrue($result->isOK());
        $this->assertSame('user', $result->user()->username);
        $this->assertNull($result->reason());
        $this->assertSame([], $_SESSION);
    }

    #[Test]
    public function wrongPasswordIsRejected(): void
    {
        TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);

        $result = $this->makeAuth()->verifyCredentials($this->credentials('user@example.com', 'nope'));

        $this->assertFalse($result->isOK());
        $this->assertSame(Auth::CREDENTIALS_INVALID, $result->reason());
        $this->assertNull($result->user());
        $this->assertSame([], $_SESSION);
    }

    #[Test]
    public function unknownEmailIsRejectedWithTheSameReason(): void
    {
        $result = $this->makeAuth()->verifyCredentials($this->credentials('ghost@example.com'));

        $this->assertFalse($result->isOK());
        $this->assertSame(Auth::CREDENTIALS_INVALID, $result->reason());
        $this->assertSame([], $_SESSION);
    }

    #[Test]
    public function bannedAccountIsReportedSeparately(): void
    {
        $user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);
        $this->pdo->exec("UPDATE users SET status = 'banned', status_message = 'Trouble.' WHERE id = {$user->id}");

        $result = $this->makeAuth()->verifyCredentials($this->credentials());

        $this->assertFalse($result->isOK());
        $this->assertSame('Trouble.', $result->reason());
        $this->assertNull($result->user());
        $this->assertSame([], $_SESSION);
    }

    #[Test]
    public function inactiveAccountGetsAFreshActivationEmail(): void
    {
        TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', false);

        $result = $this->makeAuth()->verifyCredentials($this->credentials());

        $this->assertFalse($result->isOK());
        $this->assertSame(Auth::ACCOUNT_NOT_ACTIVATED, $result->reason());
        $this->assertNull($result->user());
        $this->assertCount(1, $this->sent);
        $this->assertSame('user@example.com', $this->sent[0]['to']);
        $this->assertSame([], $_SESSION);
    }

    #[Test]
    public function activationEmailFailureStillReportsNotActivated(): void
    {
        TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', false);

        $auth = $this->makeAuth(function (): void {
            throw new \RuntimeException('mail transport down');
        });

        $result = $auth->verifyCredentials($this->credentials());

        $this->assertFalse($result->isOK());
        $this->assertSame(Auth::ACCOUNT_NOT_ACTIVATED, $result->reason());
        $this->assertSame([], $this->sent);
    }

    #[Test]
    public function everyOutcomeIsRecordedForTheRateLimiter(): void
    {
        TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);

        $auth = $this->makeAuth();
        $auth->verifyCredentials($this->credentials('user@example.com', 'nope'));
        $auth->verifyCredentials($this->credentials('ghost@example.com'));
        $auth->verifyCredentials($this->credentials());

        $total = (int) $this->pdo->query('SELECT COUNT(*) FROM auth_logins')->fetchColumn();
        $failed = (int) $this->pdo->query('SELECT COUNT(*) FROM auth_logins WHERE success = 0')->fetchColumn();

        $this->assertSame(3, $total);
        $this->assertSame(2, $failed);
    }

    private function removeDirectory(string $path): void
    {
        if (! is_dir($path)) {
            return;
        }

        foreach (scandir($path) ?: [] as $entry) {
            if ($entry === '.' || $entry === '..') {
                continue;
            }

            $full = $path . '/' . $entry;
            is_dir($full) ? $this->removeDirectory($full) : @unlink($full);
        }

        @rmdir($path);
    }
}
