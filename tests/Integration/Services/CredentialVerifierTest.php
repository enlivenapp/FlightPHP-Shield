<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Integration\Services;

use Enlivenapp\FlightShield\Authentication\Authenticators\Session;
use Enlivenapp\FlightShield\Models\Login;
use Enlivenapp\FlightShield\Models\User;
use Enlivenapp\FlightShield\Services\CredentialVerifier;
use Enlivenapp\FlightShield\Tests\TestHelper;
use PDO;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Attempt recording, the throttle counter and the activation mail helper.
 */
#[CoversClass(CredentialVerifier::class)]
class CredentialVerifierTest extends TestCase
{
    protected PDO $pdo;
    protected User $user;
    protected string $views;

    protected function setUp(): void
    {
        $this->pdo = TestHelper::createDatabase();
        TestHelper::resetFlight();
        TestHelper::registerFlightDb($this->pdo);

        $_SESSION = [];
        $_SERVER['REMOTE_ADDR'] = '10.0.0.1';

        $this->user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);

        $this->views = sys_get_temp_dir() . '/shield-cv-views-' . uniqid();
        mkdir($this->views . '/Email', 0777, true);
        file_put_contents($this->views . '/Email/email_activate_email.php', '<?= $activationUrl ?? "" ?>');
    }

    protected function tearDown(): void
    {
        TestHelper::resetFlight();
        $_SESSION = [];
        unset($_SERVER['REMOTE_ADDR']);

        if (is_dir($this->views)) {
            array_map('unlink', glob($this->views . '/Email/*'));
            @rmdir($this->views . '/Email');
            @rmdir($this->views);
        }
    }

    private function verifier(array $overrides = [], ?callable $sender = null): CredentialVerifier
    {
        $config = array_merge(TestHelper::getConfig(), $overrides);
        $config['email_sender'] = $sender ?? function (): void {
        };

        $app = \Flight::app();
        $app->set('enlivenapp.flight-shield', $config);
        $app->set('flight.views.path', $this->views);
        $app->set('flight.views.extension', '.php');

        return new CredentialVerifier($app, $config);
    }

    private function loginRows(): int
    {
        return (int) $this->pdo->query('SELECT COUNT(*) FROM auth_logins')->fetchColumn();
    }

    // -----------------------------------------------------------------
    // recordAttempt()
    // -----------------------------------------------------------------

    #[Test]
    public function recordAttemptWritesWhenTheLevelIsAll(): void
    {
        $this->verifier(['record_login_attempt' => 'all'])
            ->recordAttempt('user@example.com', Session::ID_TYPE_EMAIL_PASSWORD, true, (int) $this->user->id);

        $this->assertSame(1, $this->loginRows());
    }

    #[Test]
    public function recordAttemptIsSilentWhenTheLevelIsNone(): void
    {
        $this->verifier(['record_login_attempt' => 'none'])
            ->recordAttempt('user@example.com', Session::ID_TYPE_EMAIL_PASSWORD, false);

        $this->assertSame(0, $this->loginRows());
    }

    #[Test]
    public function recordAttemptSkipsSuccessesAtTheFailureLevel(): void
    {
        $verifier = $this->verifier(['record_login_attempt' => 'failure']);

        $verifier->recordAttempt('user@example.com', Session::ID_TYPE_EMAIL_PASSWORD, true);
        $verifier->recordAttempt('user@example.com', Session::ID_TYPE_EMAIL_PASSWORD, false);

        $this->assertSame(1, $this->loginRows());
    }

    // -----------------------------------------------------------------
    // recordThrottleHit()
    // -----------------------------------------------------------------

    #[Test]
    public function recordThrottleHitWritesEvenWhenRecordingIsOff(): void
    {
        $this->verifier(['record_login_attempt' => 'none'])
            ->recordThrottleHit('user@example.com', Login::ID_TYPE_ACTIVATION_RESEND);

        $this->assertSame(1, $this->loginRows());
    }

    #[Test]
    public function recordThrottleHitMarksTheAttemptAsSuccessful(): void
    {
        $this->verifier()->recordThrottleHit('user@example.com', Login::ID_TYPE_ACTIVATION_RESEND);

        $success = (int) $this->pdo->query('SELECT success FROM auth_logins')->fetchColumn();
        $this->assertSame(1, $success);
    }

    // -----------------------------------------------------------------
    // sendActivation()
    // -----------------------------------------------------------------

    #[Test]
    public function sendActivationReturnsTrueWhenTheMailIsSent(): void
    {
        $sent = [];
        $verifier = $this->verifier([], function (string $to) use (&$sent): void {
            $sent[] = $to;
        });

        $this->assertTrue($verifier->sendActivation($this->user));
        $this->assertSame(['user@example.com'], $sent);
    }

    #[Test]
    public function sendActivationReturnsFalseWhenTheSenderThrows(): void
    {
        $verifier = $this->verifier([], function (): void {
            throw new \RuntimeException('mail transport down');
        });

        $this->assertFalse($verifier->sendActivation($this->user));
    }
}
