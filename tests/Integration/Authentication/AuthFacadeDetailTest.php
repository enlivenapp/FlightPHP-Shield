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
 * The Auth facade details the flow tests leave open: the delegated
 * recordActiveDate, the credential trimming, the timing burn, and the
 * notice payload.
 */
#[CoversClass(Auth::class)]
class AuthFacadeDetailTest extends TestCase
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

        $this->views = sys_get_temp_dir() . '/shield-facade-views-' . uniqid();
        mkdir($this->views . '/Email', 0777, true);
        file_put_contents($this->views . '/Email/email_activate_email.php', '<?= $activationUrl ?? "" ?>');
        file_put_contents($this->views . '/Email/email_register_existing.php', 'existing');

        $this->sent = [];
        $_SESSION = [];
        $_SERVER['REMOTE_ADDR'] = '10.0.0.1';
    }

    protected function tearDown(): void
    {
        foreach (glob($this->views . '/Email/*') ?: [] as $file) {
            @unlink($file);
        }
        @rmdir($this->views . '/Email');
        @rmdir($this->views);

        TestHelper::resetFlight();
        $_SESSION = [];
        unset($_SERVER['REMOTE_ADDR']);
    }

    /**
     * @param array<string, mixed> $overrides
     */
    private function makeAuth(array $overrides = [], ?callable $sender = null): Auth
    {
        $config = array_merge(TestHelper::getConfig(), $overrides);
        $config['passwords']['validators'] = [CompositionValidator::class];
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
    private function fields(string $email = 'new@example.com'): array
    {
        return [
            'email'            => $email,
            'password'         => 'Str0ng!Passw0rd',
            'password_confirm' => 'Str0ng!Passw0rd',
        ];
    }

    private function lastActive(int $userId): mixed
    {
        return $this->pdo->query("SELECT last_active FROM users WHERE id = {$userId}")->fetchColumn();
    }

    // -----------------------------------------------------------------
    // recordActiveDate()
    // -----------------------------------------------------------------

    #[Test]
    public function recordActiveDateDelegatesToTheAuthenticator(): void
    {
        $user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);
        $auth = $this->makeAuth();

        $auth->setAuthenticator('session')->login($user);
        $auth->recordActiveDate();

        $this->assertNotNull($this->lastActive($user->id));
    }

    #[Test]
    public function recordActiveDateDoesNothingWhenLoggedOut(): void
    {
        $auth = $this->makeAuth();

        $auth->recordActiveDate();

        $this->assertSame(0, (int) $this->pdo->query('SELECT COUNT(*) FROM users WHERE last_active IS NOT NULL')->fetchColumn());
    }

    // -----------------------------------------------------------------
    // verifyCredentials(): trimming and the timing burn
    // -----------------------------------------------------------------

    #[Test]
    public function verifyCredentialsTrimsTheEmail(): void
    {
        TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);
        $auth = $this->makeAuth();

        $result = $auth->verifyCredentials([
            'email'    => '  user@example.com  ',
            'password' => 'Str0ng!Passw0rd',
        ]);

        $this->assertTrue($result->isOK());
    }

    #[Test]
    public function verifyCredentialsRejectsAnEmptyPassword(): void
    {
        TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);
        $auth = $this->makeAuth();

        $result = $auth->verifyCredentials(['email' => 'user@example.com', 'password' => '']);

        $this->assertFalse($result->isOK());
        $this->assertSame(Auth::CREDENTIALS_INVALID, $result->reason());
    }

    #[Test]
    public function verifyCredentialsRecordsAFailedAttemptForAnUnknownEmail(): void
    {
        $auth = $this->makeAuth();

        $auth->verifyCredentials(['email' => 'ghost@example.com', 'password' => 'Str0ng!Passw0rd']);

        $this->assertSame(1, (int) $this->pdo->query('SELECT COUNT(*) FROM auth_logins')->fetchColumn());
    }

    #[Test]
    public function verifyCredentialsRecordsAFailedAttemptForAWrongPassword(): void
    {
        TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);
        $auth = $this->makeAuth();

        $auth->verifyCredentials(['email' => 'user@example.com', 'password' => 'wrong-password']);

        $this->assertSame(1, (int) $this->pdo->query('SELECT COUNT(*) FROM auth_logins')->fetchColumn());
    }

    #[Test]
    public function verifyCredentialsRecordsASuccessfulAttempt(): void
    {
        $user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);
        $auth = $this->makeAuth();

        $auth->verifyCredentials(['email' => 'user@example.com', 'password' => 'Str0ng!Passw0rd']);

        $row = $this->pdo->query('SELECT * FROM auth_logins')->fetch(PDO::FETCH_ASSOC);
        $this->assertIsArray($row);
        $this->assertSame(1, (int) $row['success']);
        $this->assertSame($user->id, (int) $row['user_id']);
    }

    #[Test]
    public function verifyCredentialsDoesNotLogTheUserIn(): void
    {
        TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);
        $auth = $this->makeAuth();

        $auth->verifyCredentials(['email' => 'user@example.com', 'password' => 'Str0ng!Passw0rd']);

        $this->assertFalse($auth->setAuthenticator('session')->loggedIn());
    }

    // -----------------------------------------------------------------
    // The notice payload
    // -----------------------------------------------------------------

    #[Test]
    public function theNoticeViewReceivesTheIpAddress(): void
    {
        $_SERVER['REMOTE_ADDR'] = '203.0.113.9';

        $auth = $this->makeAuth();
        $auth->register($this->fields('dup@example.com'));

        $this->sent = [];
        $auth->register($this->fields('dup@example.com'));

        $this->assertCount(1, $this->sent);
        $this->assertSame('existing', $this->sent[0]['body']);
    }

    #[Test]
    public function theNoticeFallsBackToTheDefaultIpAddress(): void
    {
        unset($_SERVER['REMOTE_ADDR']);

        $auth = $this->makeAuth();
        $auth->register($this->fields('dup@example.com'));

        $this->sent = [];
        $result = $auth->register($this->fields('dup@example.com'));

        $this->assertTrue($result->isOK());
        $this->assertCount(1, $this->sent);
    }

    // -----------------------------------------------------------------
    // The activation guard
    // -----------------------------------------------------------------

    #[Test]
    public function aNonActivatorRegisterActionSkipsActivation(): void
    {
        $auth = $this->makeAuth(['actions' => ['register' => \stdClass::class]]);

        $result = $auth->register($this->fields());

        $this->assertTrue($result->isOK());
        $this->assertTrue($result->extraInfo()->isActivated());
    }

    #[Test]
    public function anEmptyRegisterActionSkipsActivation(): void
    {
        $auth = $this->makeAuth(['actions' => ['register' => '']]);

        $result = $auth->register($this->fields());

        $this->assertTrue($result->isOK());
        $this->assertTrue($result->extraInfo()->isActivated());
    }

    #[Test]
    public function aMissingRegisterActionSkipsActivation(): void
    {
        $auth = $this->makeAuth(['actions' => []]);

        $result = $auth->register($this->fields());

        $this->assertTrue($result->isOK());
        $this->assertTrue($result->extraInfo()->isActivated());
    }

    #[Test]
    public function theActivatorRegisterActionRequiresActivation(): void
    {
        $auth = $this->makeAuth(['actions' => ['register' => EmailActivator::class]]);

        $result = $auth->register($this->fields());

        $this->assertTrue($result->isOK());
        $this->assertFalse($result->extraInfo()->isActivated());
    }

    #[Test]
    public function anInactiveAccountResendSendsAnActivationLink(): void
    {
        $auth = $this->makeAuth(['actions' => ['register' => EmailActivator::class]]);
        $auth->register($this->fields());

        $this->sent = [];
        $result = $auth->register($this->fields());

        $this->assertTrue($result->isOK());
        $this->assertCount(1, $this->sent);
        $this->assertSame('Activate Your Account', $this->sent[0]['subject']);
    }

    #[Test]
    public function anActiveAccountGetsTheNotice(): void
    {
        $auth = $this->makeAuth(['actions' => ['register' => EmailActivator::class]]);

        $first = $auth->register($this->fields());
        $user = $first->extraInfo();
        $user->activate();
        $user->dirty(['active' => true]);
        $user->save();

        $this->sent = [];
        $result = $auth->register($this->fields());

        $this->assertTrue($result->isOK());
        $this->assertCount(1, $this->sent);
        $this->assertSame('Registration Attempt', $this->sent[0]['subject']);
    }
}
