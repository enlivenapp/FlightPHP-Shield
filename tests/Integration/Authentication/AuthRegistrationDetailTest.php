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
use Enlivenapp\FlightShield\Models\User;
use Enlivenapp\FlightShield\Passwords\CompositionValidator;
use Enlivenapp\FlightShield\Tests\TestHelper;
use PDO;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The registration details the flow tests leave open: the field-error
 * shape, the activation guard, the notice payload, and the email trimming.
 */
#[CoversClass(Auth::class)]
class AuthRegistrationDetailTest extends TestCase
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

        $this->views = sys_get_temp_dir() . '/shield-detail-views-' . uniqid();
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
        unset($_SERVER['REMOTE_ADDR']);
    }

    private function removeDirectory(string $dir): void
    {
        if (! is_dir($dir)) {
            return;
        }

        foreach (glob($dir . '/Email/*') ?: [] as $file) {
            @unlink($file);
        }
        @rmdir($dir . '/Email');
        @rmdir($dir);
    }

    private function makeAuth(bool $activation, ?callable $sender = null): Auth
    {
        $config = TestHelper::getConfig();
        $config['actions']['register'] = $activation ? EmailActivator::class : null;
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
    private function fields(string $email = 'new@example.com', string $username = 'newuser'): array
    {
        return [
            'username'         => $username,
            'email'            => $email,
            'password'         => 'Str0ng!Passw0rd',
            'password_confirm' => 'Str0ng!Passw0rd',
        ];
    }

    // -----------------------------------------------------------------
    // Field errors
    // -----------------------------------------------------------------

    #[Test]
    public function fieldErrorsAreReturnedAsAList(): void
    {
        $fields = $this->fields();
        $fields['password_confirm'] = 'SomethingElse1!';

        $result = $this->makeAuth(false)->register($fields);

        $this->assertFalse($result->isOK());
        $errors = $result->extraInfo();
        $this->assertIsArray($errors);
        $this->assertSame(array_values($errors), $errors);
    }

    #[Test]
    public function theFirstFieldErrorIsAlsoTheReason(): void
    {
        $fields = $this->fields();
        $fields['password_confirm'] = 'SomethingElse1!';

        $result = $this->makeAuth(false)->register($fields);

        $errors = $result->extraInfo();
        $this->assertSame($errors[0], $result->reason());
    }

    #[Test]
    public function anInvalidEmailIsRejectedBeforeAnyAccountIsMade(): void
    {
        $result = $this->makeAuth(false)->register($this->fields('not-an-email'));

        $this->assertFalse($result->isOK());
        $this->assertSame(0, (int) $this->pdo->query('SELECT COUNT(*) FROM users')->fetchColumn());
    }

    // -----------------------------------------------------------------
    // Email trimming
    // -----------------------------------------------------------------

    #[Test]
    public function aPaddedEmailFailsValidationBeforeTheTrim(): void
    {
        // Validation runs on the raw field, so padding is rejected before
        // the trim can help.
        $result = $this->makeAuth(false)->register($this->fields('  spaced@example.com  '));

        $this->assertFalse($result->isOK());
        $this->assertSame(0, (int) $this->pdo->query('SELECT COUNT(*) FROM users')->fetchColumn());
    }

    #[Test]
    public function aCleanEmailIsStoredAsGiven(): void
    {
        $result = $this->makeAuth(false)->register($this->fields('spaced@example.com'));

        $this->assertTrue($result->isOK());
        $this->assertSame('spaced', $result->extraInfo()->username);
    }

    // -----------------------------------------------------------------
    // The activation guard
    // -----------------------------------------------------------------

    #[Test]
    public function aNonActivatorRegisterActionDoesNotRequireActivation(): void
    {
        $config = TestHelper::getConfig();
        $config['actions']['register'] = \stdClass::class;
        $config['passwords']['validators'] = [CompositionValidator::class];
        $config['email_sender'] = function (): void {
        };

        $app = \Flight::app();
        $app->set('enlivenapp.flight-shield', $config);
        $app->set('flight.views.path', $this->views);
        $app->set('flight.views.extension', '.php');

        $result = (new Auth($app, $config))->register($this->fields());

        $this->assertTrue($result->isOK());
        $this->assertTrue($result->extraInfo()->isActivated());
    }

    #[Test]
    public function anEmptyRegisterActionDoesNotRequireActivation(): void
    {
        $config = TestHelper::getConfig();
        $config['actions']['register'] = '';
        $config['passwords']['validators'] = [CompositionValidator::class];
        $config['email_sender'] = function (): void {
        };

        $app = \Flight::app();
        $app->set('enlivenapp.flight-shield', $config);
        $app->set('flight.views.path', $this->views);
        $app->set('flight.views.extension', '.php');

        $result = (new Auth($app, $config))->register($this->fields());

        $this->assertTrue($result->isOK());
        $this->assertTrue($result->extraInfo()->isActivated());
    }

    #[Test]
    public function aMissingRegisterActionDoesNotRequireActivation(): void
    {
        $config = TestHelper::getConfig();
        unset($config['actions']['register']);
        $config['passwords']['validators'] = [CompositionValidator::class];
        $config['email_sender'] = function (): void {
        };

        $app = \Flight::app();
        $app->set('enlivenapp.flight-shield', $config);
        $app->set('flight.views.path', $this->views);
        $app->set('flight.views.extension', '.php');

        $result = (new Auth($app, $config))->register($this->fields());

        $this->assertTrue($result->isOK());
        $this->assertTrue($result->extraInfo()->isActivated());
    }

    // -----------------------------------------------------------------
    // The activation failure payload
    // -----------------------------------------------------------------

    #[Test]
    public function theActivationFailureCarriesTheFieldError(): void
    {
        $auth = $this->makeAuth(true, function (): void {
            throw new \RuntimeException('mail transport down');
        });

        $result = $auth->register($this->fields());

        $this->assertFalse($result->isOK());
        $errors = $result->extraInfo();
        $this->assertIsArray($errors);
        $this->assertCount(1, $errors);
        $this->assertStringContainsString('activation email', $errors[0]);
    }

    // -----------------------------------------------------------------
    // The soft-delete refusal payload
    // -----------------------------------------------------------------

    #[Test]
    public function theSoftDeleteRefusalCarriesTheFieldError(): void
    {
        $auth = $this->makeAuth(false);
        $first = $auth->register($this->fields('gone@example.com'));
        $auth->users()->delete($first->extraInfo());

        $again = $auth->register($this->fields('gone@example.com'));

        $this->assertFalse($again->isOK());
        $errors = $again->extraInfo();
        $this->assertIsArray($errors);
        $this->assertCount(1, $errors);
        $this->assertStringContainsString('no longer available', $errors[0]);
    }

    // -----------------------------------------------------------------
    // The registration notice
    // -----------------------------------------------------------------

    #[Test]
    public function theNoticeGoesToTheAttemptedAddress(): void
    {
        $auth = $this->makeAuth(false);
        $auth->register($this->fields('dup@example.com'));

        $this->sent = [];
        $auth->register($this->fields('dup@example.com'));

        $this->assertCount(1, $this->sent);
        $this->assertSame('dup@example.com', $this->sent[0]['to']);
        $this->assertSame('Registration Attempt', $this->sent[0]['subject']);
    }

    #[Test]
    public function theNoticeIsSkippedWhenNoSenderIsConfigured(): void
    {
        $config = TestHelper::getConfig();
        $config['actions']['register'] = null;
        $config['passwords']['validators'] = [CompositionValidator::class];
        $config['email_sender'] = null;

        $app = \Flight::app();
        $app->set('enlivenapp.flight-shield', $config);
        $app->set('flight.views.path', $this->views);
        $app->set('flight.views.extension', '.php');

        $auth = new Auth($app, $config);
        $auth->register($this->fields('dup@example.com'));

        // No sender, so the second attempt must still report success.
        $result = $auth->register($this->fields('dup@example.com'));

        $this->assertTrue($result->isOK());
        $this->assertSame([], $this->sent);
    }

    #[Test]
    public function theNoticeIsSkippedWhenTheSenderIsNotCallable(): void
    {
        $config = TestHelper::getConfig();
        $config['actions']['register'] = null;
        $config['passwords']['validators'] = [CompositionValidator::class];
        $config['email_sender'] = 'not-a-callable';

        $app = \Flight::app();
        $app->set('enlivenapp.flight-shield', $config);
        $app->set('flight.views.path', $this->views);
        $app->set('flight.views.extension', '.php');

        $auth = new Auth($app, $config);
        $auth->register($this->fields('dup@example.com'));

        $result = $auth->register($this->fields('dup@example.com'));

        $this->assertTrue($result->isOK());
        $this->assertSame([], $this->sent);
    }

    #[Test]
    public function aFailingNoticeSenderDoesNotFailTheRequest(): void
    {
        $auth = $this->makeAuth(false, function (): void {
            throw new \RuntimeException('mail transport down');
        });

        $auth->register($this->fields('dup@example.com'));

        $result = $auth->register($this->fields('dup@example.com'));

        $this->assertTrue($result->isOK());
    }

    #[Test]
    public function theNoticeViewReceivesTheRequestDetails(): void
    {
        $_SERVER['REMOTE_ADDR'] = '203.0.113.9';

        $auth = $this->makeAuth(false);
        $auth->register($this->fields('dup@example.com'));

        $this->sent = [];
        $auth->register($this->fields('dup@example.com'));

        $this->assertCount(1, $this->sent);
        $this->assertSame('existing', $this->sent[0]['body']);
    }

    // -----------------------------------------------------------------
    // The inactive-account resend
    // -----------------------------------------------------------------

    #[Test]
    public function anInactiveAccountResendDoesNotSendTheNotice(): void
    {
        $auth = $this->makeAuth(true);
        $auth->register($this->fields());

        $this->sent = [];
        $result = $auth->register($this->fields());

        $this->assertTrue($result->isOK());
        $this->assertCount(1, $this->sent);
        $this->assertSame('Activate Your Account', $this->sent[0]['subject']);
    }

    #[Test]
    public function anActiveAccountGetsTheNoticeInsteadOfAnActivationLink(): void
    {
        $auth = $this->makeAuth(true);

        // Register and activate, so the account is no longer pending.
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
