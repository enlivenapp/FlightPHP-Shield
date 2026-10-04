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

class Detail2FAView
{
    /** @var array<int, array{template: string, data: array<string, mixed>}> */
    public array $fetched = [];

    public function fetch(string $template, array $data = []): string
    {
        $this->fetched[] = ['template' => $template, 'data' => $data];

        return '';
    }
}

class Detail2FAAuthenticator
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

class Detail2FAAuth
{
    public function __construct(private Detail2FAAuthenticator $authenticator)
    {
    }

    public function getAuthenticator(): Detail2FAAuthenticator
    {
        return $this->authenticator;
    }

    public function user(): ?User
    {
        return $this->authenticator->getUser();
    }
}

class Detail2FASession
{
    /** @var array<string, mixed> */
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

class Detail2FAEngine extends Engine
{
    public ?Detail2FAAuth $authStub = null;
    public Detail2FAAuthenticator $authenticatorStub;
    public Detail2FASession $sessionStub;
    public Detail2FAView $viewSpy;
    public mixed $requestStub = null;

    /** @var string[] */
    public array $redirects = [];

    public bool $haltCalled = false;
    public ?int $haltCode = null;

    private array $store = [];

    public function __construct()
    {
        $this->authenticatorStub = new Detail2FAAuthenticator();
        $this->sessionStub = new Detail2FASession();
        $this->viewSpy = new Detail2FAView();
        $this->authStub = new Detail2FAAuth($this->authenticatorStub);
    }

    public function auth(): Detail2FAAuth
    {
        return $this->authStub;
    }

    public function session(): Detail2FASession
    {
        return $this->sessionStub;
    }

    public function view(): Detail2FAView
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
        $this->haltCode = $code;
    }
}

/**
 * The 2FA details the flow tests leave open: the halt code, the
 * "already sent" session guard, the email payload, the redirect fallbacks,
 * and the generated code shape.
 */
#[CoversClass(Email2FA::class)]
class Email2FADetailTest extends TestCase
{
    private const CONFIG_KEY = 'enlivenapp.flight-shield';

    protected PDO $pdo;
    protected Detail2FAEngine $app;
    protected User $user;

    /** @var array<string, mixed> */
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

        $this->app = new Detail2FAEngine();
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

    private function codeCount(): int
    {
        return (int) $this->pdo->query("SELECT COUNT(*) FROM auth_identities WHERE type = 'email_2fa'")->fetchColumn();
    }

    // -----------------------------------------------------------------
    // show(): the send guard
    // -----------------------------------------------------------------

    #[Test]
    public function showSendsOnlyOncePerSession(): void
    {
        $action = new Email2FA();

        $action->show($this->app);
        $action->show($this->app);

        $this->assertCount(1, $this->sent);
        $this->assertSame(1, $this->codeCount());
    }

    #[Test]
    public function showSendsAgainWhenTheCodeExpired(): void
    {
        $this->seedCode('123456', '-1 hour');
        $this->app->sessionStub->set('2fa_code_sent', true);

        (new Email2FA())->show($this->app);

        $this->assertCount(1, $this->sent);
    }

    #[Test]
    public function showSendsAgainWhenNoCodeExists(): void
    {
        $this->app->sessionStub->set('2fa_code_sent', true);

        (new Email2FA())->show($this->app);

        $this->assertCount(1, $this->sent);
    }

    #[Test]
    public function showMarksTheCodeAsSentInTheSession(): void
    {
        (new Email2FA())->show($this->app);

        $this->assertTrue($this->app->sessionStub->has('2fa_code_sent'));
        $this->assertTrue($this->app->sessionStub->get('2fa_code_sent'));
    }

    #[Test]
    public function showReplacesThePreviousCode(): void
    {
        $this->seedCode('old-code');

        (new Email2FA())->show($this->app);

        $this->assertSame(1, $this->codeCount());
    }

    #[Test]
    public function showHaltsWithA404ForARobot(): void
    {
        $_SERVER['HTTP_USER_AGENT'] = 'Googlebot/2.1';

        (new Email2FA())->show($this->app);

        $this->assertTrue($this->app->haltCalled);
        $this->assertSame(404, $this->app->haltCode);
    }

    #[Test]
    public function showReturnsAnEmptyStringForARobot(): void
    {
        $_SERVER['HTTP_USER_AGENT'] = 'Googlebot/2.1';

        $this->assertSame('', (new Email2FA())->show($this->app));
    }

    #[Test]
    public function showRendersTheVerifyTemplate(): void
    {
        (new Email2FA())->show($this->app);

        $fetched = $this->app->viewSpy->fetched;
        $this->assertSame('2fa_verify', $fetched[count($fetched) - 1]['template']);
    }

    // -----------------------------------------------------------------
    // show(): the email payload
    // -----------------------------------------------------------------

    #[Test]
    public function theEmailCarriesTheCodeAndRequestDetails(): void
    {
        $_SERVER['REMOTE_ADDR'] = '203.0.113.9';
        $_SERVER['HTTP_USER_AGENT'] = 'TestAgent/1.0';

        (new Email2FA())->show($this->app);

        $this->assertSame('user@example.com', $this->sent[0]['to']);
        $this->assertSame('Your Verification Code', $this->sent[0]['subject']);
    }

    #[Test]
    public function theEmailViewReceivesTheRequestDetails(): void
    {
        $_SERVER['REMOTE_ADDR'] = '203.0.113.9';
        $_SERVER['HTTP_USER_AGENT'] = 'TestAgent/1.0';

        (new Email2FA())->show($this->app);

        $emailView = null;
        foreach ($this->app->viewSpy->fetched as $fetch) {
            if ($fetch['template'] === 'Email/email_2fa_email') {
                $emailView = $fetch;
            }
        }

        $this->assertNotNull($emailView);
        $this->assertSame('203.0.113.9', $emailView['data']['ipAddress']);
        $this->assertSame('TestAgent/1.0', $emailView['data']['userAgent']);
        $this->assertArrayHasKey('code', $emailView['data']);
        $this->assertArrayHasKey('date', $emailView['data']);
    }

    #[Test]
    public function theEmailFallsBackToTheDefaultIpAddress(): void
    {
        unset($_SERVER['REMOTE_ADDR']);

        (new Email2FA())->show($this->app);

        $emailView = null;
        foreach ($this->app->viewSpy->fetched as $fetch) {
            if ($fetch['template'] === 'Email/email_2fa_email') {
                $emailView = $fetch;
            }
        }

        $this->assertNotNull($emailView);
        $this->assertSame('0.0.0.0', $emailView['data']['ipAddress']);
    }

    #[Test]
    public function theEmailFallsBackToAnEmptyUserAgent(): void
    {
        unset($_SERVER['HTTP_USER_AGENT']);

        (new Email2FA())->show($this->app);

        $emailView = null;
        foreach ($this->app->viewSpy->fetched as $fetch) {
            if ($fetch['template'] === 'Email/email_2fa_email') {
                $emailView = $fetch;
            }
        }

        $this->assertNotNull($emailView);
        $this->assertSame('', $emailView['data']['userAgent']);
    }

    #[Test]
    public function aMissingSenderThrows(): void
    {
        unset($this->config['email_sender']);
        $this->app->set(self::CONFIG_KEY, $this->config);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('email_sender');

        (new Email2FA())->show($this->app);
    }

    #[Test]
    public function aNonCallableSenderThrows(): void
    {
        $this->config['email_sender'] = 'not-a-callable';
        $this->app->set(self::CONFIG_KEY, $this->config);

        $this->expectException(\RuntimeException::class);

        (new Email2FA())->show($this->app);
    }

    // -----------------------------------------------------------------
    // createIdentity()
    // -----------------------------------------------------------------

    #[Test]
    public function theGeneratedCodeIsSixDigits(): void
    {
        $code = (new Email2FA())->createIdentity($this->user, $this->app);

        $this->assertMatchesRegularExpression('/^[1-9][0-9]{5}$/', $code);
    }

    #[Test]
    public function theGeneratedCodeIsStoredHashed(): void
    {
        $code = (new Email2FA())->createIdentity($this->user, $this->app);

        $stored = (string) $this->pdo->query("SELECT secret FROM auth_identities WHERE type = 'email_2fa'")->fetchColumn();

        $this->assertSame(hash('sha256', $code), $stored);
        $this->assertNotSame($code, $stored);
    }

    #[Test]
    public function createIdentityReplacesAnyPreviousCode(): void
    {
        $this->seedCode('old-code');

        (new Email2FA())->createIdentity($this->user, $this->app);

        $this->assertSame(1, $this->codeCount());
    }

    #[Test]
    public function theIdentityCarriesTheTwoFactorType(): void
    {
        (new Email2FA())->createIdentity($this->user, $this->app);

        $this->assertSame(
            Session::ID_TYPE_EMAIL_2FA,
            (string) $this->pdo->query("SELECT type FROM auth_identities WHERE type = 'email_2fa'")->fetchColumn()
        );
    }

    // -----------------------------------------------------------------
    // verify(): redirects
    // -----------------------------------------------------------------

    #[Test]
    public function verifyFallsBackToTheRootRedirect(): void
    {
        unset($this->config['redirects']['after_login']);
        $this->app->set(self::CONFIG_KEY, $this->config);

        $this->seedCode('123456');
        $this->app->requestStub = (object) ['data' => (object) ['token' => '123456'], 'query' => (object) []];

        (new Email2FA())->verify($this->app);

        $this->assertSame(['/'], $this->app->redirects);
    }

    #[Test]
    public function verifyUsesTheConfiguredRedirect(): void
    {
        $this->config['redirects']['after_login'] = '/dashboard';
        $this->app->set(self::CONFIG_KEY, $this->config);

        $this->seedCode('123456');
        $this->app->requestStub = (object) ['data' => (object) ['token' => '123456'], 'query' => (object) []];

        (new Email2FA())->verify($this->app);

        $this->assertSame(['/dashboard'], $this->app->redirects);
    }

    #[Test]
    public function verifyIgnoresTheAdminRedirectForANonAdmin(): void
    {
        $this->config['redirects']['after_login_admin'] = '/admin';
        $this->app->set(self::CONFIG_KEY, $this->config);

        $this->seedCode('123456');
        $this->app->requestStub = (object) ['data' => (object) ['token' => '123456'], 'query' => (object) []];

        (new Email2FA())->verify($this->app);

        $this->assertSame(['/'], $this->app->redirects);
    }

    #[Test]
    public function verifyIgnoresTheAdminRedirectWhenItIsNotConfigured(): void
    {
        $admin = TestHelper::createUser($this->pdo, 'admin@example.com', 'Str0ng!Passw0rd', 'admin', true);
        $admin->addPermission('admin.access');
        $this->app->authenticatorStub->pendingUser = $admin;
        $this->user = $admin;

        $this->seedCode('123456');
        $this->app->requestStub = (object) ['data' => (object) ['token' => '123456'], 'query' => (object) []];

        (new Email2FA())->verify($this->app);

        $this->assertSame(['/'], $this->app->redirects);
    }

    #[Test]
    public function verifyHaltsWithA404ForARobot(): void
    {
        $_SERVER['HTTP_USER_AGENT'] = 'Googlebot/2.1';

        (new Email2FA())->verify($this->app);

        $this->assertTrue($this->app->haltCalled);
        $this->assertSame(404, $this->app->haltCode);
    }

    #[Test]
    public function verifyReturnsAnEmptyStringForARobot(): void
    {
        $_SERVER['HTTP_USER_AGENT'] = 'Googlebot/2.1';

        $this->assertSame('', (new Email2FA())->verify($this->app));
    }

    #[Test]
    public function verifyFallsBackToAnEmptyToken(): void
    {
        $this->seedCode('123456');
        $this->app->authenticatorStub->checkActionResult = false;
        $this->app->requestStub = (object) ['data' => (object) [], 'query' => (object) []];

        (new Email2FA())->verify($this->app);

        $this->assertSame('Invalid 2FA code.', $this->app->viewSpy->fetched[0]['data']['error']);
    }

    #[Test]
    public function verifyThrowsWithoutAPendingUser(): void
    {
        $this->app->authenticatorStub->pendingUser = null;

        $this->expectException(\RuntimeException::class);

        (new Email2FA())->verify($this->app);
    }

    // -----------------------------------------------------------------
    // handle(): the cooldown message
    // -----------------------------------------------------------------

    #[Test]
    public function theCooldownMessageNamesTheWait(): void
    {
        $this->config['resend_cooldown'] = 300;
        $this->app->set(self::CONFIG_KEY, $this->config);

        $this->seedCode('123456');

        (new Email2FA())->handle($this->app);

        $error = (string) $this->app->viewSpy->fetched[0]['data']['error'];
        $this->assertStringStartsWith('Please wait ', $error);
        $this->assertStringEndsWith(' before requesting a new code.', $error);
        $this->assertStringContainsString('5', $error);
    }

    #[Test]
    public function handleThrowsWithoutAPendingUser(): void
    {
        $this->app->authenticatorStub->pendingUser = null;

        $this->expectException(\RuntimeException::class);

        (new Email2FA())->handle($this->app);
    }
}
