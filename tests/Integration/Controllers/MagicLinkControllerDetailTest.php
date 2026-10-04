<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Integration\Controllers;

use Enlivenapp\FlightShield\Authentication\Actions\Email2FA;
use Enlivenapp\FlightShield\Auth;
use Enlivenapp\FlightShield\Controllers\MagicLinkController;
use Enlivenapp\FlightShield\Models\User;
use Enlivenapp\FlightShield\Models\UserIdentity;
use Enlivenapp\FlightShield\Tests\TestHelper;
use PDO;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The magic-link details the happy-path tests do not pin down: the token
 * inside the emailed link, the configured redirects, the halt code, the
 * record_login_attempt levels, and the branches that need a custom config.
 */
#[CoversClass(MagicLinkController::class)]
class MagicLinkControllerDetailTest extends TestCase
{
    private const CONFIG_KEY = 'enlivenapp.flight-shield';

    protected PDO $pdo;
    protected ControllerSpyEngine $app;
    protected Auth $auth;

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
        $this->config['allow_magic_link'] = true;
        $this->config['email_sender'] = function (string $to, string $subject, string $body): void {
            $this->sent[] = ['to' => $to, 'subject' => $subject, 'body' => $body];
        };

        $this->app = new ControllerSpyEngine();
        $this->app->set(self::CONFIG_KEY, $this->config);
        $this->auth = new Auth($this->app, $this->config);
        $this->app->authStub = $this->auth;
        $this->request(query: ['token' => ''], data: ['email' => '']);
    }

    protected function tearDown(): void
    {
        TestHelper::resetFlight();
        $_SESSION = [];
        unset($_SERVER['REMOTE_ADDR'], $_SERVER['HTTP_USER_AGENT']);
    }

    /**
     * @param array<string, mixed> $query
     * @param array<string, mixed> $data
     */
    private function request(array $query = [], array $data = []): void
    {
        $this->app->requestStub = (object) [
            'query' => (object) $query,
            'data'  => (object) $data,
        ];
    }

    private function controller(): MagicLinkController
    {
        return new MagicLinkController($this->app, self::CONFIG_KEY);
    }

    /**
     * @param array<string, mixed> $config
     */
    private function useConfig(array $config): void
    {
        $this->config = $config;
        $this->app->set(self::CONFIG_KEY, $config);
        $this->auth = new Auth($this->app, $config);
        $this->app->authStub = $this->auth;
    }

    private function seedMagicIdentity(User $user, string $rawToken, string $expires = '+1 hour'): void
    {
        $now = new \DateTimeImmutable();

        $identity = new UserIdentity($this->pdo);
        $identity->user_id    = $user->id;
        $identity->type       = UserIdentity::TYPE_MAGIC_LINK;
        $identity->secret     = hash('sha256', $rawToken);
        $identity->expires    = $now->modify($expires)->format('Y-m-d H:i:s');
        $identity->created_at = $now->format('Y-m-d H:i:s');
        $identity->updated_at = $now->format('Y-m-d H:i:s');
        $identity->insert();
    }

    private function loginCount(): int
    {
        return (int) $this->pdo->query(
            "SELECT COUNT(*) FROM auth_logins WHERE id_type = '" . UserIdentity::TYPE_MAGIC_LINK . "'"
        )->fetchColumn();
    }

    /**
     * @return array<string, mixed>
     */
    private function onlyLoginRow(): array
    {
        $rows = $this->pdo->query('SELECT * FROM auth_logins ORDER BY id')->fetchAll(PDO::FETCH_ASSOC);
        $this->assertCount(1, $rows);

        return $rows[0];
    }

    private function tokenFromTheEmail(): string
    {
        $this->assertCount(1, $this->sent);
        $this->assertCount(1, $this->app->viewFetched);

        $url = (string) $this->app->viewFetched[0]['data']['magicLinkUrl'];
        parse_str((string) parse_url($url, PHP_URL_QUERY), $query);

        return (string) ($query['token'] ?? '');
    }

    // -----------------------------------------------------------------
    // The emailed link
    // -----------------------------------------------------------------

    #[Test]
    public function theEmailedLinkCarriesTheTokenThatVerifies(): void
    {
        TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);
        $this->request(data: ['email' => 'user@example.com']);

        $this->controller()->sendMagicLink();

        $token = $this->tokenFromTheEmail();
        $this->assertSame(40, strlen($token));

        $this->request(query: ['token' => $token]);
        $this->controller()->verify();

        $this->assertSame(['/'], $this->app->redirects);
        $this->assertTrue($this->auth->setAuthenticator('session')->loggedIn());
    }

    #[Test]
    public function theEmailedLinkUsesTheConfiguredBaseUrl(): void
    {
        TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);
        $this->app->set('flight.base_url', 'https://example.test/');
        $this->request(data: ['email' => 'user@example.com']);

        $this->controller()->sendMagicLink();

        $url = (string) $this->app->viewFetched[0]['data']['magicLinkUrl'];
        $this->assertStringStartsWith('https://example.test/auth/magic-link/verify?token=', $url);
    }

    #[Test]
    public function theEmailCarriesTheRequestDetails(): void
    {
        TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);
        $_SERVER['REMOTE_ADDR'] = '203.0.113.9';
        $_SERVER['HTTP_USER_AGENT'] = 'TestAgent/1.0';
        $this->request(data: ['email' => 'user@example.com']);

        $this->controller()->sendMagicLink();

        $data = $this->app->viewFetched[0]['data'];
        $this->assertSame('203.0.113.9', $data['ipAddress']);
        $this->assertSame('TestAgent/1.0', $data['userAgent']);
        $this->assertSame('Email/magic_link_email', $this->app->viewFetched[0]['template']);
        $this->assertSame('Your Login Link', $this->sent[0]['subject']);
    }

    #[Test]
    public function theEmailFallsBackToTheDefaultIpAddress(): void
    {
        TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);
        unset($_SERVER['REMOTE_ADDR']);
        $this->request(data: ['email' => 'user@example.com']);

        $this->controller()->sendMagicLink();

        $this->assertSame('0.0.0.0', $this->app->viewFetched[0]['data']['ipAddress']);
    }

    #[Test]
    public function theEmailIsSentToTheAddressOnTheIdentity(): void
    {
        TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);
        $this->request(data: ['email' => 'user@example.com']);

        $this->controller()->sendMagicLink();

        $this->assertSame('user@example.com', $this->sent[0]['to']);
    }

    #[Test]
    public function theAddressIsTrimmedBeforeTheLookup(): void
    {
        TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);
        $this->request(data: ['email' => '  user@example.com  ']);

        $this->controller()->sendMagicLink();

        $this->assertCount(1, $this->sent);
        $this->assertSame('user@example.com', $this->sent[0]['to']);
    }

    #[Test]
    public function aMissingEmailAddressIsTreatedAsUnknown(): void
    {
        $this->request(data: []);

        $this->controller()->sendMagicLink();

        $this->assertSame([], $this->sent);
        $this->assertSame('magic_link_message', $this->app->rendered[0]['template']);
    }

    #[Test]
    public function aNonCallableSenderIsIgnored(): void
    {
        TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);

        $config = $this->config;
        $config['email_sender'] = 'not-a-callable';
        $this->useConfig($config);

        $this->request(data: ['email' => 'user@example.com']);
        $this->controller()->sendMagicLink();

        $this->assertSame([], $this->sent);
        $this->assertSame([], $this->app->viewFetched);
        $this->assertSame('magic_link_message', $this->app->rendered[0]['template']);
    }

    #[Test]
    public function aMissingSenderIsIgnored(): void
    {
        TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);

        $config = $this->config;
        unset($config['email_sender']);
        $this->useConfig($config);

        $this->request(data: ['email' => 'user@example.com']);
        $this->controller()->sendMagicLink();

        $this->assertSame([], $this->sent);
        $this->assertSame('magic_link_message', $this->app->rendered[0]['template']);
    }

    #[Test]
    public function theTokenExpiresAfterTheConfiguredLifetime(): void
    {
        TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);

        $config = $this->config;
        $config['magic_link_lifetime'] = 120;
        $this->useConfig($config);

        $this->request(data: ['email' => 'user@example.com']);
        $this->controller()->sendMagicLink();

        $expires = (string) $this->pdo->query(
            "SELECT expires FROM auth_identities WHERE type = '" . UserIdentity::TYPE_MAGIC_LINK . "'"
        )->fetchColumn();

        $this->assertEqualsWithDelta(120, (int) strtotime($expires) - time(), 10);
    }

    #[Test]
    public function theTokenExpiresAfterTheDefaultLifetime(): void
    {
        TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);

        $config = $this->config;
        unset($config['magic_link_lifetime']);
        $this->useConfig($config);

        $this->request(data: ['email' => 'user@example.com']);
        $this->controller()->sendMagicLink();

        $expires = (string) $this->pdo->query(
            "SELECT expires FROM auth_identities WHERE type = '" . UserIdentity::TYPE_MAGIC_LINK . "'"
        )->fetchColumn();

        $this->assertEqualsWithDelta(3600, (int) strtotime($expires) - time(), 10);
    }

    #[Test]
    public function issuingANewLinkReplacesThePreviousOne(): void
    {
        $user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);
        $this->seedMagicIdentity($user, 'stale-token');

        $this->request(data: ['email' => 'user@example.com']);
        $this->controller()->sendMagicLink();

        $this->assertSame(
            1,
            (int) $this->pdo->query(
                "SELECT COUNT(*) FROM auth_identities WHERE type = '" . UserIdentity::TYPE_MAGIC_LINK . "'"
            )->fetchColumn()
        );

        $this->request(query: ['token' => 'stale-token']);
        $this->controller()->verify();

        $this->assertSame(['/auth/login'], $this->app->redirects);
    }

    // -----------------------------------------------------------------
    // Configured redirects
    // -----------------------------------------------------------------

    #[Test]
    public function showLoginFormUsesTheConfiguredLoginRedirect(): void
    {
        $config = $this->config;
        $config['allow_magic_link'] = false;
        $config['redirects']['login'] = '/custom/login';
        $this->useConfig($config);

        $this->controller()->showLoginForm();

        $this->assertSame(['/custom/login'], $this->app->redirects);
    }

    #[Test]
    public function showLoginFormUsesTheConfiguredAfterLoginRedirect(): void
    {
        $user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);
        $this->auth->setAuthenticator('session')->login($user);

        $config = $this->config;
        $config['redirects']['after_login'] = '/dashboard';
        $this->useConfig($config);

        $this->controller()->showLoginForm();

        $this->assertSame(['/dashboard'], $this->app->redirects);
    }

    #[Test]
    public function verifyUsesTheConfiguredAfterLoginRedirect(): void
    {
        $user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);
        $this->seedMagicIdentity($user, 'good-token');

        $config = $this->config;
        $config['redirects']['after_login'] = '/dashboard';
        $this->useConfig($config);

        $this->request(query: ['token' => 'good-token']);
        $this->controller()->verify();

        $this->assertSame(['/dashboard'], $this->app->redirects);
    }

    #[Test]
    public function verifyUsesTheConfiguredLoginRedirectForAnUnknownToken(): void
    {
        $config = $this->config;
        $config['redirects']['login'] = '/custom/login';
        $this->useConfig($config);

        $this->request(query: ['token' => 'nope']);
        $this->controller()->verify();

        $this->assertSame(['/custom/login'], $this->app->redirects);
    }

    #[Test]
    public function verifyUsesTheConfiguredLoginRedirectForAnExpiredToken(): void
    {
        $user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);
        $this->seedMagicIdentity($user, 'old-token', '-1 hour');

        $config = $this->config;
        $config['redirects']['login'] = '/custom/login';
        $this->useConfig($config);

        $this->request(query: ['token' => 'old-token']);
        $this->controller()->verify();

        $this->assertSame(['/custom/login'], $this->app->redirects);
    }

    #[Test]
    public function verifyUsesTheConfiguredLoginRedirectForABannedUser(): void
    {
        $user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);
        $this->pdo->exec("UPDATE users SET status = 'banned' WHERE id = {$user->id}");
        $this->seedMagicIdentity($user, 'banned-token');

        $config = $this->config;
        $config['redirects']['login'] = '/custom/login';
        $this->useConfig($config);

        $this->request(query: ['token' => 'banned-token']);
        $this->controller()->verify();

        $this->assertSame(['/custom/login'], $this->app->redirects);
        $this->assertFalse($this->auth->setAuthenticator('session')->loggedIn());
    }

    #[Test]
    public function verifyUsesTheConfiguredLoginRedirectWhenTheUserVanished(): void
    {
        $user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);
        $this->seedMagicIdentity($user, 'orphan-token');
        $this->pdo->exec("DELETE FROM users WHERE id = {$user->id}");

        $config = $this->config;
        $config['redirects']['login'] = '/custom/login';
        $this->useConfig($config);

        $this->request(query: ['token' => 'orphan-token']);
        $this->controller()->verify();

        $this->assertSame(['/custom/login'], $this->app->redirects);
        $this->assertSame(1, $this->loginCount());
    }

    // -----------------------------------------------------------------
    // Bot handling
    // -----------------------------------------------------------------

    #[Test]
    public function aRobotGetsA404(): void
    {
        $_SERVER['HTTP_USER_AGENT'] = 'Googlebot/2.1';
        $this->request(query: ['token' => 'anything']);

        $this->controller()->verify();

        $this->assertTrue($this->app->haltCalled);
        $this->assertSame(404, $this->app->haltCode);
    }

    #[Test]
    public function botDetectionCanBeTurnedOff(): void
    {
        $user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);
        $this->seedMagicIdentity($user, 'bot-token');

        $config = $this->config;
        $config['bot_detection'] = ['enabled' => false];
        $this->useConfig($config);

        $_SERVER['HTTP_USER_AGENT'] = 'Googlebot/2.1';
        $this->request(query: ['token' => 'bot-token']);
        $this->controller()->verify();

        $this->assertFalse($this->app->haltCalled);
        $this->assertSame(['/'], $this->app->redirects);
    }

    #[Test]
    public function aCustomRobotKeywordIsHonoured(): void
    {
        $config = $this->config;
        $config['bot_detection'] = ['user_agents' => ['my-crawler']];
        $this->useConfig($config);

        $_SERVER['HTTP_USER_AGENT'] = 'my-crawler/1.0';
        $this->request(query: ['token' => 'anything']);
        $this->controller()->verify();

        $this->assertTrue($this->app->haltCalled);
        $this->assertSame(404, $this->app->haltCode);
    }

    // -----------------------------------------------------------------
    // record_login_attempt levels
    // -----------------------------------------------------------------

    #[Test]
    public function theDefaultRecordLevelWritesNothing(): void
    {
        $config = $this->config;
        unset($config['record_login_attempt']);
        $this->useConfig($config);

        $this->request(query: ['token' => 'nope']);
        $this->controller()->verify();

        $this->assertSame(0, $this->loginCount());
    }

    #[Test]
    public function theAllLevelWritesAFailedAttempt(): void
    {
        $config = $this->config;
        $config['record_login_attempt'] = 'all';
        $this->useConfig($config);

        $this->request(query: ['token' => 'nope']);
        $this->controller()->verify();

        $row = $this->onlyLoginRow();
        $this->assertSame(0, (int) $row['success']);
        $this->assertSame(hash('sha256', 'nope'), $row['identifier']);
        $this->assertSame('10.0.0.1', $row['ip_address']);
    }

    #[Test]
    public function theNoneLevelWritesNothing(): void
    {
        $config = $this->config;
        $config['record_login_attempt'] = 'none';
        $this->useConfig($config);

        $this->request(query: ['token' => 'nope']);
        $this->controller()->verify();

        $this->assertSame(0, $this->loginCount());
    }

    #[Test]
    public function theFailureLevelSkipsASuccessfulLogin(): void
    {
        $user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);
        $this->seedMagicIdentity($user, 'good-token');

        $config = $this->config;
        $config['record_login_attempt'] = 'failure';
        $this->useConfig($config);

        $this->request(query: ['token' => 'good-token']);
        $this->controller()->verify();

        $this->assertSame(['/'], $this->app->redirects);
        $this->assertSame(0, $this->loginCount());
    }

    #[Test]
    public function theFailureLevelStillWritesAFailedLogin(): void
    {
        $config = $this->config;
        $config['record_login_attempt'] = 'failure';
        $this->useConfig($config);

        $this->request(query: ['token' => 'nope']);
        $this->controller()->verify();

        $row = $this->onlyLoginRow();
        $this->assertSame(0, (int) $row['success']);
    }

    #[Test]
    public function theAllLevelWritesASuccessfulLogin(): void
    {
        $user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);
        $this->seedMagicIdentity($user, 'good-token');

        $config = $this->config;
        $config['record_login_attempt'] = 'all';
        $this->useConfig($config);

        $this->request(query: ['token' => 'good-token']);
        $this->controller()->verify();

        $row = $this->onlyLoginRow();
        $this->assertSame(1, (int) $row['success']);
        $this->assertSame($user->id, (int) $row['user_id']);
    }

    #[Test]
    public function aSuccessfulLoginRecordsTheUserAgent(): void
    {
        $user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);
        $this->seedMagicIdentity($user, 'good-token');

        $config = $this->config;
        $config['record_login_attempt'] = 'all';
        $this->useConfig($config);

        $_SERVER['HTTP_USER_AGENT'] = 'TestAgent/1.0';
        $this->request(query: ['token' => 'good-token']);
        $this->controller()->verify();

        $this->assertSame('TestAgent/1.0', $this->onlyLoginRow()['user_agent']);
    }

    // -----------------------------------------------------------------
    // Action redirect
    // -----------------------------------------------------------------

    #[Test]
    public function aNonTwoFactorActionRedirectsHome(): void
    {
        $config = $this->config;
        $config['actions']['login'] = NonTwoFactorAction::class;
        $this->useConfig($config);

        $user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);
        $this->seedMagicIdentity($user, 'action-token');
        $this->request(query: ['token' => 'action-token']);

        $this->controller()->verify();

        $this->assertSame(['/'], $this->app->redirects);
    }

    #[Test]
    public function theTwoFactorActionRedirectsToTheTwoFactorPage(): void
    {
        $config = $this->config;
        $config['actions']['login'] = Email2FA::class;
        $this->useConfig($config);

        $user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);
        $this->seedMagicIdentity($user, 'twofa-token');
        $this->request(query: ['token' => 'twofa-token']);

        $this->controller()->verify();

        $this->assertSame(['/auth/2fa'], $this->app->redirects);
    }
}
