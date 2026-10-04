<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Integration\Authentication;

use Enlivenapp\FlightShield\Authentication\Actions\EmailActivator;
use Enlivenapp\FlightShield\Authentication\Authenticators\Session;
use Enlivenapp\FlightShield\Auth;
use Enlivenapp\FlightShield\Models\User;
use Enlivenapp\FlightShield\Models\UserIdentity;
use Enlivenapp\FlightShield\Tests\Integration\Controllers\ControllerSpyEngine;
use Enlivenapp\FlightShield\Tests\TestHelper;
use PDO;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The activation details the flow tests leave open: the halt code, the
 * token lookup order, the emailed link, the redirect fallbacks, and the
 * activation write.
 */
#[CoversClass(EmailActivator::class)]
class EmailActivatorDetailTest extends TestCase
{
    private const CONFIG_KEY = 'enlivenapp.flight-shield';

    protected PDO $pdo;
    protected ControllerSpyEngine $app;
    protected Auth $auth;

    /** @var array<string, mixed> */
    protected array $config;

    protected User $user;

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

        $this->app = new ControllerSpyEngine();
        $this->app->set(self::CONFIG_KEY, $this->config);
        $this->auth = new Auth($this->app, $this->config);
        $this->app->authStub = $this->auth;
        $this->request(query: ['token' => '']);

        $this->user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);
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

    private function seedToken(User $user, string $expires = '+1 day'): string
    {
        $raw = bin2hex(random_bytes(8));
        $now = new \DateTimeImmutable();

        $identity = new UserIdentity($this->pdo);
        $identity->user_id    = $user->id;
        $identity->type       = Session::ID_TYPE_EMAIL_ACTIVATE;
        $identity->name       = 'register';
        $identity->secret     = hash('sha256', $raw);
        $identity->secret2    = null;
        $identity->expires    = $now->modify($expires)->format('Y-m-d H:i:s');
        $identity->created_at = $now->format('Y-m-d H:i:s');
        $identity->updated_at = $now->format('Y-m-d H:i:s');
        $identity->insert();

        return $raw;
    }

    private function activationIdentityCount(): int
    {
        return (int) $this->pdo
            ->query("SELECT COUNT(*) FROM auth_identities WHERE type = '" . Session::ID_TYPE_EMAIL_ACTIVATE . "'")
            ->fetchColumn();
    }

    private function tokenFromTheEmail(): string
    {
        $this->assertCount(1, $this->app->viewFetched);

        $url = (string) $this->app->viewFetched[0]['data']['activationUrl'];
        parse_str((string) parse_url($url, PHP_URL_QUERY), $query);

        return (string) ($query['token'] ?? '');
    }

    // -----------------------------------------------------------------
    // begin(): the emailed link
    // -----------------------------------------------------------------

    #[Test]
    public function theEmailedLinkCarriesTheTokenThatActivates(): void
    {
        $pending = TestHelper::createUser($this->pdo, 'pending@example.com', 'Str0ng!Passw0rd', 'pending', false);

        (new EmailActivator())->begin($pending, $this->app);

        $token = $this->tokenFromTheEmail();
        $this->assertSame(40, strlen($token));

        $this->request(query: ['token' => $token]);
        (new EmailActivator())->verify($this->app);

        $this->assertSame(['/'], $this->app->redirects);
        $reloaded = (new User($this->pdo))->findById($pending->id);
        $this->assertTrue($reloaded->isActivated());
    }

    #[Test]
    public function theEmailedLinkUsesTheConfiguredBaseUrl(): void
    {
        $this->app->set('flight.base_url', 'https://example.test/');

        (new EmailActivator())->begin($this->user, $this->app);

        $url = (string) $this->app->viewFetched[0]['data']['activationUrl'];
        $this->assertStringStartsWith('https://example.test/auth/activate/verify?token=', $url);
    }

    #[Test]
    public function theEmailedLinkFallsBackToARelativeUrl(): void
    {
        (new EmailActivator())->begin($this->user, $this->app);

        $url = (string) $this->app->viewFetched[0]['data']['activationUrl'];
        $this->assertStringStartsWith('/auth/activate/verify?token=', $url);
    }

    #[Test]
    public function theEmailCarriesTheRequestDetails(): void
    {
        $_SERVER['REMOTE_ADDR'] = '203.0.113.9';
        $_SERVER['HTTP_USER_AGENT'] = 'TestAgent/1.0';

        (new EmailActivator())->begin($this->user, $this->app);

        $data = $this->app->viewFetched[0]['data'];
        $this->assertSame('203.0.113.9', $data['ipAddress']);
        $this->assertSame('TestAgent/1.0', $data['userAgent']);
        $this->assertSame('Email/email_activate_email', $this->app->viewFetched[0]['template']);
        $this->assertSame('Activate Your Account', $this->sent[0]['subject']);
        $this->assertSame('user@example.com', $this->sent[0]['to']);
    }

    #[Test]
    public function theEmailFallsBackToTheDefaultIpAddress(): void
    {
        unset($_SERVER['REMOTE_ADDR']);

        (new EmailActivator())->begin($this->user, $this->app);

        $this->assertSame('0.0.0.0', $this->app->viewFetched[0]['data']['ipAddress']);
    }

    #[Test]
    public function theEmailFallsBackToAnEmptyUserAgent(): void
    {
        unset($_SERVER['HTTP_USER_AGENT']);

        (new EmailActivator())->begin($this->user, $this->app);

        $this->assertSame('', $this->app->viewFetched[0]['data']['userAgent']);
    }

    #[Test]
    public function aNonCallableSenderThrows(): void
    {
        $config = $this->config;
        $config['email_sender'] = 'not-a-callable';
        $this->useConfig($config);

        $this->expectException(\RuntimeException::class);

        (new EmailActivator())->begin($this->user, $this->app);
    }

    #[Test]
    public function theTokenExpiresInTwentyFourHours(): void
    {
        (new EmailActivator())->begin($this->user, $this->app);

        $expires = (string) $this->pdo
            ->query("SELECT expires FROM auth_identities WHERE type = '" . Session::ID_TYPE_EMAIL_ACTIVATE . "'")
            ->fetchColumn();

        $this->assertEqualsWithDelta(24 * 3600, (int) strtotime($expires) - time(), 30);
    }

    #[Test]
    public function theTokenIsStoredHashed(): void
    {
        (new EmailActivator())->begin($this->user, $this->app);

        $token = $this->tokenFromTheEmail();
        $stored = (string) $this->pdo
            ->query("SELECT secret FROM auth_identities WHERE type = '" . Session::ID_TYPE_EMAIL_ACTIVATE . "'")
            ->fetchColumn();

        $this->assertSame(hash('sha256', $token), $stored);
        $this->assertNotSame($token, $stored);
    }

    // -----------------------------------------------------------------
    // verify(): token lookup and halt
    // -----------------------------------------------------------------

    #[Test]
    public function verifyReadsTheTokenFromTheQueryString(): void
    {
        $pending = TestHelper::createUser($this->pdo, 'pending@example.com', 'Str0ng!Passw0rd', 'pending', false);
        $raw = $this->seedToken($pending);
        $this->request(query: ['token' => $raw]);

        (new EmailActivator())->verify($this->app);

        $this->assertSame(['/'], $this->app->redirects);
    }

    #[Test]
    public function verifyFallsBackToThePostedToken(): void
    {
        $pending = TestHelper::createUser($this->pdo, 'pending@example.com', 'Str0ng!Passw0rd', 'pending', false);
        $raw = $this->seedToken($pending);
        $this->request(query: [], data: ['token' => $raw]);

        (new EmailActivator())->verify($this->app);

        $this->assertSame(['/'], $this->app->redirects);
    }

    #[Test]
    public function verifyPrefersTheQueryTokenOverThePostedOne(): void
    {
        $pending = TestHelper::createUser($this->pdo, 'pending@example.com', 'Str0ng!Passw0rd', 'pending', false);
        $raw = $this->seedToken($pending);
        $this->request(query: ['token' => $raw], data: ['token' => 'wrong']);

        (new EmailActivator())->verify($this->app);

        $this->assertSame(['/'], $this->app->redirects);
    }

    #[Test]
    public function verifyHaltsWithA404ForARobot(): void
    {
        $_SERVER['HTTP_USER_AGENT'] = 'Googlebot/2.1';
        $this->request(query: ['token' => 'anything']);

        (new EmailActivator())->verify($this->app);

        $this->assertTrue($this->app->haltCalled);
        $this->assertSame(404, $this->app->haltCode);
    }

    #[Test]
    public function verifyReturnsAnEmptyStringForARobot(): void
    {
        $_SERVER['HTTP_USER_AGENT'] = 'Googlebot/2.1';

        $this->assertSame('', (new EmailActivator())->verify($this->app));
    }

    #[Test]
    public function verifyRendersTheConsumeReason(): void
    {
        $this->request(query: ['token' => 'nope']);

        (new EmailActivator())->verify($this->app);

        $this->assertSame(
            'Invalid or already used activation token.',
            $this->app->viewFetched[0]['data']['error']
        );
    }

    // -----------------------------------------------------------------
    // verify(): redirects
    // -----------------------------------------------------------------

    #[Test]
    public function verifyUsesTheConfiguredLoginRedirectForABannedUser(): void
    {
        $config = $this->config;
        $config['redirects']['login'] = '/custom/login';
        $this->useConfig($config);

        $banned = TestHelper::createUser($this->pdo, 'banned@example.com', 'Str0ng!Passw0rd', 'banned', false);
        $this->pdo->exec("UPDATE users SET status = 'banned' WHERE id = {$banned->id}");
        $raw = $this->seedToken($banned);
        $this->request(query: ['token' => $raw]);

        (new EmailActivator())->verify($this->app);

        $this->assertSame(['/custom/login'], $this->app->redirects);
    }

    #[Test]
    public function verifyFallsBackToTheDefaultLoginRedirectForABannedUser(): void
    {
        unset($this->config['redirects']['login']);
        $this->app->set(self::CONFIG_KEY, $this->config);

        $banned = TestHelper::createUser($this->pdo, 'banned@example.com', 'Str0ng!Passw0rd', 'banned', false);
        $this->pdo->exec("UPDATE users SET status = 'banned' WHERE id = {$banned->id}");
        $raw = $this->seedToken($banned);
        $this->request(query: ['token' => $raw]);

        (new EmailActivator())->verify($this->app);

        $this->assertSame(['/auth/login'], $this->app->redirects);
    }

    #[Test]
    public function verifyUsesTheConfiguredAfterRegisterRedirect(): void
    {
        $config = $this->config;
        $config['redirects']['after_register'] = '/welcome';
        $this->useConfig($config);

        $pending = TestHelper::createUser($this->pdo, 'pending@example.com', 'Str0ng!Passw0rd', 'pending', false);
        $raw = $this->seedToken($pending);
        $this->request(query: ['token' => $raw]);

        (new EmailActivator())->verify($this->app);

        $this->assertSame(['/welcome'], $this->app->redirects);
    }

    #[Test]
    public function verifyFallsBackToTheRootAfterRegisterRedirect(): void
    {
        unset($this->config['redirects']['after_register']);
        $this->app->set(self::CONFIG_KEY, $this->config);

        $pending = TestHelper::createUser($this->pdo, 'pending@example.com', 'Str0ng!Passw0rd', 'pending', false);
        $raw = $this->seedToken($pending);
        $this->request(query: ['token' => $raw]);

        (new EmailActivator())->verify($this->app);

        $this->assertSame(['/'], $this->app->redirects);
    }

    // -----------------------------------------------------------------
    // verify(): the activation write
    // -----------------------------------------------------------------

    #[Test]
    public function verifyPersistsTheActivation(): void
    {
        $pending = TestHelper::createUser($this->pdo, 'pending@example.com', 'Str0ng!Passw0rd', 'pending', false);
        $raw = $this->seedToken($pending);
        $this->request(query: ['token' => $raw]);

        (new EmailActivator())->verify($this->app);

        $this->assertSame(
            1,
            (int) $this->pdo->query("SELECT active FROM users WHERE id = {$pending->id}")->fetchColumn()
        );
    }

    #[Test]
    public function verifyUpdatesTheTimestampOnActivation(): void
    {
        $pending = TestHelper::createUser($this->pdo, 'pending@example.com', 'Str0ng!Passw0rd', 'pending', false);
        $this->pdo->exec("UPDATE users SET updated_at = '2000-01-01 00:00:00' WHERE id = {$pending->id}");
        $raw = $this->seedToken($pending);
        $this->request(query: ['token' => $raw]);

        (new EmailActivator())->verify($this->app);

        $updatedAt = (string) $this->pdo->query("SELECT updated_at FROM users WHERE id = {$pending->id}")->fetchColumn();
        $this->assertNotSame('2000-01-01 00:00:00', $updatedAt);
    }

    #[Test]
    public function verifyLeavesAnAlreadyActiveAccountAlone(): void
    {
        $raw = $this->seedToken($this->user);
        $this->request(query: ['token' => $raw]);

        (new EmailActivator())->verify($this->app);

        $this->assertSame(['/'], $this->app->redirects);
        $this->assertSame(1, (int) $this->pdo->query("SELECT active FROM users WHERE id = {$this->user->id}")->fetchColumn());
    }

    #[Test]
    public function verifyLogsTheUserIn(): void
    {
        $pending = TestHelper::createUser($this->pdo, 'pending@example.com', 'Str0ng!Passw0rd', 'pending', false);
        $raw = $this->seedToken($pending);
        $this->request(query: ['token' => $raw]);

        (new EmailActivator())->verify($this->app);

        $this->assertTrue($this->auth->setAuthenticator('session')->loggedIn());
    }

    #[Test]
    public function verifyBurnsTheToken(): void
    {
        $pending = TestHelper::createUser($this->pdo, 'pending@example.com', 'Str0ng!Passw0rd', 'pending', false);
        $raw = $this->seedToken($pending);
        $this->request(query: ['token' => $raw]);

        (new EmailActivator())->verify($this->app);

        $this->assertSame(0, $this->activationIdentityCount());
    }

    #[Test]
    public function verifyRejectsAReusedToken(): void
    {
        $pending = TestHelper::createUser($this->pdo, 'pending@example.com', 'Str0ng!Passw0rd', 'pending', false);
        $raw = $this->seedToken($pending);
        $this->request(query: ['token' => $raw]);

        (new EmailActivator())->verify($this->app);

        $this->app->redirects = [];
        (new EmailActivator())->verify($this->app);

        $this->assertSame([], $this->app->redirects);
        $this->assertSame('activate', $this->app->viewFetched[0]['template']);
    }
}
