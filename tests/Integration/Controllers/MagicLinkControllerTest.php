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
 * The magic-link flow: form, token issue, token verify, bot rejection and
 * the activation of an inactive account.
 */
#[CoversClass(MagicLinkController::class)]
class MagicLinkControllerTest extends TestCase
{
    private const CONFIG_KEY = 'enlivenapp.flight-shield';

    protected PDO $pdo;
    protected ControllerSpyEngine $app;
    protected Auth $auth;
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

    // -----------------------------------------------------------------
    // showLoginForm()
    // -----------------------------------------------------------------

    #[Test]
    public function showLoginFormRendersTheForm(): void
    {
        $this->controller()->showLoginForm();

        $this->assertSame('magic_link_login', $this->app->rendered[0]['template']);
    }

    #[Test]
    public function showLoginFormRedirectsWhenDisabled(): void
    {
        $config = $this->config;
        $config['allow_magic_link'] = false;
        $this->useConfig($config);

        $this->controller()->showLoginForm();

        $this->assertSame(['/auth/login'], $this->app->redirects);
    }

    #[Test]
    public function showLoginFormRedirectsALoggedInUser(): void
    {
        $user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);
        $this->auth->setAuthenticator('session')->login($user);

        $this->controller()->showLoginForm();

        $this->assertSame(['/'], $this->app->redirects);
    }

    // -----------------------------------------------------------------
    // sendMagicLink()
    // -----------------------------------------------------------------

    #[Test]
    public function sendMagicLinkEmailsALinkForAKnownAddress(): void
    {
        TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);
        $this->request(data: ['email' => 'user@example.com']);

        $this->controller()->sendMagicLink();

        $this->assertCount(1, $this->sent);
        $this->assertSame('user@example.com', $this->sent[0]['to']);
        $this->assertSame('magic_link_message', $this->app->rendered[0]['template']);
        $this->assertSame(
            1,
            (int) $this->pdo->query("SELECT COUNT(*) FROM auth_identities WHERE type = '" . UserIdentity::TYPE_MAGIC_LINK . "'")->fetchColumn()
        );
    }

    #[Test]
    public function sendMagicLinkIsSilentForAnUnknownAddress(): void
    {
        $this->request(data: ['email' => 'ghost@example.com']);

        $this->controller()->sendMagicLink();

        $this->assertSame([], $this->sent);
        $this->assertSame('magic_link_message', $this->app->rendered[0]['template']);
    }

    #[Test]
    public function sendMagicLinkRedirectsWhenDisabled(): void
    {
        $config = $this->config;
        $config['allow_magic_link'] = false;
        $this->useConfig($config);

        $this->controller()->sendMagicLink();

        $this->assertSame(['/auth/login'], $this->app->redirects);
        $this->assertSame([], $this->sent);
    }

    // -----------------------------------------------------------------
    // verify()
    // -----------------------------------------------------------------

    #[Test]
    public function verifyLogsInWithAValidToken(): void
    {
        $user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);
        $this->seedMagicIdentity($user, 'good-token');
        $this->request(query: ['token' => 'good-token']);

        $this->controller()->verify();

        $this->assertSame(['/'], $this->app->redirects);
        $this->assertTrue($this->auth->setAuthenticator('session')->loggedIn());
    }

    #[Test]
    public function verifyRejectsAnUnknownToken(): void
    {
        $this->request(query: ['token' => 'nope']);

        $this->controller()->verify();

        $this->assertSame(['/auth/login'], $this->app->redirects);
        $this->assertSame(
            1,
            (int) $this->pdo->query("SELECT COUNT(*) FROM auth_logins WHERE id_type = '" . UserIdentity::TYPE_MAGIC_LINK . "'")->fetchColumn()
        );
    }

    #[Test]
    public function verifyRejectsAnExpiredToken(): void
    {
        $user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);
        $this->seedMagicIdentity($user, 'old-token', '-1 hour');
        $this->request(query: ['token' => 'old-token']);

        $this->controller()->verify();

        $this->assertSame(['/auth/login'], $this->app->redirects);
    }

    #[Test]
    public function verify404sForARobot(): void
    {
        $_SERVER['HTTP_USER_AGENT'] = 'Googlebot/2.1';
        $this->request(query: ['token' => 'anything']);

        $this->controller()->verify();

        $this->assertTrue($this->app->haltCalled);
        $this->assertSame([], $this->app->redirects);
    }

    #[Test]
    public function verifyActivatesAnInactiveAccount(): void
    {
        $user = TestHelper::createUser($this->pdo, 'pending@example.com', 'Str0ng!Passw0rd', 'pending', false);
        $this->seedMagicIdentity($user, 'activate-token');
        $this->request(query: ['token' => 'activate-token']);

        $this->controller()->verify();

        $this->assertSame(['/'], $this->app->redirects);

        $reloaded = (new User($this->pdo))->findById($user->id);
        $this->assertTrue($reloaded->isActivated());
    }

    #[Test]
    public function verifyRedirectsToTwoFactorWhenALoginActionApplies(): void
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

    #[Test]
    public function verifyRedirectsWhenDisabled(): void
    {
        $config = $this->config;
        $config['allow_magic_link'] = false;
        $this->useConfig($config);

        $this->controller()->verify();

        $this->assertSame(['/auth/login'], $this->app->redirects);
    }
}
