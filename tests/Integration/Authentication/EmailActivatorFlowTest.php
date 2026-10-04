<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Integration\Authentication;

use Enlivenapp\FlightShield\Authentication\Actions\EmailActivator;
use Enlivenapp\FlightShield\Authentication\Actions\Email2FA;
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
 * Email activation: minting a token, resolving it, and the link it points at.
 */
#[CoversClass(EmailActivator::class)]
class EmailActivatorFlowTest extends TestCase
{
    private const CONFIG_KEY = 'enlivenapp.flight-shield';

    protected PDO $pdo;
    protected ControllerSpyEngine $app;
    protected Auth $auth;
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
     */
    private function request(array $query = []): void
    {
        $this->app->requestStub = (object) [
            'query' => (object) $query,
            'data'  => (object) [],
        ];
    }

    private function useConfig(array $config): void
    {
        $this->config = $config;
        $this->app->set(self::CONFIG_KEY, $config);
        $this->auth = new Auth($this->app, $config);
        $this->app->authStub = $this->auth;
    }

    /**
     * Insert an activation identity and return the raw token.
     */
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

    // -----------------------------------------------------------------
    // begin()
    // -----------------------------------------------------------------

    #[Test]
    public function beginMintsATokenAndSendsTheLink(): void
    {
        (new EmailActivator())->begin($this->user, $this->app);

        $this->assertCount(1, $this->sent);
        $this->assertSame('user@example.com', $this->sent[0]['to']);
        $this->assertSame(1, $this->activationIdentityCount());
    }

    #[Test]
    public function beginReplacesAnyPreviousToken(): void
    {
        (new EmailActivator())->begin($this->user, $this->app);
        (new EmailActivator())->begin($this->user, $this->app);

        $this->assertSame(1, $this->activationIdentityCount());
    }

    #[Test]
    public function beginThrowsWhenNoSenderIsConfigured(): void
    {
        $config = $this->config;
        $config['email_sender'] = null;
        $this->useConfig($config);

        $this->expectException(\RuntimeException::class);

        (new EmailActivator())->begin($this->user, $this->app);
    }

    // -----------------------------------------------------------------
    // consume()
    // -----------------------------------------------------------------

    #[Test]
    public function consumeReturnsTheUserForAValidToken(): void
    {
        $raw = $this->seedToken($this->user);

        $result = (new EmailActivator())->consume($raw);

        $this->assertTrue($result->isOK());
        $this->assertSame($this->user->id, $result->extraInfo()->id);
    }

    #[Test]
    public function consumeBurnsTheTokenSoItCannotBeReused(): void
    {
        $raw = $this->seedToken($this->user);

        (new EmailActivator())->consume($raw);

        $this->assertSame(0, $this->activationIdentityCount());
    }

    #[Test]
    public function consumeRejectsAnUnknownToken(): void
    {
        $result = (new EmailActivator())->consume('nope');

        $this->assertFalse($result->isOK());
        $this->assertSame('Invalid or already used activation token.', $result->reason());
    }

    #[Test]
    public function consumeRejectsAnExpiredTokenAndDeletesIt(): void
    {
        $raw = $this->seedToken($this->user, '-1 hour');

        $result = (new EmailActivator())->consume($raw);

        $this->assertFalse($result->isOK());
        $this->assertSame('The activation token has expired.', $result->reason());
        $this->assertSame(0, $this->activationIdentityCount());
    }

    #[Test]
    public function getTypeIsTheActivationType(): void
    {
        $this->assertSame(
            Session::ID_TYPE_EMAIL_ACTIVATE,
            (new EmailActivator())->getType()
        );
    }

    // -----------------------------------------------------------------
    // verify()
    // -----------------------------------------------------------------

    #[Test]
    public function verifyActivatesTheAccountAndLogsIn(): void
    {
        $pending = TestHelper::createUser($this->pdo, 'pending@example.com', 'Str0ng!Passw0rd', 'pending', false);
        $raw = $this->seedToken($pending);
        $this->request(query: ['token' => $raw]);

        (new EmailActivator())->verify($this->app);

        $this->assertSame(['/'], $this->app->redirects);
        $reloaded = (new User($this->pdo))->findById($pending->id);
        $this->assertTrue($reloaded->isActivated());
    }

    #[Test]
    public function verifyRendersAnErrorForABadToken(): void
    {
        $this->request(query: ['token' => 'nope']);

        (new EmailActivator())->verify($this->app);

        $this->assertSame('activate', $this->app->viewFetched[0]['template']);
        $this->assertArrayHasKey('error', $this->app->viewFetched[0]['data']);
    }

    #[Test]
    public function verifyRejectsABannedAccount(): void
    {
        $banned = TestHelper::createUser($this->pdo, 'banned@example.com', 'Str0ng!Passw0rd', 'banned', false);
        $this->pdo->exec("UPDATE users SET status = 'banned' WHERE id = {$banned->id}");
        $raw = $this->seedToken($banned);
        $this->request(query: ['token' => $raw]);

        (new EmailActivator())->verify($this->app);

        $this->assertSame(['/auth/login'], $this->app->redirects);
    }

    #[Test]
    public function verify404sForARobot(): void
    {
        $_SERVER['HTTP_USER_AGENT'] = 'Googlebot/2.1';
        $this->request(query: ['token' => 'anything']);

        (new EmailActivator())->verify($this->app);

        $this->assertTrue($this->app->haltCalled);
    }

    #[Test]
    public function verifyRedirectsToTwoFactorWhenALoginActionApplies(): void
    {
        $config = $this->config;
        $config['actions']['login'] = Email2FA::class;
        $this->useConfig($config);

        $pending = TestHelper::createUser($this->pdo, 'pending@example.com', 'Str0ng!Passw0rd', 'pending', false);
        $raw = $this->seedToken($pending);
        $this->request(query: ['token' => $raw]);

        (new EmailActivator())->verify($this->app);

        $this->assertSame(['/auth/2fa'], $this->app->redirects);
    }
}
