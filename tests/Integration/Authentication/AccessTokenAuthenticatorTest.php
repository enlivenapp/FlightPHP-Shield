<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Integration\Authentication;

use Enlivenapp\FlightShield\Authentication\Authenticators\AccessTokens;
use Enlivenapp\FlightShield\Exceptions\AuthenticationException;
use Enlivenapp\FlightShield\Models\User;
use Enlivenapp\FlightShield\Models\UserIdentity;
use Enlivenapp\FlightShield\Tests\TestHelper;
use PDO;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Bearer token authentication: header parsing, expiry, disuse and the
 * login/logout lifecycle.
 */
#[CoversClass(AccessTokens::class)]
class AccessTokenAuthenticatorTest extends TestCase
{
    protected PDO $pdo;
    protected User $user;
    protected AccessTokens $auth;
    protected array $config;

    protected function setUp(): void
    {
        $this->pdo = TestHelper::createDatabase();
        TestHelper::resetFlight();
        TestHelper::registerFlightDb($this->pdo);

        $_SERVER['REMOTE_ADDR'] = '10.0.0.1';

        $this->config = TestHelper::getConfig();
        $this->user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);
        $this->auth = new AccessTokens(\Flight::app(), $this->config);
    }

    protected function tearDown(): void
    {
        TestHelper::resetFlight();
        unset($_SERVER['REMOTE_ADDR'], $_SERVER['HTTP_AUTHORIZATION']);
    }

    /**
     * Mint a token and optionally age its last_used_at.
     */
    private function makeToken(int $unusedSeconds = 0, ?\DateTimeImmutable $expires = null): string
    {
        $token = (new UserIdentity($this->pdo))->generateAccessToken($this->user, 'test', [], $expires);
        $raw = $token->rawToken;

        if ($unusedSeconds > 0) {
            $old = (new \DateTimeImmutable())->modify("-{$unusedSeconds} seconds")->format('Y-m-d H:i:s');
            $hash = hash('sha256', $raw);
            $this->pdo->exec("UPDATE auth_identities SET last_used_at = '{$old}' WHERE secret = '{$hash}'");
        }

        return $raw;
    }

    private function lastActive(): mixed
    {
        return $this->pdo->query("SELECT last_active FROM users WHERE id = {$this->user->id}")->fetchColumn();
    }

    // -----------------------------------------------------------------
    // check()
    // -----------------------------------------------------------------

    #[Test]
    public function checkWithoutATokenFails(): void
    {
        $result = $this->auth->check([]);

        $this->assertFalse($result->isOK());
        $this->assertSame('No token provided.', $result->reason());
    }

    #[Test]
    public function checkWithAnEmptyTokenFails(): void
    {
        $this->assertSame('No token provided.', $this->auth->check(['token' => ''])->reason());
    }

    #[Test]
    public function checkWithAnUnknownTokenFails(): void
    {
        $result = $this->auth->check(['token' => 'nope']);

        $this->assertFalse($result->isOK());
        $this->assertSame('Invalid token.', $result->reason());
    }

    #[Test]
    public function checkWithAValidTokenReturnsTheUserAndToken(): void
    {
        $raw = $this->makeToken();

        $result = $this->auth->check(['token' => $raw]);

        $this->assertTrue($result->isOK());

        $user = $result->extraInfo();
        $this->assertSame($this->user->id, $user->id);
        $this->assertNotNull($user->currentAccessToken());
    }

    #[Test]
    public function checkStripsTheBearerPrefix(): void
    {
        $raw = $this->makeToken();

        $this->assertTrue($this->auth->check(['token' => 'Bearer ' . $raw])->isOK());
    }

    #[Test]
    public function checkRejectsAnExpiredToken(): void
    {
        $raw = $this->makeToken(0, new \DateTimeImmutable('-1 hour'));

        $result = $this->auth->check(['token' => $raw]);

        $this->assertFalse($result->isOK());
        $this->assertSame('Token has expired.', $result->reason());
    }

    #[Test]
    public function checkRejectsATokenUnusedForLongerThanTheLifetime(): void
    {
        $raw = $this->makeToken(7200);

        $this->config['unused_token_lifetime'] = 3600;
        $auth = new AccessTokens(\Flight::app(), $this->config);

        $result = $auth->check(['token' => $raw]);

        $this->assertFalse($result->isOK());
        $this->assertSame('Token has expired from disuse.', $result->reason());
    }

    // -----------------------------------------------------------------
    // attempt() / login lifecycle
    // -----------------------------------------------------------------

    #[Test]
    public function attemptLogsTheUserIn(): void
    {
        $raw = $this->makeToken();

        $result = $this->auth->attempt(['token' => $raw]);

        $this->assertTrue($result->isOK());
        $this->assertTrue($this->auth->loggedIn());
        $this->assertSame($this->user->id, $this->auth->getUser()->id);
    }

    #[Test]
    public function attemptFailsForABannedAccount(): void
    {
        $raw = $this->makeToken();
        $this->pdo->exec("UPDATE users SET status = 'banned' WHERE id = {$this->user->id}");

        $result = $this->auth->attempt(['token' => $raw]);

        $this->assertFalse($result->isOK());
        $this->assertSame('Account is not active.', $result->reason());
        $this->assertFalse($this->auth->loggedIn());
    }

    #[Test]
    public function loggedInReadsTheAuthorizationHeader(): void
    {
        $_SERVER['HTTP_AUTHORIZATION'] = 'Bearer ' . $this->makeToken();

        $this->assertTrue($this->auth->loggedIn());
        $this->assertSame($this->user->id, $this->auth->getUser()->id);
    }

    #[Test]
    public function loggedInIsFalseWithoutAHeader(): void
    {
        $this->assertFalse($this->auth->loggedIn());
    }

    #[Test]
    public function loggedInIsFalseForABannedAccount(): void
    {
        $raw = $this->makeToken();
        $this->pdo->exec("UPDATE users SET status = 'banned' WHERE id = {$this->user->id}");
        $_SERVER['HTTP_AUTHORIZATION'] = $raw;

        $this->assertFalse($this->auth->loggedIn());
    }

    #[Test]
    public function logoutClearsTheUser(): void
    {
        $this->auth->attempt(['token' => $this->makeToken()]);
        $this->auth->logout();

        $this->assertNull($this->auth->getUser());
        $this->assertFalse($this->auth->loggedIn());
    }

    #[Test]
    public function loginByIdRejectsAnUnknownUser(): void
    {
        $this->expectException(AuthenticationException::class);

        $this->auth->loginById(999);
    }

    #[Test]
    public function loginByIdLogsInAKnownUser(): void
    {
        $this->auth->loginById($this->user->id);

        $this->assertSame($this->user->id, $this->auth->getUser()->id);
    }

    // -----------------------------------------------------------------
    // recordActiveDate()
    // -----------------------------------------------------------------

    #[Test]
    public function recordActiveDateUpdatesAnActiveUser(): void
    {
        $this->auth->login($this->user);
        $this->auth->recordActiveDate();

        $this->assertNotNull($this->lastActive());
    }

    #[Test]
    public function recordActiveDateSkipsABannedUser(): void
    {
        $this->pdo->exec("UPDATE users SET status = 'banned' WHERE id = {$this->user->id}");
        $this->auth->login((new User($this->pdo))->findById($this->user->id));

        $this->auth->recordActiveDate();

        $this->assertNull($this->lastActive());
    }

    #[Test]
    public function recordActiveDateSkipsAnInactiveUser(): void
    {
        $this->pdo->exec("UPDATE users SET active = 0 WHERE id = {$this->user->id}");
        $this->auth->login((new User($this->pdo))->findById($this->user->id));

        $this->auth->recordActiveDate();

        $this->assertNull($this->lastActive());
    }

    #[Test]
    public function recordActiveDateDoesNothingWhenNobodyIsLoggedIn(): void
    {
        $this->auth->recordActiveDate();

        $this->assertNull($this->auth->getUser());
        $this->assertNull($this->lastActive());
    }
}
