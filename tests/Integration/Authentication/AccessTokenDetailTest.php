<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Integration\Authentication;

use Enlivenapp\FlightShield\Authentication\Authenticators\AccessTokens;
use Enlivenapp\FlightShield\Models\User;
use Enlivenapp\FlightShield\Models\UserIdentity;
use Enlivenapp\FlightShield\Tests\TestHelper;
use PDO;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The access-token details the flow tests leave open: the token-log rows,
 * the disuse boundary, the header name mapping, and the loggedIn cache.
 */
#[CoversClass(AccessTokens::class)]
class AccessTokenDetailTest extends TestCase
{
    protected PDO $pdo;
    protected User $user;
    protected AccessTokens $auth;

    /** @var array<string, mixed> */
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
        unset(
            $_SERVER['REMOTE_ADDR'],
            $_SERVER['HTTP_AUTHORIZATION'],
            $_SERVER['HTTP_X_API_KEY'],
            $_SERVER['HTTP_USER_AGENT']
        );
    }

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

    private function tokenLoginCount(): int
    {
        return (int) $this->pdo->query('SELECT COUNT(*) FROM auth_token_logins')->fetchColumn();
    }

    /**
     * @return array<string, mixed>
     */
    private function onlyTokenLogin(): array
    {
        $rows = $this->pdo->query('SELECT * FROM auth_token_logins ORDER BY id')->fetchAll(PDO::FETCH_ASSOC);
        $this->assertCount(1, $rows);

        return $rows[0];
    }

    // -----------------------------------------------------------------
    // Token format
    // -----------------------------------------------------------------

    #[Test]
    public function theBearerPrefixIsStripped(): void
    {
        $raw = $this->makeToken();

        $this->assertTrue($this->auth->check(['token' => 'Bearer ' . $raw])->isOK());
    }

    #[Test]
    public function aBareTokenIsAccepted(): void
    {
        $raw = $this->makeToken();

        $this->assertTrue($this->auth->check(['token' => $raw])->isOK());
    }

    #[Test]
    public function aTokenWithTheWrongPrefixLengthIsRejected(): void
    {
        $raw = $this->makeToken();

        // 'Bear' is not the 'Bearer' prefix, so the raw value is used as-is.
        $this->assertFalse($this->auth->check(['token' => 'Bear ' . $raw])->isOK());
    }

    // -----------------------------------------------------------------
    // The disuse boundary
    // -----------------------------------------------------------------

    #[Test]
    public function aTokenInsideTheUnusedLifetimeIsAccepted(): void
    {
        $raw = $this->makeToken(1800);

        $this->config['unused_token_lifetime'] = 3600;
        $auth = new AccessTokens(\Flight::app(), $this->config);

        $this->assertTrue($auth->check(['token' => $raw])->isOK());
    }

    #[Test]
    public function aTokenOutsideTheUnusedLifetimeIsRejected(): void
    {
        $raw = $this->makeToken(3700);

        $this->config['unused_token_lifetime'] = 3600;
        $auth = new AccessTokens(\Flight::app(), $this->config);

        $result = $auth->check(['token' => $raw]);

        $this->assertFalse($result->isOK());
        $this->assertSame('Token has expired from disuse.', $result->reason());
    }

    #[Test]
    public function aZeroUnusedLifetimeDisablesTheCheck(): void
    {
        $raw = $this->makeToken(7200);

        $this->config['unused_token_lifetime'] = 0;
        $auth = new AccessTokens(\Flight::app(), $this->config);

        $this->assertTrue($auth->check(['token' => $raw])->isOK());
    }

    #[Test]
    public function aTokenWithNoLastUsedDateSkipsTheLifetimeCheck(): void
    {
        $raw = $this->makeToken();
        $hash = hash('sha256', $raw);
        $this->pdo->exec("UPDATE auth_identities SET last_used_at = NULL WHERE secret = '{$hash}'");

        $this->config['unused_token_lifetime'] = 1;
        $auth = new AccessTokens(\Flight::app(), $this->config);

        $this->assertTrue($auth->check(['token' => $raw])->isOK());
    }

    #[Test]
    public function aSuccessfulCheckTouchesTheLastUsedDate(): void
    {
        $raw = $this->makeToken();
        $hash = hash('sha256', $raw);
        $this->pdo->exec("UPDATE auth_identities SET last_used_at = NULL WHERE secret = '{$hash}'");

        $this->auth->check(['token' => $raw]);

        $lastUsed = $this->pdo->query("SELECT last_used_at FROM auth_identities WHERE secret = '{$hash}'")->fetchColumn();
        $this->assertNotNull($lastUsed);
    }

    // -----------------------------------------------------------------
    // Token log rows
    // -----------------------------------------------------------------

    #[Test]
    public function aFailedCheckWritesNoTokenLogRow(): void
    {
        $this->auth->check(['token' => 'nope']);

        $this->assertSame(0, $this->tokenLoginCount());
    }

    #[Test]
    public function aSuccessfulAttemptWritesASuccessRow(): void
    {
        $raw = $this->makeToken();

        $this->auth->attempt(['token' => $raw]);

        $row = $this->onlyTokenLogin();
        $this->assertSame(1, (int) $row['success']);
        $this->assertSame($this->user->id, (int) $row['user_id']);
        $this->assertSame('10.0.0.1', $row['ip_address']);
    }

    #[Test]
    public function aBannedAttemptWritesAFailureRow(): void
    {
        $raw = $this->makeToken();
        $this->pdo->exec("UPDATE users SET status = 'banned' WHERE id = {$this->user->id}");

        $this->auth->attempt(['token' => $raw]);

        $row = $this->onlyTokenLogin();
        $this->assertSame(0, (int) $row['success']);
        $this->assertSame($this->user->id, (int) $row['user_id']);
    }

    #[Test]
    public function aFailedAttemptWritesAFailureRow(): void
    {
        $this->auth->attempt(['token' => 'nope']);

        $row = $this->onlyTokenLogin();
        $this->assertSame(0, (int) $row['success']);
        $this->assertNull($row['user_id']);
    }

    #[Test]
    public function theNoneLevelWritesNoTokenLogRow(): void
    {
        $this->config['record_login_attempt'] = 'none';
        $auth = new AccessTokens(\Flight::app(), $this->config);

        $auth->attempt(['token' => 'nope']);

        $this->assertSame(0, $this->tokenLoginCount());
    }

    #[Test]
    public function theFailureLevelSkipsASuccessfulAttempt(): void
    {
        $raw = $this->makeToken();

        $this->config['record_login_attempt'] = 'failure';
        $auth = new AccessTokens(\Flight::app(), $this->config);

        $auth->attempt(['token' => $raw]);

        $this->assertSame(0, $this->tokenLoginCount());
    }

    #[Test]
    public function theFailureLevelStillWritesAFailedAttempt(): void
    {
        $this->config['record_login_attempt'] = 'failure';
        $auth = new AccessTokens(\Flight::app(), $this->config);

        $auth->attempt(['token' => 'nope']);

        $this->assertSame(1, $this->tokenLoginCount());
    }

    #[Test]
    public function aTokenLogRowRecordsTheUserAgent(): void
    {
        $_SERVER['HTTP_USER_AGENT'] = 'TestAgent/1.0';

        $this->auth->attempt(['token' => 'nope']);

        $this->assertSame('TestAgent/1.0', $this->onlyTokenLogin()['user_agent']);
    }

    #[Test]
    public function aTokenLogRowFallsBackToTheDefaultIpAddress(): void
    {
        unset($_SERVER['REMOTE_ADDR']);

        $this->auth->attempt(['token' => 'nope']);

        $this->assertSame('0.0.0.0', $this->onlyTokenLogin()['ip_address']);
    }

    // -----------------------------------------------------------------
    // loggedIn()
    // -----------------------------------------------------------------

    #[Test]
    public function loggedInUsesTheConfiguredHeaderName(): void
    {
        $raw = $this->makeToken();

        $this->config['token_header'] = 'X-Api-Key';
        $auth = new AccessTokens(\Flight::app(), $this->config);

        $_SERVER['HTTP_X_API_KEY'] = $raw;

        $this->assertTrue($auth->loggedIn());
    }

    #[Test]
    public function loggedInFallsBackToTheAuthorizationHeader(): void
    {
        $raw = $this->makeToken();

        unset($this->config['token_header']);
        $auth = new AccessTokens(\Flight::app(), $this->config);

        $_SERVER['HTTP_AUTHORIZATION'] = $raw;

        $this->assertTrue($auth->loggedIn());
    }

    #[Test]
    public function loggedInIsCachedAfterAFailure(): void
    {
        $this->assertFalse($this->auth->loggedIn());

        // A valid token now arrives, but the failed check is remembered.
        $raw = $this->makeToken();
        $_SERVER['HTTP_AUTHORIZATION'] = $raw;

        $this->assertFalse($this->auth->loggedIn());
    }

    #[Test]
    public function loggedInIsFalseForABannedUser(): void
    {
        $raw = $this->makeToken();
        $this->pdo->exec("UPDATE users SET status = 'banned' WHERE id = {$this->user->id}");

        $_SERVER['HTTP_AUTHORIZATION'] = $raw;

        $this->assertFalse($this->auth->loggedIn());
    }

    #[Test]
    public function loggedInIsTrueOnceAUserIsSet(): void
    {
        $this->auth->login($this->user);

        $this->assertTrue($this->auth->loggedIn());
    }

    // -----------------------------------------------------------------
    // recordActiveDate()
    // -----------------------------------------------------------------

    #[Test]
    public function recordActiveDateWritesForAnActiveUser(): void
    {
        $this->auth->login($this->user);
        $this->auth->recordActiveDate();

        $this->assertNotNull(
            $this->pdo->query("SELECT last_active FROM users WHERE id = {$this->user->id}")->fetchColumn()
        );
    }

    #[Test]
    public function recordActiveDateIsSkippedForABannedUser(): void
    {
        $this->pdo->exec("UPDATE users SET status = 'banned' WHERE id = {$this->user->id}");
        $banned = (new User($this->pdo))->findById($this->user->id);
        $this->assertNotNull($banned);

        $this->auth->login($banned);
        $this->auth->recordActiveDate();

        $this->assertNull(
            $this->pdo->query("SELECT last_active FROM users WHERE id = {$this->user->id}")->fetchColumn()
        );
    }

    #[Test]
    public function recordActiveDateIsSkippedForAnInactiveUser(): void
    {
        $inactive = TestHelper::createUser($this->pdo, 'inactive@example.com', 'Str0ng!Passw0rd', 'inactive', false);

        $this->auth->login($inactive);
        $this->auth->recordActiveDate();

        $this->assertNull(
            $this->pdo->query("SELECT last_active FROM users WHERE id = {$inactive->id}")->fetchColumn()
        );
    }

    #[Test]
    public function recordActiveDateDoesNothingWhenLoggedOut(): void
    {
        $this->auth->recordActiveDate();

        $this->assertSame(
            0,
            (int) $this->pdo->query('SELECT COUNT(*) FROM users WHERE last_active IS NOT NULL')->fetchColumn()
        );
    }
}
