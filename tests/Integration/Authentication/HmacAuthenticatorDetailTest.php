<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Integration\Authentication;

use Enlivenapp\FlightShield\Authentication\Authenticators\HmacSha256;
use Enlivenapp\FlightShield\Models\User;
use Enlivenapp\FlightShield\Models\UserIdentity;
use Enlivenapp\FlightShield\Tests\TestHelper;
use PDO;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * HMAC details the happy-path tests leave open: the token prefix, the
 * timestamp window edges, the method casing, the header name mapping, the
 * token-log rows, and the loggedIn() caching.
 */
#[CoversClass(HmacSha256::class)]
class HmacAuthenticatorDetailTest extends TestCase
{
    protected PDO $pdo;
    protected User $user;
    protected HmacSha256 $auth;

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
        $this->auth = new HmacSha256(\Flight::app(), $this->config);
    }

    protected function tearDown(): void
    {
        TestHelper::resetFlight();
        unset(
            $_SERVER['REMOTE_ADDR'],
            $_SERVER['HTTP_AUTHORIZATION'],
            $_SERVER['HTTP_X_REQUEST_TIMESTAMP'],
            $_SERVER['HTTP_X_CUSTOM_SIG'],
            $_SERVER['REQUEST_METHOD'],
            $_SERVER['REQUEST_URI'],
            $_SERVER['HTTP_USER_AGENT']
        );
    }

    /**
     * @return array{0: string, 1: string}
     */
    private function makeKey(): array
    {
        $token = (new UserIdentity($this->pdo))->generateHmacToken($this->user, 'test', [], null, null);
        $key = $token->rawToken;

        $stmt = $this->pdo->prepare("SELECT secret2 FROM auth_identities WHERE type = 'hmac_sha256' AND secret = ?");
        $stmt->execute([$key]);

        return [$key, (string) $stmt->fetchColumn()];
    }

    private function signature(string $key, string $secret, int $timestamp, string $method = 'GET', string $path = '/api', string $body = ''): string
    {
        $sig = hash_hmac('sha256', $method . "\n" . $path . "\n" . $timestamp . "\n" . $body, $secret);

        return 'HMAC-SHA256 ' . $key . ':' . $sig;
    }

    /**
     * @return array<string, mixed>
     */
    private function credentials(string $token, ?int $timestamp = null, string $method = 'GET', string $path = '/api', string $body = ''): array
    {
        return [
            'token'     => $token,
            'timestamp' => (string) ($timestamp ?? time()),
            'method'    => $method,
            'path'      => $path,
            'body'      => $body,
        ];
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
    public function thePrefixIsStrippedBeforeTheKeyIsRead(): void
    {
        [$key, $secret] = $this->makeKey();
        $ts = time();

        $result = $this->auth->check($this->credentials($this->signature($key, $secret, $ts), $ts));

        $this->assertTrue($result->isOK());
    }

    #[Test]
    public function aBareKeyAndSignatureIsAccepted(): void
    {
        [$key, $secret] = $this->makeKey();
        $ts = time();
        $sig = hash_hmac('sha256', "GET\n/api\n{$ts}\n", $secret);

        $result = $this->auth->check($this->credentials($key . ':' . $sig, $ts));

        $this->assertTrue($result->isOK());
    }

    #[Test]
    public function aTokenWithThreePartsIsRejected(): void
    {
        [$key, $secret] = $this->makeKey();
        $ts = time();

        $result = $this->auth->check($this->credentials($key . ':extra:' . $secret, $ts));

        $this->assertFalse($result->isOK());
        $this->assertSame('Invalid HMAC token format.', $result->reason());
    }

    #[Test]
    public function anEmptyTokenIsRejected(): void
    {
        $this->assertSame('No HMAC token provided.', $this->auth->check(['token' => ''])->reason());
    }

    // -----------------------------------------------------------------
    // Timestamp window
    // -----------------------------------------------------------------

    #[Test]
    public function aTimestampJustInsideTheWindowIsAccepted(): void
    {
        [$key, $secret] = $this->makeKey();
        $ts = time() - 299;

        $result = $this->auth->check($this->credentials($this->signature($key, $secret, $ts), $ts));

        $this->assertTrue($result->isOK());
    }

    #[Test]
    public function aTimestampJustOutsideTheWindowIsRejected(): void
    {
        [$key, $secret] = $this->makeKey();
        $ts = time() - 301;

        $result = $this->auth->check($this->credentials($this->signature($key, $secret, $ts), $ts));

        $this->assertFalse($result->isOK());
        $this->assertSame('Request timestamp is outside the acceptable window.', $result->reason());
    }

    #[Test]
    public function aFutureTimestampInsideTheWindowIsAccepted(): void
    {
        [$key, $secret] = $this->makeKey();
        $ts = time() + 299;

        $result = $this->auth->check($this->credentials($this->signature($key, $secret, $ts), $ts));

        $this->assertTrue($result->isOK());
    }

    #[Test]
    public function aNonNumericTimestampIsRejected(): void
    {
        [$key, $secret] = $this->makeKey();

        // (int) 'not-a-number' is 0, so the request looks like it came from
        // 1970 and falls outside the window.
        $creds = $this->credentials($this->signature($key, $secret, time()));
        $creds['timestamp'] = 'not-a-number';

        $result = $this->auth->check($creds);

        $this->assertFalse($result->isOK());
        $this->assertSame('Request timestamp is outside the acceptable window.', $result->reason());
    }

    // -----------------------------------------------------------------
    // Method and path
    // -----------------------------------------------------------------

    #[Test]
    public function theMethodIsUppercasedBeforeSigning(): void
    {
        [$key, $secret] = $this->makeKey();
        $ts = time();

        // The client signed with POST; the request says post.
        $result = $this->auth->check($this->credentials($this->signature($key, $secret, $ts, 'POST'), $ts, 'post'));

        $this->assertTrue($result->isOK());
    }

    #[Test]
    public function aMissingMethodDefaultsToGet(): void
    {
        [$key, $secret] = $this->makeKey();
        $ts = time();
        $creds = $this->credentials($this->signature($key, $secret, $ts, 'GET'), $ts);
        unset($creds['method']);

        $this->assertTrue($this->auth->check($creds)->isOK());
    }

    #[Test]
    public function aMissingPathDefaultsToRoot(): void
    {
        [$key, $secret] = $this->makeKey();
        $ts = time();
        $creds = $this->credentials($this->signature($key, $secret, $ts, 'GET', '/'), $ts);
        unset($creds['path']);

        $this->assertTrue($this->auth->check($creds)->isOK());
    }

    #[Test]
    public function aMissingBodyDefaultsToEmpty(): void
    {
        [$key, $secret] = $this->makeKey();
        $ts = time();
        $creds = $this->credentials($this->signature($key, $secret, $ts), $ts);
        unset($creds['body']);

        $this->assertTrue($this->auth->check($creds)->isOK());
    }

    #[Test]
    public function theBodyIsPartOfTheSignature(): void
    {
        [$key, $secret] = $this->makeKey();
        $ts = time();

        $result = $this->auth->check($this->credentials($this->signature($key, $secret, $ts, 'POST', '/api', '{"a":1}'), $ts, 'POST', '/api', '{"a":2}'));

        $this->assertFalse($result->isOK());
        $this->assertSame('HMAC signature verification failed.', $result->reason());
    }

    // -----------------------------------------------------------------
    // Unused lifetime
    // -----------------------------------------------------------------

    #[Test]
    public function aTokenInsideTheUnusedLifetimeIsAccepted(): void
    {
        [$key, $secret] = $this->makeKey();
        $recent = (new \DateTimeImmutable('-30 minutes'))->format('Y-m-d H:i:s');
        $this->pdo->exec("UPDATE auth_identities SET last_used_at = '{$recent}' WHERE secret = '{$key}'");

        $this->config['unused_token_lifetime'] = 3600;
        $auth = new HmacSha256(\Flight::app(), $this->config);

        $ts = time();
        $this->assertTrue($auth->check($this->credentials($this->signature($key, $secret, $ts), $ts))->isOK());
    }

    #[Test]
    public function aZeroUnusedLifetimeDisablesTheCheck(): void
    {
        [$key, $secret] = $this->makeKey();
        $old = (new \DateTimeImmutable('-2 hours'))->format('Y-m-d H:i:s');
        $this->pdo->exec("UPDATE auth_identities SET last_used_at = '{$old}' WHERE secret = '{$key}'");

        $this->config['unused_token_lifetime'] = 0;
        $auth = new HmacSha256(\Flight::app(), $this->config);

        $ts = time();
        $this->assertTrue($auth->check($this->credentials($this->signature($key, $secret, $ts), $ts))->isOK());
    }

    #[Test]
    public function aTokenWithNoLastUsedDateSkipsTheLifetimeCheck(): void
    {
        [$key, $secret] = $this->makeKey();
        $this->pdo->exec("UPDATE auth_identities SET last_used_at = NULL WHERE secret = '{$key}'");

        $this->config['unused_token_lifetime'] = 1;
        $auth = new HmacSha256(\Flight::app(), $this->config);

        $ts = time();
        $this->assertTrue($auth->check($this->credentials($this->signature($key, $secret, $ts), $ts))->isOK());
    }

    #[Test]
    public function aSuccessfulCheckTouchesTheLastUsedDate(): void
    {
        [$key, $secret] = $this->makeKey();
        $this->pdo->exec("UPDATE auth_identities SET last_used_at = NULL WHERE secret = '{$key}'");

        $ts = time();
        $this->auth->check($this->credentials($this->signature($key, $secret, $ts), $ts));

        $lastUsed = $this->pdo->query("SELECT last_used_at FROM auth_identities WHERE secret = '{$key}'")->fetchColumn();
        $this->assertNotNull($lastUsed);
    }

    // -----------------------------------------------------------------
    // Token log rows
    // -----------------------------------------------------------------

    #[Test]
    public function aFailedCheckWritesNoTokenLogRow(): void
    {
        $this->auth->check(['token' => 'no-colon']);

        $this->assertSame(0, $this->tokenLoginCount());
    }

    #[Test]
    public function aSuccessfulAttemptWritesASuccessRow(): void
    {
        [$key, $secret] = $this->makeKey();
        $ts = time();

        $this->auth->attempt($this->credentials($this->signature($key, $secret, $ts), $ts));

        $row = $this->onlyTokenLogin();
        $this->assertSame(1, (int) $row['success']);
        $this->assertSame($this->user->id, (int) $row['user_id']);
        $this->assertSame('10.0.0.1', $row['ip_address']);
    }

    #[Test]
    public function aBannedAttemptWritesAFailureRow(): void
    {
        [$key, $secret] = $this->makeKey();
        $this->pdo->exec("UPDATE users SET status = 'banned' WHERE id = {$this->user->id}");
        $ts = time();

        $this->auth->attempt($this->credentials($this->signature($key, $secret, $ts), $ts));

        $row = $this->onlyTokenLogin();
        $this->assertSame(0, (int) $row['success']);
        $this->assertSame($this->user->id, (int) $row['user_id']);
    }

    #[Test]
    public function aFailedAttemptWritesAFailureRow(): void
    {
        $this->auth->attempt(['token' => 'no-colon']);

        $row = $this->onlyTokenLogin();
        $this->assertSame(0, (int) $row['success']);
        $this->assertNull($row['user_id']);
    }

    #[Test]
    public function theNoneLevelWritesNoTokenLogRow(): void
    {
        $this->config['record_login_attempt'] = 'none';
        $auth = new HmacSha256(\Flight::app(), $this->config);

        $auth->attempt(['token' => 'no-colon']);

        $this->assertSame(0, $this->tokenLoginCount());
    }

    #[Test]
    public function theFailureLevelSkipsASuccessfulAttempt(): void
    {
        [$key, $secret] = $this->makeKey();
        $ts = time();

        $this->config['record_login_attempt'] = 'failure';
        $auth = new HmacSha256(\Flight::app(), $this->config);

        $auth->attempt($this->credentials($this->signature($key, $secret, $ts), $ts));

        $this->assertSame(0, $this->tokenLoginCount());
    }

    #[Test]
    public function theFailureLevelStillWritesAFailedAttempt(): void
    {
        $this->config['record_login_attempt'] = 'failure';
        $auth = new HmacSha256(\Flight::app(), $this->config);

        $auth->attempt(['token' => 'no-colon']);

        $this->assertSame(1, $this->tokenLoginCount());
    }

    #[Test]
    public function aTokenLogRowRecordsTheUserAgent(): void
    {
        $_SERVER['HTTP_USER_AGENT'] = 'TestAgent/1.0';

        $this->auth->attempt(['token' => 'no-colon']);

        $this->assertSame('TestAgent/1.0', $this->onlyTokenLogin()['user_agent']);
    }

    #[Test]
    public function aTokenLogRowFallsBackToTheDefaultIpAddress(): void
    {
        unset($_SERVER['REMOTE_ADDR']);

        $this->auth->attempt(['token' => 'no-colon']);

        $this->assertSame('0.0.0.0', $this->onlyTokenLogin()['ip_address']);
    }

    // -----------------------------------------------------------------
    // loggedIn()
    // -----------------------------------------------------------------

    #[Test]
    public function loggedInUsesTheConfiguredHeaderName(): void
    {
        [$key, $secret] = $this->makeKey();
        $ts = time();

        $this->config['hmac_header'] = 'X-Custom-Sig';
        $auth = new HmacSha256(\Flight::app(), $this->config);

        $_SERVER['HTTP_X_CUSTOM_SIG'] = $this->signature($key, $secret, $ts, 'GET', '/');
        $_SERVER['HTTP_X_REQUEST_TIMESTAMP'] = (string) $ts;
        $_SERVER['REQUEST_METHOD'] = 'GET';
        $_SERVER['REQUEST_URI'] = '/';

        $this->assertTrue($auth->loggedIn());
    }

    #[Test]
    public function loggedInFallsBackToTheAuthorizationHeader(): void
    {
        [$key, $secret] = $this->makeKey();
        $ts = time();

        unset($this->config['hmac_header']);
        $auth = new HmacSha256(\Flight::app(), $this->config);

        $_SERVER['HTTP_AUTHORIZATION'] = $this->signature($key, $secret, $ts, 'GET', '/');
        $_SERVER['HTTP_X_REQUEST_TIMESTAMP'] = (string) $ts;
        $_SERVER['REQUEST_METHOD'] = 'GET';
        $_SERVER['REQUEST_URI'] = '/';

        $this->assertTrue($auth->loggedIn());
    }

    #[Test]
    public function loggedInDefaultsTheMethodAndPath(): void
    {
        [$key, $secret] = $this->makeKey();
        $ts = time();

        $_SERVER['HTTP_AUTHORIZATION'] = $this->signature($key, $secret, $ts, 'GET', '/');
        $_SERVER['HTTP_X_REQUEST_TIMESTAMP'] = (string) $ts;
        unset($_SERVER['REQUEST_METHOD'], $_SERVER['REQUEST_URI']);

        $this->assertTrue($this->auth->loggedIn());
    }

    #[Test]
    public function loggedInIsCachedAfterAFailure(): void
    {
        $this->assertFalse($this->auth->loggedIn());

        // A valid request now arrives, but the failed check is remembered.
        [$key, $secret] = $this->makeKey();
        $ts = time();
        $_SERVER['HTTP_AUTHORIZATION'] = $this->signature($key, $secret, $ts, 'GET', '/');
        $_SERVER['HTTP_X_REQUEST_TIMESTAMP'] = (string) $ts;
        $_SERVER['REQUEST_METHOD'] = 'GET';
        $_SERVER['REQUEST_URI'] = '/';

        $this->assertFalse($this->auth->loggedIn());
    }

    #[Test]
    public function loggedInIsFalseForABannedUser(): void
    {
        [$key, $secret] = $this->makeKey();
        $this->pdo->exec("UPDATE users SET status = 'banned' WHERE id = {$this->user->id}");
        $ts = time();

        $_SERVER['HTTP_AUTHORIZATION'] = $this->signature($key, $secret, $ts, 'GET', '/');
        $_SERVER['HTTP_X_REQUEST_TIMESTAMP'] = (string) $ts;
        $_SERVER['REQUEST_METHOD'] = 'GET';
        $_SERVER['REQUEST_URI'] = '/';

        $this->assertFalse($this->auth->loggedIn());
    }

    #[Test]
    public function loggedInIsTrueOnceAUserIsSet(): void
    {
        $this->auth->login($this->user);

        $this->assertTrue($this->auth->loggedIn());
    }
}
