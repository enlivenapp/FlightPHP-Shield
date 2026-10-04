<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Integration\Authentication;

use Enlivenapp\FlightShield\Authentication\Authenticators\HmacSha256;
use Enlivenapp\FlightShield\Exceptions\AuthenticationException;
use Enlivenapp\FlightShield\Models\User;
use Enlivenapp\FlightShield\Models\UserIdentity;
use Enlivenapp\FlightShield\Tests\TestHelper;
use PDO;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * HMAC-SHA256 request signing: token format, timestamp window and signature.
 */
#[CoversClass(HmacSha256::class)]
class HmacAuthenticatorTest extends TestCase
{
    protected PDO $pdo;
    protected User $user;
    protected HmacSha256 $auth;
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
        unset($_SERVER['REMOTE_ADDR'], $_SERVER['HTTP_AUTHORIZATION'], $_SERVER['HTTP_X_REQUEST_TIMESTAMP']);
    }

    /**
     * Mint a key/secret pair, returning the raw key and its stored secret.
     *
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

    /**
     * Build the signed Authorization value the client would send.
     */
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

    #[Test]
    public function checkWithoutATokenFails(): void
    {
        $this->assertSame('No HMAC token provided.', $this->auth->check([])->reason());
    }

    #[Test]
    public function checkWithAMalformedTokenFails(): void
    {
        $this->assertSame('Invalid HMAC token format.', $this->auth->check(['token' => 'no-colon'])->reason());
    }

    #[Test]
    public function checkWithAnUnknownKeyFails(): void
    {
        $result = $this->auth->check($this->credentials('HMAC-SHA256 ghost:deadbeef'));

        $this->assertFalse($result->isOK());
        $this->assertSame('Invalid HMAC token.', $result->reason());
    }

    #[Test]
    public function checkWithoutATimestampFails(): void
    {
        [$key, $secret] = $this->makeKey();
        $creds = $this->credentials($this->signature($key, $secret, time()));
        unset($creds['timestamp']);

        $this->assertSame('Missing X-Request-Timestamp header.', $this->auth->check($creds)->reason());
    }

    #[Test]
    public function checkRejectsAStaleTimestamp(): void
    {
        [$key, $secret] = $this->makeKey();
        $old = time() - 3600;

        $result = $this->auth->check($this->credentials($this->signature($key, $secret, $old), $old));

        $this->assertFalse($result->isOK());
        $this->assertSame('Request timestamp is outside the acceptable window.', $result->reason());
    }

    #[Test]
    public function checkRejectsABadSignature(): void
    {
        [$key] = $this->makeKey();

        $result = $this->auth->check($this->credentials('HMAC-SHA256 ' . $key . ':deadbeef'));

        $this->assertFalse($result->isOK());
        $this->assertSame('HMAC signature verification failed.', $result->reason());
    }

    #[Test]
    public function checkAcceptsAValidSignature(): void
    {
        [$key, $secret] = $this->makeKey();
        $ts = time();

        $result = $this->auth->check($this->credentials($this->signature($key, $secret, $ts, 'POST', '/api/orders', '{"a":1}'), $ts, 'POST', '/api/orders', '{"a":1}'));

        $this->assertTrue($result->isOK());
        $user = $result->extraInfo();
        $this->assertSame($this->user->id, $user->id);
        $this->assertNotNull($user->currentHmacToken());
    }

    #[Test]
    public function checkRejectsATokenUnusedForLongerThanTheLifetime(): void
    {
        [$key, $secret] = $this->makeKey();
        $old = (new \DateTimeImmutable('-2 hours'))->format('Y-m-d H:i:s');
        $this->pdo->exec("UPDATE auth_identities SET last_used_at = '{$old}' WHERE secret = '{$key}'");

        $this->config['unused_token_lifetime'] = 3600;
        $auth = new HmacSha256(\Flight::app(), $this->config);

        $ts = time();
        $result = $auth->check($this->credentials($this->signature($key, $secret, $ts), $ts));

        $this->assertFalse($result->isOK());
        $this->assertSame('HMAC token expired from disuse.', $result->reason());
    }

    #[Test]
    public function attemptLogsTheUserIn(): void
    {
        [$key, $secret] = $this->makeKey();
        $ts = time();

        $result = $this->auth->attempt($this->credentials($this->signature($key, $secret, $ts), $ts));

        $this->assertTrue($result->isOK());
        $this->assertTrue($this->auth->loggedIn());
        $this->assertSame($this->user->id, $this->auth->getUser()->id);
    }

    #[Test]
    public function attemptFailsForABannedAccount(): void
    {
        [$key, $secret] = $this->makeKey();
        $this->pdo->exec("UPDATE users SET status = 'banned' WHERE id = {$this->user->id}");
        $ts = time();

        $result = $this->auth->attempt($this->credentials($this->signature($key, $secret, $ts), $ts));

        $this->assertFalse($result->isOK());
        $this->assertSame('Account is not active.', $result->reason());
        $this->assertFalse($this->auth->loggedIn());
    }

    #[Test]
    public function loggedInReadsTheRequestHeaders(): void
    {
        [$key, $secret] = $this->makeKey();
        $ts = time();

        $_SERVER['HTTP_AUTHORIZATION'] = $this->signature($key, $secret, $ts, 'GET', '/');
        $_SERVER['HTTP_X_REQUEST_TIMESTAMP'] = (string) $ts;
        $_SERVER['REQUEST_METHOD'] = 'GET';
        $_SERVER['REQUEST_URI'] = '/';

        $this->assertTrue($this->auth->loggedIn());
        $this->assertSame($this->user->id, $this->auth->getUser()->id);
    }

    #[Test]
    public function loggedInIsFalseWithoutHeaders(): void
    {
        $this->assertFalse($this->auth->loggedIn());
    }

    #[Test]
    public function logoutClearsTheUser(): void
    {
        [$key, $secret] = $this->makeKey();
        $ts = time();
        $this->auth->attempt($this->credentials($this->signature($key, $secret, $ts), $ts));

        $this->auth->logout();

        $this->assertNull($this->auth->getUser());
    }

    #[Test]
    public function loginByIdRejectsAnUnknownUser(): void
    {
        $this->expectException(AuthenticationException::class);

        $this->auth->loginById(999);
    }

    #[Test]
    public function recordActiveDateUpdatesAnActiveUser(): void
    {
        $this->auth->login($this->user);
        $this->auth->recordActiveDate();

        $stored = $this->pdo->query("SELECT last_active FROM users WHERE id = {$this->user->id}")->fetchColumn();
        $this->assertNotNull($stored);
    }

    #[Test]
    public function recordActiveDateSkipsAnInactiveUser(): void
    {
        $this->pdo->exec("UPDATE users SET active = 0 WHERE id = {$this->user->id}");
        $this->auth->login((new User($this->pdo))->findById($this->user->id));

        $this->auth->recordActiveDate();

        $stored = $this->pdo->query("SELECT last_active FROM users WHERE id = {$this->user->id}")->fetchColumn();
        $this->assertNull($stored);
    }

    #[Test]
    public function recordActiveDateDoesNothingWhenNobodyIsLoggedIn(): void
    {
        $this->auth->recordActiveDate();

        $this->assertNull($this->auth->getUser());
    }
}
