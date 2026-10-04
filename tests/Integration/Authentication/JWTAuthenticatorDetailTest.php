<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Integration\Authentication;

use Enlivenapp\FlightShield\Authentication\Authenticators\JWT;
use Enlivenapp\FlightShield\Authentication\JWTManager;
use Enlivenapp\FlightShield\Models\User;
use Enlivenapp\FlightShield\Tests\TestHelper;
use PDO;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The JWT details the flow tests leave open: the token-log rows, the
 * header name mapping, the Bearer prefix, and the loggedIn() cache.
 */
#[CoversClass(JWT::class)]
class JWTAuthenticatorDetailTest extends TestCase
{
    protected PDO $pdo;
    protected User $user;
    protected JWT $auth;

    /** @var array<string, mixed> */
    protected array $config;

    protected function setUp(): void
    {
        $this->pdo = TestHelper::createDatabase();
        TestHelper::resetFlight();
        TestHelper::registerFlightDb($this->pdo);

        $_SERVER['REMOTE_ADDR'] = '10.0.0.1';

        $this->config = TestHelper::getConfig();
        $this->config['jwt'] = $this->jwtConfig();

        $this->user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);
        $this->auth = new JWT(\Flight::app(), $this->config);
    }

    protected function tearDown(): void
    {
        TestHelper::resetFlight();
        unset(
            $_SERVER['REMOTE_ADDR'],
            $_SERVER['HTTP_AUTHORIZATION'],
            $_SERVER['HTTP_X_CUSTOM_TOKEN'],
            $_SERVER['HTTP_USER_AGENT']
        );
    }

    /**
     * @return array<string, mixed>
     */
    private function jwtConfig(string $header = 'Authorization'): array
    {
        return [
            'header'         => $header,
            'time_to_live'   => 3600,
            'default_claims' => ['iss' => 'test'],
            'keys'           => [
                'default' => [
                    ['kid' => '', 'alg' => 'HS256', 'secret' => str_repeat('s', 40)],
                ],
            ],
        ];
    }

    private function tokenFor(User $user, ?int $ttl = null): string
    {
        return (new JWTManager($this->jwtConfig()))->generateToken($user, [], $ttl);
    }

    /**
     * @param array<string, mixed> $config
     */
    private function makeAuth(array $config): JWT
    {
        return new JWT(\Flight::app(), $config);
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
    // Token-log rows
    // -----------------------------------------------------------------

    #[Test]
    public function aSuccessfulAttemptWritesASuccessRow(): void
    {
        $token = $this->tokenFor($this->user);

        $this->auth->attempt(['token' => $token]);

        $row = $this->onlyTokenLogin();
        $this->assertSame(1, (int) $row['success']);
        $this->assertSame($this->user->id, (int) $row['user_id']);
        $this->assertSame('sha256:' . hash('sha256', $token), $row['identifier']);
    }

    #[Test]
    public function aBannedAttemptWritesAFailureRow(): void
    {
        $user = TestHelper::createUser($this->pdo, 'banned@example.com', 'Str0ng!Passw0rd', 'banned', true);
        $this->pdo->exec("UPDATE users SET status = 'banned' WHERE id = {$user->id}");
        $token = $this->tokenFor($user);

        $this->auth->attempt(['token' => $token]);

        $row = $this->onlyTokenLogin();
        $this->assertSame(0, (int) $row['success']);
        $this->assertSame($user->id, (int) $row['user_id']);
        $this->assertSame('sha256:' . hash('sha256', $token), $row['identifier']);
    }

    #[Test]
    public function aFailedCheckWritesAFailureRowWithTheRawToken(): void
    {
        $this->auth->attempt(['token' => 'not-a-jwt']);

        $row = $this->onlyTokenLogin();
        $this->assertSame(0, (int) $row['success']);
        $this->assertNull($row['user_id']);
        $this->assertSame('not-a-jwt', $row['identifier']);
    }

    #[Test]
    public function aFailedCheckWithoutATokenWritesAnEmptyIdentifier(): void
    {
        $this->auth->attempt([]);

        $row = $this->onlyTokenLogin();
        $this->assertSame('', $row['identifier']);
    }

    #[Test]
    public function theNoneLevelWritesNoRow(): void
    {
        $this->config['record_login_attempt'] = 'none';
        $auth = $this->makeAuth($this->config);

        $auth->attempt(['token' => 'not-a-jwt']);

        $this->assertSame(0, $this->tokenLoginCount());
    }

    #[Test]
    public function theFailureLevelSkipsASuccessfulAttempt(): void
    {
        $this->config['record_login_attempt'] = 'failure';
        $auth = $this->makeAuth($this->config);

        $auth->attempt(['token' => $this->tokenFor($this->user)]);

        $this->assertSame(0, $this->tokenLoginCount());
    }

    #[Test]
    public function theFailureLevelStillWritesAFailedAttempt(): void
    {
        $this->config['record_login_attempt'] = 'failure';
        $auth = $this->makeAuth($this->config);

        $auth->attempt(['token' => 'not-a-jwt']);

        $this->assertSame(1, $this->tokenLoginCount());
    }

    #[Test]
    public function aTokenLogRowRecordsTheUserAgent(): void
    {
        $_SERVER['HTTP_USER_AGENT'] = 'TestAgent/1.0';

        $this->auth->attempt(['token' => 'not-a-jwt']);

        $this->assertSame('TestAgent/1.0', $this->onlyTokenLogin()['user_agent']);
    }

    #[Test]
    public function aTokenLogRowFallsBackToTheDefaultIpAddress(): void
    {
        unset($_SERVER['REMOTE_ADDR']);

        $this->auth->attempt(['token' => 'not-a-jwt']);

        $this->assertSame('0.0.0.0', $this->onlyTokenLogin()['ip_address']);
    }

    // -----------------------------------------------------------------
    // Header handling
    // -----------------------------------------------------------------

    #[Test]
    public function theHeaderNameIsMappedToTheServerKey(): void
    {
        $config = $this->config;
        $config['jwt']['header'] = 'X-Custom-Token';
        $auth = $this->makeAuth($config);

        $_SERVER['HTTP_X_CUSTOM_TOKEN'] = $this->tokenFor($this->user);

        $this->assertTrue($auth->loggedIn());
    }

    #[Test]
    public function aBearerPrefixIsStripped(): void
    {
        $_SERVER['HTTP_AUTHORIZATION'] = 'Bearer ' . $this->tokenFor($this->user);

        $this->assertTrue($this->auth->loggedIn());
    }

    #[Test]
    public function aBareTokenIsAccepted(): void
    {
        $_SERVER['HTTP_AUTHORIZATION'] = $this->tokenFor($this->user);

        $this->assertTrue($this->auth->loggedIn());
    }

    #[Test]
    public function aBearerPrefixWithExtraSpacesIsTrimmed(): void
    {
        $_SERVER['HTTP_AUTHORIZATION'] = 'Bearer   ' . $this->tokenFor($this->user) . '  ';

        $this->assertTrue($this->auth->loggedIn());
    }

    #[Test]
    public function aMissingHeaderConfigMeansNoTokenSource(): void
    {
        $config = $this->config;
        unset($config['jwt']['header']);
        $auth = $this->makeAuth($config);

        $_SERVER['HTTP_AUTHORIZATION'] = 'Bearer ' . $this->tokenFor($this->user);

        $this->assertFalse($auth->loggedIn());
    }

    // -----------------------------------------------------------------
    // loggedIn() caching
    // -----------------------------------------------------------------

    #[Test]
    public function loggedInIsCachedAfterAFailure(): void
    {
        $this->assertFalse($this->auth->loggedIn());

        // A valid header now arrives, but the failed check is remembered.
        $_SERVER['HTTP_AUTHORIZATION'] = 'Bearer ' . $this->tokenFor($this->user);

        $this->assertFalse($this->auth->loggedIn());
    }

    #[Test]
    public function loggedInIsTrueOnceAUserIsSet(): void
    {
        $this->auth->login($this->user);

        $this->assertTrue($this->auth->loggedIn());
    }

    // -----------------------------------------------------------------
    // Payload
    // -----------------------------------------------------------------

    #[Test]
    public function thePayloadIsNullBeforeAnyCheck(): void
    {
        $this->assertNull($this->auth->getPayload());
    }

    #[Test]
    public function aFailedCheckLeavesThePayloadNull(): void
    {
        $this->auth->check(['token' => 'not-a-jwt']);

        $this->assertNull($this->auth->getPayload());
    }

    #[Test]
    public function aSuccessfulCheckStoresThePayload(): void
    {
        $this->auth->check(['token' => $this->tokenFor($this->user)]);

        $payload = $this->auth->getPayload();
        $this->assertNotNull($payload);
        $this->assertSame((string) $this->user->id, $payload->sub);
    }

    // -----------------------------------------------------------------
    // Keyset
    // -----------------------------------------------------------------

    #[Test]
    public function aNamedKeysetIsUsedForVerification(): void
    {
        $config = $this->config;
        $config['jwt']['keys']['secondary'] = [
            ['kid' => '', 'alg' => 'HS256', 'secret' => str_repeat('t', 40)],
        ];
        $auth = $this->makeAuth($config);
        $auth->setKeyset('secondary');

        $token = (new JWTManager($config['jwt']))->generateToken($this->user, [], null, 'secondary');

        $this->assertTrue($auth->check(['token' => $token])->isOK());
    }

    #[Test]
    public function aTokenFromAnotherKeysetIsRejected(): void
    {
        $config = $this->config;
        $config['jwt']['keys']['secondary'] = [
            ['kid' => '', 'alg' => 'HS256', 'secret' => str_repeat('t', 40)],
        ];
        $auth = $this->makeAuth($config);
        $auth->setKeyset('secondary');

        $token = (new JWTManager($config['jwt']))->generateToken($this->user, [], null, 'default');

        $this->assertFalse($auth->check(['token' => $token])->isOK());
    }

    // -----------------------------------------------------------------
    // generateToken()
    // -----------------------------------------------------------------

    #[Test]
    public function generateTokenUsesTheConfiguredKeyset(): void
    {
        $token = $this->auth->generateToken($this->user);

        $this->assertTrue($this->auth->check(['token' => $token])->isOK());
    }

    #[Test]
    public function generateTokenCarriesTheExtraClaims(): void
    {
        $token = $this->auth->generateToken($this->user, ['role' => 'admin']);

        $this->auth->check(['token' => $token]);

        $this->assertSame('admin', $this->auth->getPayload()->role);
    }
}
