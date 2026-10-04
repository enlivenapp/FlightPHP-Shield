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
use Enlivenapp\FlightShield\Exceptions\AuthenticationException;
use Enlivenapp\FlightShield\Models\User;
use Enlivenapp\FlightShield\Tests\TestHelper;
use PDO;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The stateless JWT authenticator: parsing, subject resolution, the header
 * source and the login lifecycle.
 */
#[CoversClass(JWT::class)]
class JWTAuthenticatorTest extends TestCase
{
    protected PDO $pdo;
    protected User $user;
    protected JWT $auth;
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
        unset($_SERVER['REMOTE_ADDR'], $_SERVER['HTTP_AUTHORIZATION']);
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

    private function makeAuth(array $config): JWT
    {
        return new JWT(\Flight::app(), $config);
    }

    // -----------------------------------------------------------------
    // check()
    // -----------------------------------------------------------------

    #[Test]
    public function checkWithoutATokenFails(): void
    {
        $this->assertSame('No JWT provided.', $this->auth->check([])->reason());
        $this->assertSame('No JWT provided.', $this->auth->check(['token' => ''])->reason());
    }

    #[Test]
    public function checkRejectsGarbage(): void
    {
        $result = $this->auth->check(['token' => 'not-a-jwt']);

        $this->assertFalse($result->isOK());
        $this->assertSame('Invalid or expired token.', $result->reason());
    }

    #[Test]
    public function checkReturnsTheUserForAValidToken(): void
    {
        $result = $this->auth->check(['token' => $this->tokenFor($this->user)]);

        $this->assertTrue($result->isOK());
        $this->assertSame($this->user->id, $result->extraInfo()->id);
        $this->assertSame((string) $this->user->id, $this->auth->getPayload()->sub);
    }

    #[Test]
    public function checkRejectsATokenWithoutASubject(): void
    {
        $token = (new JWTManager($this->jwtConfig()))->issue(['foo' => 'bar']);

        $result = $this->auth->check(['token' => $token]);

        $this->assertFalse($result->isOK());
        $this->assertSame('Invalid JWT: missing subject.', $result->reason());
    }

    #[Test]
    public function checkRejectsATokenForAMissingUser(): void
    {
        $ghost = new User($this->pdo);
        $ghost->id = 9999;

        $result = $this->auth->check(['token' => $this->tokenFor($ghost)]);

        $this->assertFalse($result->isOK());
        $this->assertSame('Invalid user.', $result->reason());
    }

    #[Test]
    public function checkRejectsAnExpiredToken(): void
    {
        $result = $this->auth->check(['token' => $this->tokenFor($this->user, -10)]);

        $this->assertFalse($result->isOK());
        $this->assertSame('Invalid or expired token.', $result->reason());
    }

    // -----------------------------------------------------------------
    // attempt() / lifecycle
    // -----------------------------------------------------------------

    #[Test]
    public function attemptLogsTheUserIn(): void
    {
        $result = $this->auth->attempt(['token' => $this->tokenFor($this->user)]);

        $this->assertTrue($result->isOK());
        $this->assertTrue($this->auth->loggedIn());
        $this->assertSame($this->user->id, $this->auth->getUser()->id);
    }

    #[Test]
    public function attemptReportsTheBanMessage(): void
    {
        $user = TestHelper::createUser($this->pdo, 'banned@example.com', 'Str0ng!Passw0rd', 'banned', true);
        $this->pdo->exec("UPDATE users SET status = 'banned', status_message = 'Trouble.' WHERE id = {$user->id}");

        $result = $this->auth->attempt(['token' => $this->tokenFor($user)]);

        $this->assertFalse($result->isOK());
        $this->assertSame('Trouble.', $result->reason());
        $this->assertFalse($this->auth->loggedIn());
    }

    #[Test]
    public function attemptFallsBackToTheDefaultBanMessage(): void
    {
        $user = TestHelper::createUser($this->pdo, 'banned@example.com', 'Str0ng!Passw0rd', 'banned', true);
        $this->pdo->exec("UPDATE users SET status = 'banned' WHERE id = {$user->id}");

        $result = $this->auth->attempt(['token' => $this->tokenFor($user)]);

        $this->assertSame('User is banned.', $result->reason());
    }

    #[Test]
    public function loggedInReadsTheConfiguredHeader(): void
    {
        $_SERVER['HTTP_AUTHORIZATION'] = 'Bearer ' . $this->tokenFor($this->user);

        $this->assertTrue($this->auth->loggedIn());
        $this->assertSame($this->user->id, $this->auth->getUser()->id);
    }

    #[Test]
    public function loggedInIsFalseWithoutAHeader(): void
    {
        $this->assertFalse($this->auth->loggedIn());
    }

    #[Test]
    public function loggedInIsFalseForABannedUser(): void
    {
        $user = TestHelper::createUser($this->pdo, 'banned@example.com', 'Str0ng!Passw0rd', 'banned', true);
        $this->pdo->exec("UPDATE users SET status = 'banned' WHERE id = {$user->id}");
        $_SERVER['HTTP_AUTHORIZATION'] = $this->tokenFor($user);

        $this->assertFalse($this->auth->loggedIn());
    }

    #[Test]
    public function anEmptyHeaderConfigMeansNoTokenSource(): void
    {
        $config = $this->config;
        $config['jwt']['header'] = '';
        $auth = $this->makeAuth($config);

        $_SERVER['HTTP_AUTHORIZATION'] = 'Bearer ' . $this->tokenFor($this->user);

        $this->assertFalse($auth->loggedIn());
    }

    #[Test]
    public function logoutClearsTheUserAndPayload(): void
    {
        $this->auth->check(['token' => $this->tokenFor($this->user)]);

        $this->auth->logout();

        $this->assertNull($this->auth->getUser());
        $this->assertNull($this->auth->getPayload());
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

    #[Test]
    public function generateTokenProducesATokenThatCheckAccepts(): void
    {
        $token = $this->auth->generateToken($this->user, ['role' => 'admin']);

        $result = $this->auth->check(['token' => $token]);

        $this->assertTrue($result->isOK());
        $this->assertSame('admin', $this->auth->getPayload()->role);
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
    public function recordActiveDateDoesNothingWhenLoggedOut(): void
    {
        $this->auth->recordActiveDate();

        $this->assertNull($this->auth->getUser());
    }
}
