<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Integration\Authentication;

use Enlivenapp\FlightShield\Authentication\Authenticators\Session;
use Enlivenapp\FlightShield\Tests\TestHelper;
use PDO;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * What attempt(), login(), logout() and remember() write: the auth_logins
 * rows, the remember token, and the session keys they touch.
 */
#[CoversClass(Session::class)]
class SessionAttemptLoggingTest extends TestCase
{
    protected PDO $pdo;
    protected Session $auth;

    /** @var array<string, mixed> */
    protected array $config;

    protected function setUp(): void
    {
        $this->pdo = TestHelper::createDatabase();
        TestHelper::resetFlight();
        TestHelper::registerFlightDb($this->pdo);

        $_SESSION = [];
        unset($_COOKIE['remember']);

        $this->config = TestHelper::getConfig();
        $this->auth = new Session(\Flight::app(), $this->config);
    }

    protected function tearDown(): void
    {
        TestHelper::resetFlight();
        $_SESSION = [];
        unset($_COOKIE['remember']);
    }

    /**
     * @return array<int, array<string, mixed>>
     */
    private function loginRows(): array
    {
        return $this->pdo->query('SELECT * FROM auth_logins ORDER BY id')
            ->fetchAll(PDO::FETCH_ASSOC);
    }

    /**
     * @return array<string, mixed>
     */
    private function onlyLoginRow(): array
    {
        $rows = $this->loginRows();
        $this->assertCount(1, $rows);

        return $rows[0];
    }

    /**
     * @return array<string, mixed>|null
     */
    private function rememberToken(): ?array
    {
        $row = $this->pdo->query('SELECT * FROM auth_remember_tokens')
            ->fetch(PDO::FETCH_ASSOC);

        return $row === false ? null : $row;
    }

    private function elapseOnTheTokenExpiry(string $expires): int
    {
        return (int) strtotime($expires) - time();
    }

    // -----------------------------------------------------------------
    // attempt() writes an auth_logins row per branch
    // -----------------------------------------------------------------

    #[Test]
    public function aWrongPasswordIsRecordedAsAFailure(): void
    {
        TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);

        $result = $this->auth->attempt(['email' => 'user@example.com', 'password' => 'wrong-password']);

        $this->assertFalse($result->isOK());

        $row = $this->onlyLoginRow();
        $this->assertSame(0, (int) $row['success']);
        $this->assertSame('user@example.com', $row['identifier']);
        $this->assertSame(Session::ID_TYPE_EMAIL_PASSWORD, $row['id_type']);
        $this->assertNull($row['user_id']);
    }

    #[Test]
    public function anUnknownEmailIsRecordedAsAFailure(): void
    {
        $result = $this->auth->attempt(['email' => 'nobody@example.com', 'password' => 'Str0ng!Passw0rd']);

        $this->assertFalse($result->isOK());

        $row = $this->onlyLoginRow();
        $this->assertSame(0, (int) $row['success']);
        $this->assertSame('nobody@example.com', $row['identifier']);
        $this->assertNull($row['user_id']);
    }

    #[Test]
    public function aBannedAccountIsRecordedAsAFailureAgainstTheUserId(): void
    {
        $user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);
        $this->pdo->exec("UPDATE users SET status = 'banned' WHERE id = {$user->id}");

        $result = $this->auth->attempt(['email' => 'user@example.com', 'password' => 'Str0ng!Passw0rd']);

        $this->assertFalse($result->isOK());

        $row = $this->onlyLoginRow();
        $this->assertSame(0, (int) $row['success']);
        $this->assertSame($user->id, (int) $row['user_id']);
    }

    #[Test]
    public function anUnactivatedAccountIsRecordedAsAFailureAgainstTheUserId(): void
    {
        $user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', false);

        $result = $this->auth->attempt(['email' => 'user@example.com', 'password' => 'Str0ng!Passw0rd']);

        $this->assertFalse($result->isOK());
        $this->assertSame(Session::ACCOUNT_NOT_ACTIVATED, $result->extraInfo());

        $row = $this->onlyLoginRow();
        $this->assertSame(0, (int) $row['success']);
        $this->assertSame($user->id, (int) $row['user_id']);
    }

    #[Test]
    public function aSuccessfulAttemptIsRecordedAsASuccessAndLogsTheUserIn(): void
    {
        $user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);

        $result = $this->auth->attempt(['email' => 'user@example.com', 'password' => 'Str0ng!Passw0rd']);

        $this->assertTrue($result->isOK());
        $this->assertTrue($this->auth->loggedIn());
        $this->assertSame($user->id, $_SESSION['user']);

        $row = $this->onlyLoginRow();
        $this->assertSame(1, (int) $row['success']);
        $this->assertSame($user->id, (int) $row['user_id']);
    }

    #[Test]
    public function aUsernameLoginRecordsTheUsernameIdentifier(): void
    {
        TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'bob', true);

        $result = $this->auth->attempt(['username' => 'bob', 'password' => 'Str0ng!Passw0rd']);

        $this->assertTrue($result->isOK());

        $row = $this->onlyLoginRow();
        $this->assertSame('bob', $row['identifier']);
        $this->assertSame('username', $row['id_type']);
    }

    #[Test]
    public function anAttemptWithNoIdentifierRecordsUnknown(): void
    {
        $result = $this->auth->attempt(['password' => 'Str0ng!Passw0rd']);

        $this->assertFalse($result->isOK());

        $row = $this->onlyLoginRow();
        $this->assertSame('unknown', $row['identifier']);
        $this->assertSame(0, (int) $row['success']);
    }

    // -----------------------------------------------------------------
    // Default session field
    // -----------------------------------------------------------------

    #[Test]
    public function loginFallsBackToTheDefaultSessionField(): void
    {
        $user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);

        unset($this->config['session']);
        $auth = new Session(\Flight::app(), $this->config);

        $auth->login($user);

        $this->assertSame($user->id, $_SESSION['user']);
    }

    #[Test]
    public function logoutFallsBackToTheDefaultSessionField(): void
    {
        $user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);
        $this->auth->login($user);

        unset($this->config['session']);
        $auth = new Session(\Flight::app(), $this->config);

        $auth->logout();

        $this->assertArrayNotHasKey('user', $_SESSION);
        $this->assertFalse($auth->loggedIn());
    }

    #[Test]
    public function logoutFindsTheRememberTokenUnderTheDefaultCookieName(): void
    {
        $user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);

        unset($this->config['session']['remember_cookie_name']);
        $auth = new Session(\Flight::app(), $this->config);

        $auth->login($user);
        $auth->remember();

        $token = $this->rememberToken();
        $this->assertNotNull($token);

        $_COOKIE['remember'] = $token['selector'] . ':' . str_repeat('a', 40);

        $auth->logout();

        $this->assertNull($this->rememberToken());
    }

    // -----------------------------------------------------------------
    // remember()
    // -----------------------------------------------------------------

    #[Test]
    public function rememberStoresATokenWithTheDefaultLifetime(): void
    {
        $user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);

        unset($this->config['session']['remember_length']);
        $auth = new Session(\Flight::app(), $this->config);

        $auth->login($user);
        $auth->remember();

        $token = $this->rememberToken();
        $this->assertNotNull($token);

        $this->assertSame(24, strlen((string) $token['selector']));
        $this->assertSame(64, strlen((string) $token['hashed_validator']));
        $this->assertSame($user->id, (int) $token['user_id']);
        $this->assertEqualsWithDelta(30 * 86400, $this->elapseOnTheTokenExpiry((string) $token['expires']), 10);
    }

    #[Test]
    public function rememberHonoursTheConfiguredLifetime(): void
    {
        $user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);

        $this->config['session']['remember_length'] = 600;
        $auth = new Session(\Flight::app(), $this->config);

        $auth->login($user);
        $auth->remember();

        $token = $this->rememberToken();
        $this->assertNotNull($token);

        $this->assertEqualsWithDelta(600, $this->elapseOnTheTokenExpiry((string) $token['expires']), 10);
    }

    // -----------------------------------------------------------------
    // Configured values beat the defaults
    // -----------------------------------------------------------------

    private function storedHash(string $email): string
    {
        $stmt = $this->pdo->prepare('SELECT secret2 FROM auth_identities WHERE secret = ?');
        $stmt->execute([$email]);

        return (string) $stmt->fetchColumn();
    }

    private function setStoredHash(string $email, string $password, int $cost): void
    {
        $stmt = $this->pdo->prepare('UPDATE auth_identities SET secret2 = ? WHERE secret = ?');
        $stmt->execute([password_hash($password, PASSWORD_BCRYPT, ['cost' => $cost]), $email]);
    }

    #[Test]
    public function loginUsesTheConfiguredSessionField(): void
    {
        $user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);

        $this->config['session']['field'] = 'auth_user';
        $auth = new Session(\Flight::app(), $this->config);

        $auth->login($user);

        $this->assertSame($user->id, $_SESSION['auth_user']);
        $this->assertArrayNotHasKey('user', $_SESSION);
    }

    #[Test]
    public function logoutUsesTheConfiguredSessionField(): void
    {
        $user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);

        $this->config['session']['field'] = 'auth_user';
        $auth = new Session(\Flight::app(), $this->config);

        $auth->login($user);
        $auth->logout();

        $this->assertArrayNotHasKey('auth_user', $_SESSION);
    }

    #[Test]
    public function aSessionUnderAConfiguredFieldIsFoundByAFreshInstance(): void
    {
        $user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);

        $this->config['session']['field'] = 'auth_user';
        $auth = new Session(\Flight::app(), $this->config);
        $auth->login($user);

        $fresh = new Session(\Flight::app(), $this->config);

        $this->assertTrue($fresh->loggedIn());
        $this->assertSame($user->id, $fresh->getUser()->id);
    }

    #[Test]
    public function getUserLoadsTheUserFromAnExistingSession(): void
    {
        $user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);
        $this->auth->login($user);

        $fresh = new Session(\Flight::app(), $this->config);

        $this->assertSame($user->id, $fresh->getUser()->id);
    }

    #[Test]
    public function logoutFindsTheRememberTokenUnderTheConfiguredCookieName(): void
    {
        $user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);

        $this->config['session']['remember_cookie_name'] = 'stay_signed_in';
        $auth = new Session(\Flight::app(), $this->config);

        $auth->login($user);
        $auth->remember();

        $token = $this->rememberToken();
        $this->assertNotNull($token);

        $_COOKIE['stay_signed_in'] = $token['selector'] . ':' . str_repeat('a', 40);

        $auth->logout();

        $this->assertNull($this->rememberToken());
    }

    #[Test]
    public function rememberingIsSkippedWhenTheConfigTurnsItOff(): void
    {
        $user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);

        $this->config['session']['allow_remembering'] = false;
        $auth = new Session(\Flight::app(), $this->config);

        $auth->login($user);
        $auth->remember();

        $token = $this->rememberToken();
        $this->assertNotNull($token);

        $_SESSION = [];
        $_COOKIE['remember'] = $token['selector'] . ':' . str_repeat('a', 40);

        $fresh = new Session(\Flight::app(), $this->config);

        $this->assertFalse($fresh->loggedIn());
        $this->assertNotNull($this->rememberToken());
    }

    #[Test]
    public function anAttemptWithTwoIdentifiersRecordsTheEmail(): void
    {
        TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'bob', true);

        $result = $this->auth->attempt([
            'email'    => 'user@example.com',
            'username' => 'bob',
            'password' => 'Str0ng!Passw0rd',
        ]);

        $this->assertTrue($result->isOK());

        $row = $this->onlyLoginRow();
        $this->assertSame('user@example.com', $row['identifier']);
    }

    #[Test]
    public function aRehashUsesTheConfiguredPasswordCost(): void
    {
        TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);
        $this->setStoredHash('user@example.com', 'Str0ng!Passw0rd', 10);

        $this->config['passwords']['cost'] = 4;
        $auth = new Session(\Flight::app(), $this->config);

        $result = $auth->attempt(['email' => 'user@example.com', 'password' => 'Str0ng!Passw0rd']);

        $this->assertTrue($result->isOK());
        $this->assertStringStartsWith('$2y$04$', $this->storedHash('user@example.com'));
    }
}
