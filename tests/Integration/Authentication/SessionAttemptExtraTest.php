<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Integration\Authentication;

use Enlivenapp\FlightShield\Authentication\Authenticators\Session;
use Enlivenapp\FlightShield\Models\UserIdentity;
use Enlivenapp\FlightShield\Tests\TestHelper;
use PDO;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The remaining attempt() branches: a banned account, the rehash on a
 * changed cost, and a session that points at a vanished user.
 */
#[CoversClass(Session::class)]
class SessionAttemptExtraTest extends TestCase
{
    protected PDO $pdo;
    protected Session $auth;

    protected function setUp(): void
    {
        $this->pdo = TestHelper::createDatabase();
        TestHelper::resetFlight();
        TestHelper::registerFlightDb($this->pdo);

        $_SESSION = [];

        $this->auth = new Session(\Flight::app(), TestHelper::getConfig());
    }

    protected function tearDown(): void
    {
        TestHelper::resetFlight();
        $_SESSION = [];
    }

    private function storedHash(string $email): string
    {
        $stmt = $this->pdo->prepare('SELECT secret2 FROM auth_identities WHERE secret = ?');
        $stmt->execute([$email]);

        return (string) $stmt->fetchColumn();
    }

    #[Test]
    public function aBannedAccountFailsGenerically(): void
    {
        $user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);
        $this->pdo->exec("UPDATE users SET status = 'banned' WHERE id = {$user->id}");

        $result = $this->auth->attempt(['email' => 'user@example.com', 'password' => 'Str0ng!Passw0rd']);

        $this->assertFalse($result->isOK());
        $this->assertSame('Invalid credentials.', $result->reason());
        $this->assertFalse($this->auth->loggedIn());
    }

    #[Test]
    public function aSuccessfulLoginRehashesWhenTheCostChanged(): void
    {
        TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);
        $before = $this->storedHash('user@example.com');

        // Raise the configured cost above the one the fixture used.
        $config = TestHelper::getConfig();
        $config['passwords']['cost'] = 12;
        $auth = new Session(\Flight::app(), $config);

        $result = $auth->attempt(['email' => 'user@example.com', 'password' => 'Str0ng!Passw0rd']);

        $this->assertTrue($result->isOK());

        $after = $this->storedHash('user@example.com');
        $this->assertNotSame($before, $after);
        $this->assertStringStartsWith('$2y$12$', $after);
    }

    #[Test]
    public function aSessionPointingAtAVanishedUserIsCleared(): void
    {
        $user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);
        $this->auth->login($user);

        // Hard-delete the row behind the session.
        $this->pdo->exec("DELETE FROM auth_identities WHERE user_id = {$user->id}");
        $this->pdo->exec("DELETE FROM users WHERE id = {$user->id}");

        $fresh = new Session(\Flight::app(), TestHelper::getConfig());

        $this->assertFalse($fresh->loggedIn());
        $this->assertArrayNotHasKey('user', $_SESSION);
    }

    #[Test]
    public function loggedInShortCircuitsForAnAlreadyLoggedInUser(): void
    {
        $user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);
        $this->auth->login($user);

        // Two calls in a row: the second hits the cached state.
        $this->assertTrue($this->auth->loggedIn());
        $this->assertTrue($this->auth->loggedIn());
        $this->assertSame($user->id, $this->auth->getUser()->id);
    }

    #[Test]
    public function loginUpdatesTheIdentitiesLastUsedAt(): void
    {
        TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);

        $this->auth->attempt(['email' => 'user@example.com', 'password' => 'Str0ng!Passw0rd']);

        $identity = (new UserIdentity($this->pdo))->getEmailIdentity(
            (new \Enlivenapp\FlightShield\Models\User($this->pdo))->eq('username', 'user')->find()
        );

        $this->assertNotNull($identity->last_used_at);
    }
}
