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
 * Regression coverage for the "remember me" sliding refresh: restoring a
 * remembered user consumes the presented token and issues a fresh one, so
 * the old cookie cannot be replayed. (Set-Cookie emission itself is not
 * asserted — headers_list() is empty under CLI SAPI — the cookie value is
 * derived from the rotated database token instead.)
 */
#[CoversClass(Session::class)]
class SessionRememberMeRefreshTest extends TestCase
{
    protected PDO $pdo;
    protected int $userId;

    protected function setUp(): void
    {
        $this->pdo = TestHelper::createDatabase();
        TestHelper::registerFlightDb($this->pdo);

        $user = TestHelper::createUser($this->pdo, 'remember@example.com', 'password123', 'rememberuser');
        $this->userId = $user->id;

        $_SESSION = [];
        $_COOKIE  = [];
        header_remove();
    }

    protected function tearDown(): void
    {
        TestHelper::resetFlight();
        $_SESSION = [];
        $_COOKIE  = [];
        header_remove();
    }

    private function insertToken(int $userId, string $selector, string $validator, string $expires = '2099-12-31 23:59:59'): void
    {
        $now  = (new \DateTimeImmutable())->format('Y-m-d H:i:s');
        $stmt = $this->pdo->prepare(
            'INSERT INTO auth_remember_tokens
             (selector, hashed_validator, user_id, expires, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?)'
        );
        $stmt->execute([$selector, hash('sha256', $validator), $userId, $expires, $now, $now]);
    }

    private function countTokens(): int
    {
        return (int) $this->pdo
            ->query('SELECT COUNT(*) FROM auth_remember_tokens')
            ->fetchColumn();
    }

    #[Test]
    public function restoringRememberedUserRotatesToken(): void
    {
        $this->insertToken($this->userId, 'old-sel', 'old-validator');

        $_COOKIE['remember'] = 'old-sel:old-validator';

        $auth = new Session(\Flight::app(), TestHelper::getConfig());

        $this->assertTrue($auth->loggedIn(), 'remembered session should restore login');
        $this->assertSame($this->userId, (int) $_SESSION['user']);

        // Old token consumed, one fresh token issued (sliding refresh)
        $this->assertSame(1, $this->countTokens());
        $newSelector = (string) $this->pdo
            ->query('SELECT selector FROM auth_remember_tokens LIMIT 1')
            ->fetchColumn();
        $this->assertNotSame('old-sel', $newSelector);
        $this->assertSame(0, $this->pdo
            ->query("SELECT COUNT(*) FROM auth_remember_tokens WHERE selector = 'old-sel'")
            ->fetchColumn());
    }

    #[Test]
    public function staleRememberedCookieCannotBeReplayed(): void
    {
        $this->insertToken($this->userId, 'old-sel', 'old-validator');

        $_COOKIE['remember'] = 'old-sel:old-validator';

        $first = new Session(\Flight::app(), TestHelper::getConfig());
        $this->assertTrue($first->loggedIn());

        // Second request starts from a fresh session (no session field yet)
        $newSelector = (string) $this->pdo->query('SELECT selector FROM auth_remember_tokens LIMIT 1')->fetchColumn();
        $_SESSION = [];

        $replay = new Session(\Flight::app(), TestHelper::getConfig());
        $this->assertFalse($replay->loggedIn(), 'rotated cookie must not be accepted again');

        $this->assertSame(1, $this->countTokens());
        $this->assertNotSame('old-sel', $newSelector);
    }

    #[Test]
    public function expiredRememberTokenIsNotAcceptedAndRowIsKeptForGc(): void
    {
        $this->insertToken($this->userId, 'expired-sel', 'expired-validator', '2020-01-01 00:00:00');

        $_COOKIE['remember'] = 'expired-sel:expired-validator';

        $auth = new Session(\Flight::app(), TestHelper::getConfig());

        $this->assertFalse($auth->loggedIn());
        // Lazy GC: the expired row stays in place until purgeExpired() runs
        $this->assertSame(1, $this->countTokens());
    }
}