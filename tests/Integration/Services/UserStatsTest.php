<?php

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Integration\Services;

use Enlivenapp\FlightShield\Services\UserStats;
use Enlivenapp\FlightShield\Tests\TestHelper;
use PDO;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(UserStats::class)]
class UserStatsTest extends TestCase
{
    protected PDO $pdo;
    protected UserStats $stats;

    protected function setUp(): void
    {
        $this->pdo   = TestHelper::createDatabase();
        $this->stats = new UserStats($this->pdo);
    }

    protected function insertLogin(bool $success, string $date): void
    {
        $this->pdo->prepare(
            'INSERT INTO auth_logins (ip_address, id_type, identifier, date, success)
             VALUES (?, ?, ?, ?, ?)'
        )->execute(['1.2.3.4', 'email', 'user@test.com', $date, $success ? 1 : 0]);
    }

    protected function insertGroupUser(int $userId, string $groupAlias): void
    {
        $this->pdo->prepare(
            'INSERT INTO auth_groups_users (user_id, group_alias, created_at) VALUES (?, ?, ?)'
        )->execute([$userId, $groupAlias, date('Y-m-d H:i:s')]);
    }

    // -----------------------------------------------------------------
    // totalUsers / activeUsers / inactiveUsers / bannedUsers
    // -----------------------------------------------------------------

    #[Test]
    public function totalUsersCountsNonDeletedUsers(): void
    {
        TestHelper::createUser($this->pdo, 'a@test.com', 'pass1234', 'u1', true);
        $deleted = TestHelper::createUser($this->pdo, 'b@test.com', 'pass1234', 'u2', true);
        $this->pdo->prepare('UPDATE users SET deleted_at = ? WHERE id = ?')
            ->execute([date('Y-m-d H:i:s'), $deleted->id]);

        $this->assertSame(1, $this->stats->totalUsers());
    }

    #[Test]
    public function activeUsersCountsActiveNonDeletedUsers(): void
    {
        TestHelper::createUser($this->pdo, 'a@test.com', 'pass1234', 'active', true);
        TestHelper::createUser($this->pdo, 'b@test.com', 'pass1234', 'inactive', false);

        $this->assertSame(1, $this->stats->activeUsers());
    }

    #[Test]
    public function inactiveUsersCountsInactiveNonBannedUsers(): void
    {
        TestHelper::createUser($this->pdo, 'a@test.com', 'pass1234', 'inactive1', false);
        $banned = TestHelper::createUser($this->pdo, 'b@test.com', 'pass1234', 'banned1', false);
        $this->pdo->prepare("UPDATE users SET status = 'banned' WHERE id = ?")
            ->execute([$banned->id]);

        $this->assertSame(1, $this->stats->inactiveUsers());
    }

    #[Test]
    public function bannedUsersCountsBannedUsers(): void
    {
        $u = TestHelper::createUser($this->pdo, 'a@test.com', 'pass1234', 'banned', false);
        $this->pdo->prepare("UPDATE users SET status = 'banned' WHERE id = ?")
            ->execute([$u->id]);

        $this->assertSame(1, $this->stats->bannedUsers());
    }

    // -----------------------------------------------------------------
    // usersByGroup
    // -----------------------------------------------------------------

    #[Test]
    public function usersByGroupReturnsGroupCounts(): void
    {
        $u1 = TestHelper::createUser($this->pdo, 'a@test.com', 'pass1234', 'u1', true);
        $u2 = TestHelper::createUser($this->pdo, 'b@test.com', 'pass1234', 'u2', true);

        $this->insertGroupUser($u1->id, 'admin');
        $this->insertGroupUser($u2->id, 'user');

        $result = $this->stats->usersByGroup();

        $this->assertSame(1, $result['admin']);
        $this->assertSame(1, $result['user']);
    }

    // -----------------------------------------------------------------
    // newUsersThisMonth / newUsersLastMonth
    // -----------------------------------------------------------------

    #[Test]
    public function newUsersThisMonthCountsUsersCreatedThisMonth(): void
    {
        // Created "now" by TestHelper — should be in this month
        TestHelper::createUser($this->pdo, 'a@test.com', 'pass1234', 'new1', true);

        // Old user
        $old = TestHelper::createUser($this->pdo, 'b@test.com', 'pass1234', 'old1', true);
        $this->pdo->prepare('UPDATE users SET created_at = ? WHERE id = ?')
            ->execute(['2020-01-15 00:00:00', $old->id]);

        $this->assertSame(1, $this->stats->newUsersThisMonth());
    }

    #[Test]
    public function newUsersLastMonthCountsUsersCreatedLastMonth(): void
    {
        $firstOfLastMonth = (new \DateTimeImmutable('first day of last month'))->format('Y-m-d');
        $midLastMonth = $firstOfLastMonth . ' 12:00:00';

        $u = TestHelper::createUser($this->pdo, 'a@test.com', 'pass1234', 'last_month', true);
        $this->pdo->prepare('UPDATE users SET created_at = ? WHERE id = ?')
            ->execute([$midLastMonth, $u->id]);

        $this->assertSame(1, $this->stats->newUsersLastMonth());
    }

    // -----------------------------------------------------------------
    // newUsersPercentChange
    // -----------------------------------------------------------------

    #[Test]
    public function newUsersPercentChangeCalculatesGrowth(): void
    {
        $firstOfLastMonth = (new \DateTimeImmutable('first day of last month'))->format('Y-m-d') . ' 12:00:00';

        // 1 user last month
        $uLast = TestHelper::createUser($this->pdo, 'a@test.com', 'pass1234', 'last', true);
        $this->pdo->prepare('UPDATE users SET created_at = ? WHERE id = ?')
            ->execute([$firstOfLastMonth, $uLast->id]);

        // 2 users this month
        TestHelper::createUser($this->pdo, 'b@test.com', 'pass1234', 'this1', true);
        TestHelper::createUser($this->pdo, 'c@test.com', 'pass1234', 'this2', true);

        // (2 - 1) / 1 * 100 = 100.0
        $this->assertSame(100.0, $this->stats->newUsersPercentChange());
    }

    #[Test]
    public function newUsersPercentChangeHandlesZeroLastMonth(): void
    {
        // 1 user this month, 0 last month
        TestHelper::createUser($this->pdo, 'a@test.com', 'pass1234', 'this1', true);

        $this->assertSame(100.0, $this->stats->newUsersPercentChange());
    }

    #[Test]
    public function newUsersPercentChangeReturnsZeroWhenBothMonthsEmpty(): void
    {
        $this->assertSame(0.0, $this->stats->newUsersPercentChange());
    }

    // -----------------------------------------------------------------
    // loginAttempts / loginAttemptsByDay
    // -----------------------------------------------------------------

    #[Test]
    public function loginAttemptsReturnsSummary(): void
    {
        $recent = (new \DateTimeImmutable('-1 day'))->format('Y-m-d H:i:s');

        $this->insertLogin(true,  $recent);
        $this->insertLogin(false, $recent);

        $result = $this->stats->loginAttempts(30);

        $this->assertSame(2, $result['total']);
        $this->assertSame(1, $result['success']);
        $this->assertSame(1, $result['failed']);
    }

    #[Test]
    public function loginAttemptsByDayReturnsDailyBreakdown(): void
    {
        $today = date('Y-m-d');
        $this->insertLogin(true,  $today . ' 10:00:00');
        $this->insertLogin(false, $today . ' 11:00:00');

        $result = $this->stats->loginAttemptsByDay(30);

        $this->assertArrayHasKey($today, $result);
        $this->assertSame(1, $result[$today]['success']);
        $this->assertSame(1, $result[$today]['failed']);
    }

    // -----------------------------------------------------------------
    // countNewByMonth — skipped (DATE_FORMAT is MySQL-only, tests use SQLite)
    // -----------------------------------------------------------------
}
