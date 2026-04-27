<?php

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Integration\Models;

use Enlivenapp\FlightShield\Models\User;
use Enlivenapp\FlightShield\Tests\TestHelper;
use PDO;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(User::class)]
class UserAggregatesTest extends TestCase
{
    protected PDO $pdo;
    protected User $model;

    protected function setUp(): void
    {
        $this->pdo   = TestHelper::createDatabase();
        $this->model = new User($this->pdo);
    }

    // -----------------------------------------------------------------
    // countActive
    // -----------------------------------------------------------------

    #[Test]
    public function countActiveReturnsActiveNonDeletedCount(): void
    {
        TestHelper::createUser($this->pdo, 'a@test.com', 'pass1234', 'active1', true);
        TestHelper::createUser($this->pdo, 'b@test.com', 'pass1234', 'active2', true);
        TestHelper::createUser($this->pdo, 'c@test.com', 'pass1234', 'inactive1', false);

        $this->assertSame(2, $this->model->countActive());
    }

    #[Test]
    public function countActiveExcludesSoftDeletedUsers(): void
    {
        $user = TestHelper::createUser($this->pdo, 'a@test.com', 'pass1234', 'active1', true);
        TestHelper::createUser($this->pdo, 'b@test.com', 'pass1234', 'active2', true);

        $this->pdo->prepare('UPDATE users SET deleted_at = ? WHERE id = ?')
            ->execute([date('Y-m-d H:i:s'), $user->id]);

        $this->assertSame(1, $this->model->countActive());
    }

    #[Test]
    public function countActiveReturnsZeroOnEmptyTable(): void
    {
        $this->assertSame(0, $this->model->countActive());
    }

    // -----------------------------------------------------------------
    // countInactive
    // -----------------------------------------------------------------

    #[Test]
    public function countInactiveReturnsInactiveNonBannedCount(): void
    {
        TestHelper::createUser($this->pdo, 'a@test.com', 'pass1234', 'active1', true);
        TestHelper::createUser($this->pdo, 'b@test.com', 'pass1234', 'inactive1', false);
        TestHelper::createUser($this->pdo, 'c@test.com', 'pass1234', 'inactive2', false);

        $this->assertSame(2, $this->model->countInactive());
    }

    #[Test]
    public function countInactiveExcludesBannedUsers(): void
    {
        TestHelper::createUser($this->pdo, 'a@test.com', 'pass1234', 'inactive1', false);
        $banned = TestHelper::createUser($this->pdo, 'b@test.com', 'pass1234', 'banned1', false);

        $this->pdo->prepare("UPDATE users SET status = 'banned' WHERE id = ?")
            ->execute([$banned->id]);

        $this->assertSame(1, $this->model->countInactive());
    }

    #[Test]
    public function countInactiveExcludesSoftDeletedUsers(): void
    {
        $user = TestHelper::createUser($this->pdo, 'a@test.com', 'pass1234', 'inactive1', false);
        TestHelper::createUser($this->pdo, 'b@test.com', 'pass1234', 'inactive2', false);

        $this->pdo->prepare('UPDATE users SET deleted_at = ? WHERE id = ?')
            ->execute([date('Y-m-d H:i:s'), $user->id]);

        $this->assertSame(1, $this->model->countInactive());
    }

    // -----------------------------------------------------------------
    // countBanned
    // -----------------------------------------------------------------

    #[Test]
    public function countBannedReturnsBannedNonDeletedCount(): void
    {
        $u1 = TestHelper::createUser($this->pdo, 'a@test.com', 'pass1234', 'banned1', false);
        $u2 = TestHelper::createUser($this->pdo, 'b@test.com', 'pass1234', 'banned2', false);
        TestHelper::createUser($this->pdo, 'c@test.com', 'pass1234', 'normal', true);

        $this->pdo->prepare("UPDATE users SET status = 'banned' WHERE id IN (?, ?)")
            ->execute([$u1->id, $u2->id]);

        $this->assertSame(2, $this->model->countBanned());
    }

    #[Test]
    public function countBannedExcludesDeletedBannedUsers(): void
    {
        $u1 = TestHelper::createUser($this->pdo, 'a@test.com', 'pass1234', 'banned1', false);
        $u2 = TestHelper::createUser($this->pdo, 'b@test.com', 'pass1234', 'banned2', false);

        $this->pdo->exec("UPDATE users SET status = 'banned'");
        $this->pdo->prepare('UPDATE users SET deleted_at = ? WHERE id = ?')
            ->execute([date('Y-m-d H:i:s'), $u2->id]);

        $this->assertSame(1, $this->model->countBanned());
    }

    // -----------------------------------------------------------------
    // countNewSince
    // -----------------------------------------------------------------

    #[Test]
    public function countNewSinceCountsUsersCreatedAfterDate(): void
    {
        TestHelper::createUser($this->pdo, 'a@test.com', 'pass1234', 'new1', true);
        TestHelper::createUser($this->pdo, 'b@test.com', 'pass1234', 'new2', true);

        $old = TestHelper::createUser($this->pdo, 'c@test.com', 'pass1234', 'old1', true);
        $this->pdo->prepare('UPDATE users SET created_at = ? WHERE id = ?')
            ->execute(['2020-01-01 00:00:00', $old->id]);

        $this->assertSame(2, $this->model->countNewSince('2025-01-01'));
    }

    #[Test]
    public function countNewSinceReturnsZeroWhenNoneMatch(): void
    {
        $old = TestHelper::createUser($this->pdo, 'a@test.com', 'pass1234', 'old1', true);
        $this->pdo->prepare('UPDATE users SET created_at = ? WHERE id = ?')
            ->execute(['2020-01-01 00:00:00', $old->id]);

        $this->assertSame(0, $this->model->countNewSince('2025-01-01'));
    }

    // -----------------------------------------------------------------
    // countNewBetween
    // -----------------------------------------------------------------

    #[Test]
    public function countNewBetweenCountsUsersInDateRange(): void
    {
        $u1 = TestHelper::createUser($this->pdo, 'a@test.com', 'pass1234', 'u1', true);
        $u2 = TestHelper::createUser($this->pdo, 'b@test.com', 'pass1234', 'u2', true);
        $u3 = TestHelper::createUser($this->pdo, 'c@test.com', 'pass1234', 'u3', true);

        $this->pdo->prepare('UPDATE users SET created_at = ? WHERE id = ?')
            ->execute(['2026-03-15 10:00:00', $u1->id]);
        $this->pdo->prepare('UPDATE users SET created_at = ? WHERE id = ?')
            ->execute(['2026-03-20 10:00:00', $u2->id]);
        $this->pdo->prepare('UPDATE users SET created_at = ? WHERE id = ?')
            ->execute(['2026-04-05 10:00:00', $u3->id]);

        $this->assertSame(2, $this->model->countNewBetween('2026-03-01', '2026-04-01'));
    }

    #[Test]
    public function countNewBetweenExcludesUpperBound(): void
    {
        $u1 = TestHelper::createUser($this->pdo, 'a@test.com', 'pass1234', 'u1', true);
        $this->pdo->prepare('UPDATE users SET created_at = ? WHERE id = ?')
            ->execute(['2026-04-01 00:00:00', $u1->id]);

        $this->assertSame(0, $this->model->countNewBetween('2026-03-01', '2026-04-01'));
    }

    // -----------------------------------------------------------------
    // countNewByMonth — skipped (DATE_FORMAT is MySQL-only, tests use SQLite)
    // -----------------------------------------------------------------
}
