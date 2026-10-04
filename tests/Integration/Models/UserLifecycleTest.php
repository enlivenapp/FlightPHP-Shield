<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Integration\Models;

use Enlivenapp\FlightShield\Models\User;
use Enlivenapp\FlightShield\Models\UserIdentity;
use Enlivenapp\FlightShield\Tests\TestHelper;
use PDO;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * User creation, update, soft delete and the aggregate finders.
 */
#[CoversClass(User::class)]
class UserLifecycleTest extends TestCase
{
    protected PDO $pdo;

    protected function setUp(): void
    {
        $this->pdo = TestHelper::createDatabase();
        TestHelper::resetFlight();
        TestHelper::registerFlightDb($this->pdo);
    }

    protected function tearDown(): void
    {
        TestHelper::resetFlight();
    }

    #[Test]
    public function createUserStoresTheAccountIdentityAndGroup(): void
    {
        $user = (new User($this->pdo))->createUser('bob', 'bob@example.com', 'Str0ng!Passw0rd', 'staff');

        $this->assertTrue($user->isActivated());

        $identity = (new UserIdentity($this->pdo))->getEmailIdentity($user);
        $this->assertNotNull($identity);
        $this->assertSame('bob@example.com', $identity->secret);

        $this->assertTrue($user->inGroup('staff'));
    }

    #[Test]
    public function updateUserRefreshesTheTimestamp(): void
    {
        $user = (new User($this->pdo))->createUser('bob', 'bob@example.com', 'Str0ng!Passw0rd');
        $this->pdo->exec("UPDATE users SET updated_at = '2000-01-01 00:00:00' WHERE id = {$user->id}");

        $user->updated_at = '2000-01-01 00:00:00';
        $user->updateUser();

        $stored = $this->pdo->query("SELECT updated_at FROM users WHERE id = {$user->id}")->fetchColumn();
        $this->assertNotSame('2000-01-01 00:00:00', $stored);
    }

    #[Test]
    public function softDeleteMarksTheRowDeleted(): void
    {
        $user = (new User($this->pdo))->createUser('bob', 'bob@example.com', 'Str0ng!Passw0rd');

        $user->softDelete();

        $stored = $this->pdo->query("SELECT deleted_at FROM users WHERE id = {$user->id}")->fetchColumn();
        $this->assertNotNull($stored);
        $this->assertNull((new User($this->pdo))->findById($user->id));
    }

    #[Test]
    public function findByIdIncludingDeletedStillFindsASoftDeletedUser(): void
    {
        $user = (new User($this->pdo))->createUser('bob', 'bob@example.com', 'Str0ng!Passw0rd');
        $user->softDelete();

        $found = (new User($this->pdo))->findByIdIncludingDeleted($user->id);

        $this->assertNotNull($found);
        $this->assertNotNull($found->deleted_at);
    }

    #[Test]
    public function findActiveReturnsOnlyActiveLiveUsers(): void
    {
        (new User($this->pdo))->createUser('a', 'a@example.com', 'Str0ng!Passw0rd');
        $inactive = (new User($this->pdo))->createUser('b', 'b@example.com', 'Str0ng!Passw0rd');
        $this->pdo->exec("UPDATE users SET active = 0 WHERE id = {$inactive->id}");

        $active = (new User($this->pdo))->findActive();

        $this->assertCount(1, $active);
        $this->assertSame('a', $active[0]->username);
    }

    #[Test]
    public function theCountsSplitByState(): void
    {
        $model = new User($this->pdo);

        $model->createUser('a', 'a@example.com', 'Str0ng!Passw0rd');
        $inactive = $model->createUser('b', 'b@example.com', 'Str0ng!Passw0rd');
        $banned = $model->createUser('c', 'c@example.com', 'Str0ng!Passw0rd');

        $this->pdo->exec("UPDATE users SET active = 0 WHERE id = {$inactive->id}");
        $this->pdo->exec("UPDATE users SET status = 'banned' WHERE id = {$banned->id}");

        // 'c' is banned but still flagged active, so two rows count as active.
        $this->assertSame(2, $model->countActive());
        $this->assertSame(1, $model->countInactive());
        $this->assertSame(1, $model->countBanned());
    }

    #[Test]
    public function theDateRangeCountsInspectCreatedAt(): void
    {
        $model = new User($this->pdo);
        $model->createUser('a', 'a@example.com', 'Str0ng!Passw0rd');

        $yesterday = (new \DateTimeImmutable('-1 day'))->format('Y-m-d H:i:s');
        $tomorrow = (new \DateTimeImmutable('+1 day'))->format('Y-m-d H:i:s');

        $this->assertSame(1, $model->countNewSince($yesterday));
        $this->assertSame(1, $model->countNewBetween($yesterday, $tomorrow));
        $this->assertSame(0, $model->countNewBetween($tomorrow, $tomorrow));
    }

    #[Test]
    public function findAllPaginatedExcludesSuperadminsByDefault(): void
    {
        $model = new User($this->pdo);
        $model->createUser('a', 'a@example.com', 'Str0ng!Passw0rd', 'user');
        $root = $model->createUser('root', 'root@example.com', 'Str0ng!Passw0rd', 'superadmin');

        $this->assertCount(1, $model->findAllPaginated(1, 20));
        $this->assertCount(2, $model->findAllPaginated(1, 20, true));
    }

    #[Test]
    public function countNewByMonthBucketsByRegistrationMonth(): void
    {
        $model = new User($this->pdo);
        $model->createUser('a', 'a@example.com', 'Str0ng!Passw0rd');
        $model->createUser('b', 'b@example.com', 'Str0ng!Passw0rd');

        $byMonth = $model->countNewByMonth(12);

        $this->assertSame([(new \DateTimeImmutable())->format('Y-m') => 2], $byMonth);
    }

    #[Test]
    public function countNewByMonthIgnoresSoftDeletedUsers(): void
    {
        $model = new User($this->pdo);
        $model->createUser('a', 'a@example.com', 'Str0ng!Passw0rd');
        $gone = $model->createUser('b', 'b@example.com', 'Str0ng!Passw0rd');
        $gone->softDelete();

        $this->assertSame([(new \DateTimeImmutable())->format('Y-m') => 1], $model->countNewByMonth(12));
    }
}
