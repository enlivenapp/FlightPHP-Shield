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
class UserSuperadminVisibilityTest extends TestCase
{
    protected PDO $pdo;
    protected User $model;

    protected function setUp(): void
    {
        $this->pdo   = TestHelper::createDatabase();
        TestHelper::registerFlightDb($this->pdo);
        $this->model = new User($this->pdo);
    }

    /**
     * Helper: create a user and assign them to a group.
     */
    private function createUserInGroup(string $email, string $username, string $group): User
    {
        $user = TestHelper::createUser($this->pdo, $email, 'password123', $username);

        $now = (new \DateTimeImmutable())->format('Y-m-d H:i:s');
        $stmt = $this->pdo->prepare(
            'INSERT INTO auth_groups_users (user_id, group_alias, created_at) VALUES (?, ?, ?)'
        );
        $stmt->execute([$user->id, $group, $now]);

        return $user;
    }

    // -----------------------------------------------------------------
    // findAllPaginated — superadmin exclusion
    // -----------------------------------------------------------------

    #[Test]
    public function findAllPaginatedExcludesSuperadminsByDefault(): void
    {
        $this->createUserInGroup('admin@test.com', 'admin1', 'admin');
        $this->createUserInGroup('super@test.com', 'super1', 'superadmin');
        $this->createUserInGroup('user@test.com', 'user1', 'user');

        $results = $this->model->findAllPaginated(1, 20, false);

        $this->assertCount(2, $results);
        $usernames = array_map(fn($u) => $u->username, $results);
        $this->assertContains('admin1', $usernames);
        $this->assertContains('user1', $usernames);
        $this->assertNotContains('super1', $usernames);
    }

    #[Test]
    public function findAllPaginatedIncludesSuperadminsWhenFlagIsTrue(): void
    {
        $this->createUserInGroup('admin@test.com', 'admin1', 'admin');
        $this->createUserInGroup('super@test.com', 'super1', 'superadmin');

        $results = $this->model->findAllPaginated(1, 20, true);

        $this->assertCount(2, $results);
        $usernames = array_map(fn($u) => $u->username, $results);
        $this->assertContains('super1', $usernames);
    }

    #[Test]
    public function findAllPaginatedExcludesSuperadminButKeepsUsersWithOtherGroups(): void
    {
        $user = $this->createUserInGroup('multi@test.com', 'multigroup', 'admin');
        $this->createUserInGroup('super@test.com', 'super1', 'superadmin');

        $results = $this->model->findAllPaginated(1, 20, false);

        $this->assertCount(1, $results);
        $this->assertSame('multigroup', $results[0]->username);
    }

    #[Test]
    public function findAllPaginatedExcludesUserInBothSuperadminAndOtherGroup(): void
    {
        $user = TestHelper::createUser($this->pdo, 'both@test.com', 'password123', 'bothgroups');

        $now = (new \DateTimeImmutable())->format('Y-m-d H:i:s');
        $stmt = $this->pdo->prepare(
            'INSERT INTO auth_groups_users (user_id, group_alias, created_at) VALUES (?, ?, ?)'
        );
        $stmt->execute([$user->id, 'admin', $now]);
        $stmt->execute([$user->id, 'superadmin', $now]);

        $results = $this->model->findAllPaginated(1, 20, false);

        $this->assertCount(0, $results);
    }

    #[Test]
    public function findAllPaginatedRespectsPageAndPerPage(): void
    {
        for ($i = 1; $i <= 5; $i++) {
            $this->createUserInGroup("user{$i}@test.com", "user{$i}", 'user');
        }
        $this->createUserInGroup('super@test.com', 'super1', 'superadmin');

        $page1 = $this->model->findAllPaginated(1, 2, false);
        $page2 = $this->model->findAllPaginated(2, 2, false);
        $page3 = $this->model->findAllPaginated(3, 2, false);

        $this->assertCount(2, $page1);
        $this->assertCount(2, $page2);
        $this->assertCount(1, $page3);
    }

    #[Test]
    public function findAllPaginatedWithNoUsersReturnsEmpty(): void
    {
        $results = $this->model->findAllPaginated(1, 20, false);

        $this->assertCount(0, $results);
    }

    #[Test]
    public function findAllPaginatedExcludesSoftDeletedUsersRegardlessOfFlag(): void
    {
        $user = $this->createUserInGroup('del@test.com', 'deleted1', 'user');

        $this->pdo->prepare('UPDATE users SET deleted_at = ? WHERE id = ?')
            ->execute([date('Y-m-d H:i:s'), $user->id]);

        $results = $this->model->findAllPaginated(1, 20, false);
        $this->assertCount(0, $results);

        $results = $this->model->findAllPaginated(1, 20, true);
        $this->assertCount(0, $results);
    }

    // -----------------------------------------------------------------
    // countAll — superadmin exclusion
    // -----------------------------------------------------------------

    #[Test]
    public function countAllExcludesSuperadminsByDefault(): void
    {
        $this->createUserInGroup('admin@test.com', 'admin1', 'admin');
        $this->createUserInGroup('super@test.com', 'super1', 'superadmin');
        $this->createUserInGroup('user@test.com', 'user1', 'user');

        $this->assertSame(2, $this->model->countAll(false));
    }

    #[Test]
    public function countAllIncludesSuperadminsWhenFlagIsTrue(): void
    {
        $this->createUserInGroup('admin@test.com', 'admin1', 'admin');
        $this->createUserInGroup('super@test.com', 'super1', 'superadmin');

        $this->assertSame(2, $this->model->countAll(true));
    }

    #[Test]
    public function countAllReturnsZeroOnEmptyTable(): void
    {
        $this->assertSame(0, $this->model->countAll(false));
        $this->assertSame(0, $this->model->countAll(true));
    }

    #[Test]
    public function countAllExcludesSoftDeletedRegardlessOfFlag(): void
    {
        $user = $this->createUserInGroup('del@test.com', 'deleted1', 'user');

        $this->pdo->prepare('UPDATE users SET deleted_at = ? WHERE id = ?')
            ->execute([date('Y-m-d H:i:s'), $user->id]);

        $this->assertSame(0, $this->model->countAll(false));
        $this->assertSame(0, $this->model->countAll(true));
    }

    // -----------------------------------------------------------------
    // findById — superadmin guard
    // -----------------------------------------------------------------

    #[Test]
    public function findByIdReturnsSuperadminWhenIncludeIsTrue(): void
    {
        $user = $this->createUserInGroup('super@test.com', 'super1', 'superadmin');

        $found = $this->model->findById($user->id, true);

        $this->assertNotNull($found);
        $this->assertSame('super1', $found->username);
    }

    #[Test]
    public function findByIdReturnsNullForSuperadminWhenIncludeIsFalse(): void
    {
        $user = $this->createUserInGroup('super@test.com', 'super1', 'superadmin');

        $found = $this->model->findById($user->id, false);

        $this->assertNull($found);
    }

    #[Test]
    public function findByIdReturnsNonSuperadminRegardlessOfFlag(): void
    {
        $user = $this->createUserInGroup('admin@test.com', 'admin1', 'admin');

        $this->assertNotNull($this->model->findById($user->id, true));
        $this->assertNotNull($this->model->findById($user->id, false));
    }

    #[Test]
    public function findByIdDefaultsToIncludingSuperadmins(): void
    {
        $user = $this->createUserInGroup('super@test.com', 'super1', 'superadmin');

        $found = $this->model->findById($user->id);

        $this->assertNotNull($found);
    }

    #[Test]
    public function findByIdReturnsNullForNonExistentIdRegardlessOfFlag(): void
    {
        $this->assertNull($this->model->findById(99999, true));
        $this->assertNull($this->model->findById(99999, false));
    }

    #[Test]
    public function findByIdReturnsNullForSoftDeletedSuperadminEvenWhenIncluded(): void
    {
        $user = $this->createUserInGroup('super@test.com', 'super1', 'superadmin');

        $this->pdo->prepare('UPDATE users SET deleted_at = ? WHERE id = ?')
            ->execute([date('Y-m-d H:i:s'), $user->id]);

        $this->assertNull($this->model->findById($user->id, true));
    }

    #[Test]
    public function findByIdGuardsUserInMultipleGroupsIncludingSuperadmin(): void
    {
        $user = TestHelper::createUser($this->pdo, 'both@test.com', 'password123', 'bothgroups');

        $now = (new \DateTimeImmutable())->format('Y-m-d H:i:s');
        $stmt = $this->pdo->prepare(
            'INSERT INTO auth_groups_users (user_id, group_alias, created_at) VALUES (?, ?, ?)'
        );
        $stmt->execute([$user->id, 'admin', $now]);
        $stmt->execute([$user->id, 'superadmin', $now]);

        $this->assertNull($this->model->findById($user->id, false));
        $this->assertNotNull($this->model->findById($user->id, true));
    }
}
