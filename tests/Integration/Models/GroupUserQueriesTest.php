<?php

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Integration\Models;

use Enlivenapp\FlightShield\Models\GroupUser;
use Enlivenapp\FlightShield\Tests\TestHelper;
use PDO;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(GroupUser::class)]
class GroupUserQueriesTest extends TestCase
{
    protected PDO $pdo;
    protected GroupUser $model;

    protected function setUp(): void
    {
        $this->pdo   = TestHelper::createDatabase();
        $this->model = new GroupUser($this->pdo);
    }

    protected function insertGroupUser(int $userId, string $groupAlias): void
    {
        $this->pdo->prepare(
            'INSERT INTO auth_groups_users (user_id, group_alias, created_at) VALUES (?, ?, ?)'
        )->execute([$userId, $groupAlias, date('Y-m-d H:i:s')]);
    }

    // -----------------------------------------------------------------
    // countByGroup
    // -----------------------------------------------------------------

    #[Test]
    public function countByGroupReturnsCountsPerGroup(): void
    {
        $u1 = TestHelper::createUser($this->pdo, 'a@test.com', 'pass1234', 'user1', true);
        $u2 = TestHelper::createUser($this->pdo, 'b@test.com', 'pass1234', 'user2', true);
        $u3 = TestHelper::createUser($this->pdo, 'c@test.com', 'pass1234', 'user3', true);

        $this->insertGroupUser($u1->id, 'admin');
        $this->insertGroupUser($u2->id, 'admin');
        $this->insertGroupUser($u3->id, 'user');

        $result = $this->model->countByGroup();

        $this->assertSame(2, $result['admin']);
        $this->assertSame(1, $result['user']);
    }

    #[Test]
    public function countByGroupExcludesDeletedUsers(): void
    {
        $u1 = TestHelper::createUser($this->pdo, 'a@test.com', 'pass1234', 'user1', true);
        $u2 = TestHelper::createUser($this->pdo, 'b@test.com', 'pass1234', 'user2', true);

        $this->insertGroupUser($u1->id, 'admin');
        $this->insertGroupUser($u2->id, 'admin');

        $this->pdo->prepare('UPDATE users SET deleted_at = ? WHERE id = ?')
            ->execute([date('Y-m-d H:i:s'), $u2->id]);

        $result = $this->model->countByGroup();

        $this->assertSame(1, $result['admin']);
    }

    #[Test]
    public function countByGroupReturnsEmptyArrayWhenNoData(): void
    {
        $this->assertSame([], $this->model->countByGroup());
    }
}
