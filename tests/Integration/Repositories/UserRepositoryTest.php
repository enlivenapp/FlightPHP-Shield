<?php

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Integration\Repositories;

use Enlivenapp\FlightShield\Models\User;
use Enlivenapp\FlightShield\Tests\TestHelper;
use PDO;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(User::class)]
class UserRepositoryTest extends TestCase
{
    protected PDO $pdo;
    protected User $model;

    protected function setUp(): void
    {
        $this->pdo   = TestHelper::createDatabase();
        TestHelper::registerFlightDb($this->pdo);
        $this->model = new User($this->pdo);
    }

    // -----------------------------------------------------------------
    // findById
    // -----------------------------------------------------------------

    #[Test]
    public function findByIdWithExistingUserReturnsUser(): void
    {
        $user = TestHelper::createUser($this->pdo, 'alice@example.com', 'password123', 'alice');

        $found = $this->model->findById($user->id);

        $this->assertInstanceOf(User::class, $found);
        $this->assertSame($user->id, $found->id);
        $this->assertSame('alice', $found->username);
    }

    #[Test]
    public function findByIdWithNonExistentIdReturnsNull(): void
    {
        $result = $this->model->findById(99999);

        $this->assertNull($result);
    }

    #[Test]
    public function findByIdExcludesSoftDeletedUsers(): void
    {
        $user = TestHelper::createUser($this->pdo, 'deleted@example.com', 'password123', 'deleted_user');

        $now = (new \DateTimeImmutable())->format('Y-m-d H:i:s');
        $stmt = $this->pdo->prepare('UPDATE users SET deleted_at = ? WHERE id = ?');
        $stmt->execute([$now, $user->id]);

        $result = $this->model->findById($user->id);

        $this->assertNull($result);
    }

    // -----------------------------------------------------------------
    // findByCredentials
    // -----------------------------------------------------------------

    #[Test]
    public function findByCredentialsWithEmailFindsUserViaIdentityTable(): void
    {
        TestHelper::createUser($this->pdo, 'bob@example.com', 'password123', 'bob');

        $found = $this->model->findByCredentials(['email' => 'bob@example.com']);

        $this->assertInstanceOf(User::class, $found);
        $this->assertSame('bob', $found->username);
    }

    #[Test]
    public function findByCredentialsWithUsernameFindsUserViaUsersTable(): void
    {
        TestHelper::createUser($this->pdo, 'carol@example.com', 'password123', 'carol');

        $found = $this->model->findByCredentials(['username' => 'carol']);

        $this->assertInstanceOf(User::class, $found);
        $this->assertSame('carol', $found->username);
    }

    #[Test]
    public function findByCredentialsWithNonExistentEmailReturnsNull(): void
    {
        $result = $this->model->findByCredentials(['email' => 'nobody@example.com']);

        $this->assertNull($result);
    }

    #[Test]
    public function findByCredentialsWithNonExistentUsernameReturnsNull(): void
    {
        $result = $this->model->findByCredentials(['username' => 'ghost']);

        $this->assertNull($result);
    }

    #[Test]
    public function findByCredentialsWithEmptyArrayReturnsNull(): void
    {
        $result = $this->model->findByCredentials([]);

        $this->assertNull($result);
    }

    // -----------------------------------------------------------------
    // findActive
    // -----------------------------------------------------------------

    #[Test]
    public function findActiveReturnsOnlyActiveNonDeletedUsers(): void
    {
        TestHelper::createUser($this->pdo, 'active1@example.com', 'password123', 'active1', true);
        TestHelper::createUser($this->pdo, 'active2@example.com', 'password123', 'active2', true);

        $results = $this->model->findActive();

        $this->assertCount(2, $results);
        foreach ($results as $u) {
            $this->assertInstanceOf(User::class, $u);
            $this->assertTrue((bool) $u->active);
            $this->assertNull($u->deleted_at);
        }
    }

    #[Test]
    public function findActiveExcludesInactiveUsers(): void
    {
        TestHelper::createUser($this->pdo, 'active@example.com', 'password123', 'activeone', true);
        TestHelper::createUser($this->pdo, 'inactive@example.com', 'password123', 'inactiveone', false);

        $results = $this->model->findActive();

        $this->assertCount(1, $results);
        $this->assertSame('activeone', $results[0]->username);
    }

    #[Test]
    public function findActiveExcludesSoftDeletedUsers(): void
    {
        $active  = TestHelper::createUser($this->pdo, 'stay@example.com', 'password123', 'stayuser', true);
        $deleted = TestHelper::createUser($this->pdo, 'gone@example.com', 'password123', 'goneuser', true);

        $now = (new \DateTimeImmutable())->format('Y-m-d H:i:s');
        $stmt = $this->pdo->prepare('UPDATE users SET deleted_at = ? WHERE id = ?');
        $stmt->execute([$now, $deleted->id]);

        $results = $this->model->findActive();

        $this->assertCount(1, $results);
        $this->assertSame('stayuser', $results[0]->username);
    }
}
