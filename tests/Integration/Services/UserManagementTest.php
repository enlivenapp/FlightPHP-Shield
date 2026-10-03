<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Integration\Services;

use Enlivenapp\FlightShield\Models\User;
use Enlivenapp\FlightShield\Services\UserManagement;
use Enlivenapp\FlightShield\Tests\TestHelper;
use PDO;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Profile and account-status writes must come back as Result errors, not
 * escape as server errors when the database rejects the write.
 */
#[CoversClass(UserManagement::class)]
class UserManagementTest extends TestCase
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

    private function service(): UserManagement
    {
        return new UserManagement($this->pdo, TestHelper::getConfig());
    }

    private function usernameOf(int $userId): string
    {
        return (string) $this->pdo
            ->query("SELECT username FROM users WHERE id = {$userId}")
            ->fetchColumn();
    }

    #[Test]
    public function renamingOntoATakenUsernameReturnsAnError(): void
    {
        TestHelper::createUser($this->pdo, 'taken@example.com', 'password123', 'taken');
        $user = TestHelper::createUser($this->pdo, 'other@example.com', 'password123', 'otheruser');

        $result = $this->service()->updateProfile($user, ['username' => 'taken']);

        $this->assertFalse($result->isOK());
        $this->assertStringContainsString('already in use', (string) $result->reason());
        $this->assertSame('otheruser', $this->usernameOf($user->id));
    }

    #[Test]
    public function keepingTheSameUsernameIsAllowed(): void
    {
        $user = TestHelper::createUser($this->pdo, 'same@example.com', 'password123', 'sameuser');

        $result = $this->service()->updateProfile($user, ['username' => 'sameuser']);

        $this->assertTrue($result->isOK());
    }

    #[Test]
    public function setActiveReturnsSuccess(): void
    {
        $user = TestHelper::createUser($this->pdo, 'flip@example.com', 'password123', 'flipuser');

        $result = $this->service()->setActive($user, false);

        $this->assertTrue($result->isOK());
        $this->assertSame(0, (int) $this->pdo
            ->query("SELECT active FROM users WHERE id = {$user->id}")
            ->fetchColumn());
    }

    #[Test]
    public function setActiveReportsAnErrorWhenTheWriteFails(): void
    {
        $user = TestHelper::createUser($this->pdo, 'boom@example.com', 'password123', 'boomuser');
        $this->pdo->exec('DROP TABLE users');

        $result = $this->service()->setActive($user, true);

        $this->assertFalse($result->isOK());
    }

    #[Test]
    public function deleteReportsAnErrorWhenTheWriteFails(): void
    {
        $user = TestHelper::createUser($this->pdo, 'boom2@example.com', 'password123', 'boomuser2');
        $this->pdo->exec('DROP TABLE users');

        $result = $this->service()->delete($user);

        $this->assertFalse($result->isOK());
    }

    #[Test]
    public function deleteSoftDeletesTheUser(): void
    {
        $user = TestHelper::createUser($this->pdo, 'gone@example.com', 'password123', 'goneuser');

        $result = $this->service()->delete($user);

        $this->assertTrue($result->isOK());
        $this->assertNotNull($this->pdo
            ->query("SELECT deleted_at FROM users WHERE id = {$user->id}")
            ->fetchColumn());
    }
}
