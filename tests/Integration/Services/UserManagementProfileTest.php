<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Integration\Services;

use Enlivenapp\FlightShield\Models\User;
use Enlivenapp\FlightShield\Models\UserIdentity;
use Enlivenapp\FlightShield\Services\UserManagement;
use Enlivenapp\FlightShield\Services\UserManagement as UserManagementAlias;
use Enlivenapp\FlightShield\Tests\TestHelper;
use PDO;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Profile updates: username, email and password changes.
 */
#[CoversClass(UserManagementAlias::class)]
class UserManagementProfileTest extends TestCase
{
    protected PDO $pdo;
    protected UserManagement $users;
    protected User $user;

    protected function setUp(): void
    {
        $this->pdo = TestHelper::createDatabase();
        TestHelper::resetFlight();
        TestHelper::registerFlightDb($this->pdo);

        $this->users = new UserManagement($this->pdo, TestHelper::getConfig());
        $this->user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'bob', true);
    }

    protected function tearDown(): void
    {
        TestHelper::resetFlight();
    }

    private function emailIdentity(): UserIdentity
    {
        return (new UserIdentity($this->pdo))->getEmailIdentity($this->user);
    }

    #[Test]
    public function updatingOnlyTheUsernameSaves(): void
    {
        $result = $this->users->updateProfile($this->user, ['username' => 'bobby']);

        $this->assertTrue($result->isOK());
        $this->assertSame('bobby', (new User($this->pdo))->findById($this->user->id)->username);
    }

    #[Test]
    public function anEmptyUsernameIsRejected(): void
    {
        $result = $this->users->updateProfile($this->user, ['username' => '   ']);

        $this->assertFalse($result->isOK());
        $this->assertSame('Username cannot be empty.', $result->reason());
    }

    #[Test]
    public function aTakenUsernameIsRejected(): void
    {
        TestHelper::createUser($this->pdo, 'other@example.com', 'Str0ng!Passw0rd', 'taken', true);

        $result = $this->users->updateProfile($this->user, ['username' => 'taken']);

        $this->assertFalse($result->isOK());
        $this->assertSame('Username is already in use.', $result->reason());
    }

    #[Test]
    public function keepingTheSameUsernameIsAllowed(): void
    {
        $result = $this->users->updateProfile($this->user, ['username' => 'bob']);

        $this->assertTrue($result->isOK());
    }

    #[Test]
    public function aValidEmailChangeIsSaved(): void
    {
        $result = $this->users->updateProfile($this->user, ['email' => 'new@example.com']);

        $this->assertTrue($result->isOK());
        $this->assertSame('new@example.com', $this->emailIdentity()->secret);
    }

    #[Test]
    public function anInvalidEmailIsRejected(): void
    {
        $result = $this->users->updateProfile($this->user, ['email' => 'nope']);

        $this->assertFalse($result->isOK());
        $this->assertSame('A valid email address is required.', $result->reason());
    }

    #[Test]
    public function anEmailUsedByAnotherAccountIsRejected(): void
    {
        TestHelper::createUser($this->pdo, 'other@example.com', 'Str0ng!Passw0rd', 'other', true);

        $result = $this->users->updateProfile($this->user, ['email' => 'other@example.com']);

        $this->assertFalse($result->isOK());
        $this->assertSame('Email address is already in use.', $result->reason());
    }

    #[Test]
    public function aWeakPasswordIsRejected(): void
    {
        $result = $this->users->updateProfile($this->user, ['password' => 'short']);

        $this->assertFalse($result->isOK());
    }

    #[Test]
    public function aValidPasswordIsRehashed(): void
    {
        $before = $this->emailIdentity()->secret2;

        $result = $this->users->updateProfile($this->user, ['password' => 'An0ther!Str0ng']);

        $this->assertTrue($result->isOK());
        $this->assertNotSame($before, $this->emailIdentity()->secret2);
    }

    #[Test]
    public function updatingWithoutAnIdentityIsRejected(): void
    {
        $this->pdo->exec("DELETE FROM auth_identities WHERE user_id = {$this->user->id}");

        $result = $this->users->updateProfile($this->user, ['email' => 'new@example.com']);

        $this->assertFalse($result->isOK());
        $this->assertSame('User has no email/password identity to update.', $result->reason());
    }

    #[Test]
    public function anEmptyPasswordStringIsTreatedAsNoChange(): void
    {
        $before = $this->emailIdentity()->secret2;

        $result = $this->users->updateProfile($this->user, ['password' => '']);

        $this->assertTrue($result->isOK());
        $this->assertSame($before, $this->emailIdentity()->secret2);
    }
}
