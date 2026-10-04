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
use Enlivenapp\FlightShield\Tests\TestHelper;
use PDO;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The user service: listing, lookup, email resolution and account creation.
 */
#[CoversClass(UserManagement::class)]
class UserManagementQueriesTest extends TestCase
{
    protected PDO $pdo;
    protected UserManagement $users;
    protected array $config;

    protected function setUp(): void
    {
        $this->pdo = TestHelper::createDatabase();
        TestHelper::resetFlight();
        TestHelper::registerFlightDb($this->pdo);

        $now = (new \DateTimeImmutable())->format('Y-m-d H:i:s');
        $this->pdo->exec("INSERT INTO auth_groups (alias, title, created_at, updated_at) VALUES ('user', 'User', '{$now}', '{$now}')");

        $this->config = TestHelper::getConfig();
        $this->users = new UserManagement($this->pdo, $this->config);
    }

    protected function tearDown(): void
    {
        TestHelper::resetFlight();
    }

    private function makeUser(string $email, string $username, string $group = 'user'): User
    {
        $user = TestHelper::createUser($this->pdo, $email, 'Str0ng!Passw0rd', $username, true);
        if ($group !== '') {
            $user->addGroup($group);
        }

        return $user;
    }

    // -----------------------------------------------------------------
    // Listing and lookup
    // -----------------------------------------------------------------

    #[Test]
    public function countReturnsEveryNonDeletedUser(): void
    {
        $this->makeUser('a@example.com', 'a');
        $this->makeUser('b@example.com', 'b');

        $this->assertSame(2, $this->users->count(true));
    }

    #[Test]
    public function countExcludesSuperadminsByDefault(): void
    {
        $this->makeUser('a@example.com', 'a');
        $this->makeUser('root@example.com', 'root', 'superadmin');

        $this->assertSame(1, $this->users->count());
        $this->assertSame(2, $this->users->count(true));
    }

    #[Test]
    public function paginatedReturnsAPageOfUsers(): void
    {
        $this->makeUser('a@example.com', 'a');
        $this->makeUser('b@example.com', 'b');
        $this->makeUser('c@example.com', 'c');

        $page = $this->users->paginated(1, 2, true);

        $this->assertCount(2, $page);
    }

    #[Test]
    public function findReturnsTheUserOrNull(): void
    {
        $user = $this->makeUser('a@example.com', 'a');

        $this->assertSame($user->id, $this->users->find($user->id)->id);
        $this->assertNull($this->users->find(999));
    }

    #[Test]
    public function findHidesSuperadminsWhenAsked(): void
    {
        $root = $this->makeUser('root@example.com', 'root', 'superadmin');

        $this->assertNull($this->users->find($root->id, false));
        $this->assertNotNull($this->users->find($root->id, true));
    }

    #[Test]
    public function getEmailReturnsTheIdentityEmail(): void
    {
        $user = $this->makeUser('a@example.com', 'a');

        $this->assertSame('a@example.com', $this->users->getEmail($user));
    }

    #[Test]
    public function getEmailReturnsNullWithoutAnIdentity(): void
    {
        $user = $this->makeUser('a@example.com', 'a');
        $this->pdo->exec("DELETE FROM auth_identities WHERE user_id = {$user->id}");

        $this->assertNull($this->users->getEmail($user));
    }

    // -----------------------------------------------------------------
    // create()
    // -----------------------------------------------------------------

    #[Test]
    public function createMakesAnAccountAndDerivesAUsername(): void
    {
        $result = $this->users->create('', 'new@example.com', 'Str0ng!Passw0rd');

        $this->assertTrue($result->isOK());

        $user = $result->extraInfo();
        $this->assertSame('new', $user->username);
        $this->assertSame('new@example.com', $this->users->getEmail($user));
    }

    #[Test]
    public function createRejectsAnInvalidEmail(): void
    {
        $result = $this->users->create('', 'not-an-email', 'Str0ng!Passw0rd');

        $this->assertFalse($result->isOK());
        $this->assertSame('A valid email address is required.', $result->reason());
    }

    #[Test]
    public function createRejectsADuplicateEmail(): void
    {
        $this->makeUser('dup@example.com', 'dup');

        $result = $this->users->create('', 'dup@example.com', 'Str0ng!Passw0rd');

        $this->assertFalse($result->isOK());
        $this->assertSame('Email address is already in use.', $result->reason());
    }

    #[Test]
    public function createRejectsATakenUsername(): void
    {
        $this->makeUser('a@example.com', 'taken');

        $result = $this->users->create('taken', 'b@example.com', 'Str0ng!Passw0rd');

        $this->assertFalse($result->isOK());
        $this->assertSame('Username is already in use.', $result->reason());
    }

    #[Test]
    public function createRejectsAWeakPassword(): void
    {
        $result = $this->users->create('', 'new@example.com', 'short');

        $this->assertFalse($result->isOK());
    }

    #[Test]
    public function createRejectsAnUnknownGroup(): void
    {
        $result = $this->users->create('', 'new@example.com', 'Str0ng!Passw0rd', 'ghosts');

        $this->assertFalse($result->isOK());
        $this->assertSame("Group 'ghosts' does not exist.", $result->reason());
    }

    #[Test]
    public function createCanLeaveTheAccountInactiveForActivation(): void
    {
        $result = $this->users->create('', 'new@example.com', 'Str0ng!Passw0rd', null, true);

        $this->assertTrue($result->isOK());
        $this->assertFalse($result->extraInfo()->isActivated());

        $identity = (new UserIdentity($this->pdo))->getEmailIdentity($result->extraInfo());
        $this->assertNotNull($identity);
    }
}
