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
 * The user service details the existing tests leave open: default
 * arguments, username derivation, the retry loop, and the transaction
 * ownership rules.
 */
#[CoversClass(UserManagement::class)]
class UserManagementDetailTest extends TestCase
{
    protected PDO $pdo;
    protected UserManagement $users;

    /** @var array<string, mixed> */
    protected array $config;

    protected function setUp(): void
    {
        $this->pdo = TestHelper::createDatabase();
        TestHelper::resetFlight();
        TestHelper::registerFlightDb($this->pdo);

        $now = (new \DateTimeImmutable())->format('Y-m-d H:i:s');
        $this->pdo->exec("INSERT INTO auth_groups (alias, title, created_at, updated_at) VALUES ('user', 'User', '{$now}', '{$now}')");
        $this->pdo->exec("INSERT INTO auth_groups (alias, title, created_at, updated_at) VALUES ('admin', 'Admin', '{$now}', '{$now}')");

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

    private function usernameOf(int $userId): string
    {
        return (string) $this->pdo
            ->query("SELECT username FROM users WHERE id = {$userId}")
            ->fetchColumn();
    }

    private function groupCount(int $userId): int
    {
        return (int) $this->pdo
            ->query("SELECT COUNT(*) FROM auth_groups_users WHERE user_id = {$userId}")
            ->fetchColumn();
    }

    // -----------------------------------------------------------------
    // Default arguments
    // -----------------------------------------------------------------

    #[Test]
    public function paginatedDefaultsToOnePageOfTwenty(): void
    {
        for ($i = 1; $i <= 25; $i++) {
            $this->makeUser("user{$i}@example.com", "user{$i}");
        }

        $page = $this->users->paginated();

        $this->assertCount(20, $page);
    }

    #[Test]
    public function paginatedDefaultsToExcludingSuperadmins(): void
    {
        $this->makeUser('admin@example.com', 'adminuser', 'superadmin');
        $this->makeUser('plain@example.com', 'plainuser');

        $this->assertCount(1, $this->users->paginated());
    }

    #[Test]
    public function findDefaultsToIncludingSuperadmins(): void
    {
        $admin = $this->makeUser('admin@example.com', 'adminuser', 'superadmin');

        $found = $this->users->find($admin->id);

        $this->assertNotNull($found);
        $this->assertSame($admin->id, $found->id);
    }

    #[Test]
    public function createDefaultsToAnActiveAccount(): void
    {
        $result = $this->users->create('', 'new@example.com', 'Str0ng!Passw0rd');

        $this->assertTrue($result->isOK());

        /** @var User $user */
        $user = $result->extraInfo();
        $this->assertTrue($user->isActivated());
    }

    #[Test]
    public function createDefaultsToTheConfiguredGroup(): void
    {
        $this->config['default_group'] = 'admin';
        $users = new UserManagement($this->pdo, $this->config);

        $result = $users->create('', 'new@example.com', 'Str0ng!Passw0rd');

        $this->assertTrue($result->isOK());

        /** @var User $user */
        $user = $result->extraInfo();
        $this->assertSame(1, $this->groupCount($user->id));
        $this->assertSame(
            'admin',
            (string) $this->pdo->query("SELECT group_alias FROM auth_groups_users WHERE user_id = {$user->id}")->fetchColumn()
        );
    }

    #[Test]
    public function createFallsBackToTheUserGroup(): void
    {
        unset($this->config['default_group']);
        $users = new UserManagement($this->pdo, $this->config);

        $result = $users->create('', 'new@example.com', 'Str0ng!Passw0rd');

        $this->assertTrue($result->isOK());

        /** @var User $user */
        $user = $result->extraInfo();
        $this->assertSame(
            'user',
            (string) $this->pdo->query("SELECT group_alias FROM auth_groups_users WHERE user_id = {$user->id}")->fetchColumn()
        );
    }

    #[Test]
    public function createLowercasesTheGroupAliasForTheLookup(): void
    {
        $result = $this->users->create('', 'new@example.com', 'Str0ng!Passw0rd', 'ADMIN');

        $this->assertTrue($result->isOK());

        /** @var User $user */
        $user = $result->extraInfo();
        $this->assertSame(
            'ADMIN',
            (string) $this->pdo->query("SELECT group_alias FROM auth_groups_users WHERE user_id = {$user->id}")->fetchColumn()
        );
    }

    #[Test]
    public function anUnknownGroupIsRejectedRegardlessOfCase(): void
    {
        $result = $this->users->create('', 'new@example.com', 'Str0ng!Passw0rd', 'NOPE');

        $this->assertFalse($result->isOK());
        $this->assertSame("Group 'NOPE' does not exist.", $result->reason());
    }

    // -----------------------------------------------------------------
    // Username derivation
    // -----------------------------------------------------------------

    #[Test]
    public function aDerivedUsernameComesFromTheEmailLocalPart(): void
    {
        $result = $this->users->create('', 'jane.doe@example.com', 'Str0ng!Passw0rd');

        $this->assertTrue($result->isOK());

        /** @var User $user */
        $user = $result->extraInfo();
        $this->assertSame('jane.doe', $this->usernameOf($user->id));
    }

    #[Test]
    public function aDerivedUsernameStripsDisallowedCharacters(): void
    {
        $result = $this->users->create('', 'ja!ne+doe@example.com', 'Str0ng!Passw0rd');

        $this->assertTrue($result->isOK());

        /** @var User $user */
        $user = $result->extraInfo();
        $this->assertSame('janedoe', $this->usernameOf($user->id));
    }

    #[Test]
    public function aDerivedUsernameTrimsLeadingAndTrailingDots(): void
    {
        $result = $this->users->create('', 'jane.doe.1@example.com', 'Str0ng!Passw0rd');

        $this->assertTrue($result->isOK());

        /** @var User $user */
        $user = $result->extraInfo();
        $this->assertSame('jane.doe.1', $this->usernameOf($user->id));
    }

    #[Test]
    public function aLocalPartWithInnerDotsKeepsThem(): void
    {
        $result = $this->users->create('', 'a.b.c@example.com', 'Str0ng!Passw0rd');

        $this->assertTrue($result->isOK());

        /** @var User $user */
        $user = $result->extraInfo();
        $this->assertSame('a.b.c', $this->usernameOf($user->id));
    }

    #[Test]
    public function aShortLocalPartIsPadded(): void
    {
        $result = $this->users->create('', 'ab@example.com', 'Str0ng!Passw0rd');

        $this->assertTrue($result->isOK());

        /** @var User $user */
        $user = $result->extraInfo();
        $this->assertSame('userab', $this->usernameOf($user->id));
    }

    #[Test]
    public function aLongLocalPartIsTruncatedToThirtyCharacters(): void
    {
        $local = str_repeat('a', 40);
        $result = $this->users->create('', $local . '@example.com', 'Str0ng!Passw0rd');

        $this->assertTrue($result->isOK());

        /** @var User $user */
        $user = $result->extraInfo();
        $this->assertSame(30, strlen($this->usernameOf($user->id)));
    }

    #[Test]
    public function aTakenDerivedUsernameGetsASuffix(): void
    {
        $this->makeUser('taken@example.com', 'jane');

        $result = $this->users->create('', 'jane@example.com', 'Str0ng!Passw0rd');

        $this->assertTrue($result->isOK());

        /** @var User $user */
        $user = $result->extraInfo();
        $this->assertSame('jane2', $this->usernameOf($user->id));
    }

    #[Test]
    public function aTakenDerivedUsernameKeepsAdvancingTheSuffix(): void
    {
        $this->makeUser('taken1@example.com', 'jane');
        $this->makeUser('taken2@example.com', 'jane2');
        $this->makeUser('taken3@example.com', 'jane3');

        $result = $this->users->create('', 'jane@example.com', 'Str0ng!Passw0rd');

        $this->assertTrue($result->isOK());

        /** @var User $user */
        $user = $result->extraInfo();
        $this->assertSame('jane4', $this->usernameOf($user->id));
    }

    #[Test]
    public function aSuffixedUsernameStaysWithinThirtyCharacters(): void
    {
        $local = str_repeat('a', 30);
        $this->makeUser('taken@example.com', $local);

        $result = $this->users->create('', $local . '@example.com', 'Str0ng!Passw0rd');

        $this->assertTrue($result->isOK());

        /** @var User $user */
        $user = $result->extraInfo();
        $username = $this->usernameOf($user->id);

        $this->assertSame(30, strlen($username));
        $this->assertStringEndsWith('2', $username);
    }

    #[Test]
    public function aSuppliedUsernameIsTrimmed(): void
    {
        $result = $this->users->create('  bob  ', 'bob@example.com', 'Str0ng!Passw0rd');

        $this->assertTrue($result->isOK());

        /** @var User $user */
        $user = $result->extraInfo();
        $this->assertSame('bob', $this->usernameOf($user->id));
    }

    #[Test]
    public function anEmailIsTrimmedBeforeValidation(): void
    {
        $result = $this->users->create('', '  bob@example.com  ', 'Str0ng!Passw0rd');

        $this->assertTrue($result->isOK());

        /** @var User $user */
        $user = $result->extraInfo();
        $this->assertSame('bob@example.com', $this->users->getEmail($user));
    }

    // -----------------------------------------------------------------
    // Transaction ownership
    // -----------------------------------------------------------------

    #[Test]
    public function createJoinsAnExistingTransaction(): void
    {
        $this->pdo->beginTransaction();

        $result = $this->users->create('', 'new@example.com', 'Str0ng!Passw0rd');

        $this->assertTrue($result->isOK());
        $this->assertTrue($this->pdo->inTransaction());

        $this->pdo->rollBack();

        $this->assertSame(0, (int) $this->pdo->query('SELECT COUNT(*) FROM users')->fetchColumn());
    }

    #[Test]
    public function createCommitsItsOwnTransaction(): void
    {
        $result = $this->users->create('', 'new@example.com', 'Str0ng!Passw0rd');

        $this->assertTrue($result->isOK());
        $this->assertFalse($this->pdo->inTransaction());
        $this->assertSame(1, (int) $this->pdo->query('SELECT COUNT(*) FROM users')->fetchColumn());
    }

    #[Test]
    public function updateProfileJoinsAnExistingTransaction(): void
    {
        $user = $this->makeUser('user@example.com', 'user');

        $this->pdo->beginTransaction();

        $result = $this->users->updateProfile($user, ['username' => 'renamed']);

        $this->assertTrue($result->isOK());
        $this->assertTrue($this->pdo->inTransaction());

        $this->pdo->rollBack();

        $this->assertSame('user', $this->usernameOf($user->id));
    }

    #[Test]
    public function updateProfileCommitsItsOwnTransaction(): void
    {
        $user = $this->makeUser('user@example.com', 'user');

        $result = $this->users->updateProfile($user, ['username' => 'renamed']);

        $this->assertTrue($result->isOK());
        $this->assertFalse($this->pdo->inTransaction());
        $this->assertSame('renamed', $this->usernameOf($user->id));
    }

    // -----------------------------------------------------------------
    // Profile details
    // -----------------------------------------------------------------

    #[Test]
    public function aUsernameOnlyUpdateSkipsTheIdentity(): void
    {
        $user = $this->makeUser('user@example.com', 'user');

        $result = $this->users->updateProfile($user, ['username' => 'renamed']);

        $this->assertTrue($result->isOK());
        $this->assertSame('renamed', $this->usernameOf($user->id));
        $this->assertSame('user@example.com', $this->users->getEmail($user));
    }

    #[Test]
    public function anEmailUpdateIsTrimmed(): void
    {
        $user = $this->makeUser('user@example.com', 'user');

        $result = $this->users->updateProfile($user, ['email' => '  new@example.com  ']);

        $this->assertTrue($result->isOK());
        $this->assertSame('new@example.com', $this->users->getEmail($user));
    }

    #[Test]
    public function aPasswordUpdateRehashesTheSecret(): void
    {
        $user = $this->makeUser('user@example.com', 'user');

        $before = (string) $this->pdo->query("SELECT secret2 FROM auth_identities WHERE user_id = {$user->id}")->fetchColumn();

        $result = $this->users->updateProfile($user, ['password' => 'An0ther!Passw0rd']);

        $this->assertTrue($result->isOK());

        $after = (string) $this->pdo->query("SELECT secret2 FROM auth_identities WHERE user_id = {$user->id}")->fetchColumn();
        $this->assertNotSame($before, $after);
        $this->assertTrue(password_verify('An0ther!Passw0rd', $after));
    }

    #[Test]
    public function aPasswordFailureReportsTheValidatorReason(): void
    {
        $user = $this->makeUser('user@example.com', 'user');

        $result = $this->users->updateProfile($user, ['password' => 'short']);

        $this->assertFalse($result->isOK());
        $this->assertNotSame('Password does not meet requirements.', $result->reason());
        $this->assertNotNull($result->reason());
    }

    #[Test]
    public function aPasswordFailureOnCreateReportsTheValidatorReason(): void
    {
        $result = $this->users->create('', 'new@example.com', 'short');

        $this->assertFalse($result->isOK());
        $this->assertNotSame('Password does not meet requirements.', $result->reason());
    }

    // -----------------------------------------------------------------
    // Account status
    // -----------------------------------------------------------------

    #[Test]
    public function setActiveActivatesAnInactiveUser(): void
    {
        $user = $this->makeUser('user@example.com', 'user');
        $this->pdo->exec("UPDATE users SET active = 0 WHERE id = {$user->id}");

        $reloaded = (new User($this->pdo))->findById($user->id);
        $this->assertNotNull($reloaded);

        $result = $this->users->setActive($reloaded, true);

        $this->assertTrue($result->isOK());
        $this->assertSame(1, (int) $this->pdo->query("SELECT active FROM users WHERE id = {$user->id}")->fetchColumn());
    }

    #[Test]
    public function setActiveDeactivatesAnActiveUser(): void
    {
        $user = $this->makeUser('user@example.com', 'user');

        $result = $this->users->setActive($user, false);

        $this->assertTrue($result->isOK());
        $this->assertSame(0, (int) $this->pdo->query("SELECT active FROM users WHERE id = {$user->id}")->fetchColumn());
    }

    #[Test]
    public function setActiveUpdatesTheTimestamp(): void
    {
        $user = $this->makeUser('user@example.com', 'user');
        $this->pdo->exec("UPDATE users SET updated_at = '2000-01-01 00:00:00' WHERE id = {$user->id}");

        $reloaded = (new User($this->pdo))->findById($user->id);
        $this->assertNotNull($reloaded);

        $this->users->setActive($reloaded, false);

        $updatedAt = (string) $this->pdo->query("SELECT updated_at FROM users WHERE id = {$user->id}")->fetchColumn();
        $this->assertNotSame('2000-01-01 00:00:00', $updatedAt);
    }
}
