<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Integration\Authorization;

use Enlivenapp\FlightShield\Authorization\Groups;
use Enlivenapp\FlightShield\Authorization\Permissions;
use Enlivenapp\FlightShield\Models\User;
use Enlivenapp\FlightShield\Tests\TestHelper;
use PDO;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The group service: CRUD, permission mappings and safe deletion.
 */
#[CoversClass(Groups::class)]
class GroupsTest extends TestCase
{
    protected PDO $pdo;
    protected Groups $groups;

    protected function setUp(): void
    {
        $this->pdo = TestHelper::createDatabase();
        TestHelper::resetFlight();
        TestHelper::registerFlightDb($this->pdo);

        $this->groups = new Groups($this->pdo);
    }

    protected function tearDown(): void
    {
        TestHelper::resetFlight();
    }

    #[Test]
    public function createStoresALowercasedGroup(): void
    {
        $group = $this->groups->create('Admin', 'Admins', 'The admins');

        $this->assertSame('admin', $group->alias);
        $this->assertSame('Admins', $group->title);
        $this->assertNotNull($group->id);
    }

    #[Test]
    public function infoFindsByAliasCaseInsensitively(): void
    {
        $this->groups->create('Admin', 'Admins');

        $found = $this->groups->info('ADMIN');

        $this->assertNotNull($found);
        $this->assertSame('admin', $found->alias);
    }

    #[Test]
    public function infoReturnsNullForAnUnknownGroup(): void
    {
        $this->assertNull($this->groups->info('nope'));
    }

    #[Test]
    public function findByIdReturnsTheGroupOrNull(): void
    {
        $group = $this->groups->create('staff', 'Staff');

        $this->assertSame($group->id, $this->groups->findById((int) $group->id)->id);
        $this->assertNull($this->groups->findById(999));
    }

    #[Test]
    public function allReturnsGroupsOrderedByAlias(): void
    {
        $this->groups->create('zeta', 'Zeta');
        $this->groups->create('alpha', 'Alpha');

        $aliases = array_map(static fn ($g) => $g->alias, $this->groups->all());

        $this->assertSame(['alpha', 'zeta'], $aliases);
    }

    #[Test]
    public function saveUpdatesAnExistingGroup(): void
    {
        $group = $this->groups->create('admin', 'Admins');

        $group->title = 'Administrators';
        $group->description = 'changed';
        $this->groups->save($group);

        $reloaded = $this->groups->info('admin');
        $this->assertSame('Administrators', $reloaded->title);
        $this->assertSame('changed', $reloaded->description);
    }

    // -----------------------------------------------------------------
    // Permission mappings
    // -----------------------------------------------------------------

    #[Test]
    public function addPermissionAddsAndListReturnsIt(): void
    {
        $this->groups->create('admin', 'Admins');
        $this->groups->addPermission('admin', 'users.list');

        $this->assertSame(['users.list'], $this->groups->permissions('admin'));
    }

    #[Test]
    public function addPermissionIsIdempotent(): void
    {
        $this->groups->create('admin', 'Admins');
        $this->groups->addPermission('admin', 'users.list');
        $this->groups->addPermission('admin', 'users.list');

        $this->assertSame(['users.list'], $this->groups->permissions('admin'));
    }

    #[Test]
    public function removePermissionRemovesIt(): void
    {
        $this->groups->create('admin', 'Admins');
        $this->groups->addPermission('admin', 'users.list');
        $this->groups->removePermission('admin', 'users.list');

        $this->assertSame([], $this->groups->permissions('admin'));
    }

    #[Test]
    public function removePermissionForAMissingMappingIsSafe(): void
    {
        $this->groups->create('admin', 'Admins');
        $this->groups->removePermission('admin', 'users.list');

        $this->assertSame([], $this->groups->permissions('admin'));
    }

    #[Test]
    public function syncPermissionsSkipsUnknownAliasesAndDeduplicates(): void
    {
        $permissions = new Permissions($this->pdo);
        $permissions->create('users.list');
        $permissions->create('users.edit');

        $this->groups->create('admin', 'Admins');
        $this->groups->addPermission('admin', 'users.list');

        $this->groups->syncPermissions('admin', ['users.edit', 'ghost.permission', 'users.edit']);

        $this->assertSame(['users.edit'], $this->groups->permissions('admin'));
    }

    // -----------------------------------------------------------------
    // Deletion
    // -----------------------------------------------------------------

    #[Test]
    public function deleteRemovesTheGroupAndItsMappings(): void
    {
        (new Permissions($this->pdo))->create('users.list');

        $this->groups->create('admin', 'Admins');
        $this->groups->addPermission('admin', 'users.list');

        $this->groups->delete('admin');

        $this->assertNull($this->groups->info('admin'));
        $this->assertSame(
            0,
            (int) $this->pdo->query("SELECT COUNT(*) FROM auth_group_permissions WHERE group_alias = 'admin'")->fetchColumn()
        );
    }

    #[Test]
    public function deleteReassignsALeftoverUserToTheDefaultGroup(): void
    {
        $user = TestHelper::createUser($this->pdo, 'u@example.com', 'Str0ng!Passw0rd', 'u', true);
        $user->addGroup('admin');

        $this->groups->create('admin', 'Admins');
        $this->groups->delete('admin');

        $reloaded = (new User($this->pdo))->findById($user->id);
        $this->assertTrue($reloaded->inGroup('user'));
    }

    #[Test]
    public function deleteKeepsUsersWhoStillHaveAnotherGroup(): void
    {
        $user = TestHelper::createUser($this->pdo, 'u@example.com', 'Str0ng!Passw0rd', 'u', true);
        $user->addGroup('admin');
        $user->addGroup('staff');

        $this->groups->create('admin', 'Admins');
        $this->groups->delete('admin');

        $reloaded = (new User($this->pdo))->findById($user->id);
        $this->assertSame(['staff'], $reloaded->getGroups());
    }

    #[Test]
    public function deletingAnUnknownGroupIsSafe(): void
    {
        $this->groups->delete('nope');

        $this->assertNull($this->groups->info('nope'));
    }
}
