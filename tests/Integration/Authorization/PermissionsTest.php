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
use Enlivenapp\FlightShield\Tests\TestHelper;
use PDO;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The permission service: CRUD and cascade deletion of assignments.
 */
#[CoversClass(Permissions::class)]
class PermissionsTest extends TestCase
{
    protected PDO $pdo;
    protected Permissions $permissions;

    protected function setUp(): void
    {
        $this->pdo = TestHelper::createDatabase();
        TestHelper::resetFlight();
        TestHelper::registerFlightDb($this->pdo);

        $this->permissions = new Permissions($this->pdo);
    }

    protected function tearDown(): void
    {
        TestHelper::resetFlight();
    }

    #[Test]
    public function createStoresALowercasedPermission(): void
    {
        $permission = $this->permissions->create('Users.List', 'List users');

        $this->assertSame('users.list', $permission->alias);
        $this->assertNotNull($permission->id);
    }

    #[Test]
    public function infoFindsByAliasCaseInsensitively(): void
    {
        $this->permissions->create('Users.List');

        $found = $this->permissions->info('USERS.LIST');

        $this->assertNotNull($found);
        $this->assertSame('users.list', $found->alias);
    }

    #[Test]
    public function infoReturnsNullForAnUnknownPermission(): void
    {
        $this->assertNull($this->permissions->info('nope'));
    }

    #[Test]
    public function findByIdReturnsThePermissionOrNull(): void
    {
        $permission = $this->permissions->create('users.list');

        $this->assertSame($permission->id, $this->permissions->findById((int) $permission->id)->id);
        $this->assertNull($this->permissions->findById(999));
    }

    #[Test]
    public function allReturnsPermissionsOrderedByAlias(): void
    {
        $this->permissions->create('z.a');
        $this->permissions->create('a.b');

        $aliases = array_map(static fn ($p) => $p->alias, $this->permissions->all());

        $this->assertSame(['a.b', 'z.a'], $aliases);
    }

    #[Test]
    public function saveUpdatesAnExistingPermission(): void
    {
        $permission = $this->permissions->create('users.list', 'old');

        $permission->description = 'new';
        $this->permissions->save($permission);

        $this->assertSame('new', $this->permissions->info('users.list')->description);
    }

    #[Test]
    public function deleteRemovesMappingsAndDirectAssignments(): void
    {
        $groups = new Groups($this->pdo);

        $this->permissions->create('users.list');
        $groups->create('admin', 'Admins');
        $groups->addPermission('admin', 'users.list');

        $user = TestHelper::createUser($this->pdo, 'u@example.com', 'Str0ng!Passw0rd', 'u', true);
        $user->addPermission('users.list');

        $this->permissions->delete('users.list');

        $this->assertNull($this->permissions->info('users.list'));
        $this->assertSame(
            0,
            (int) $this->pdo->query("SELECT COUNT(*) FROM auth_group_permissions WHERE permission_alias = 'users.list'")->fetchColumn()
        );
        $this->assertSame(
            0,
            (int) $this->pdo->query("SELECT COUNT(*) FROM auth_permissions_users WHERE permission = 'users.list'")->fetchColumn()
        );
    }

    #[Test]
    public function deletingAnUnknownPermissionIsSafe(): void
    {
        $this->permissions->delete('nope');

        $this->assertNull($this->permissions->info('nope'));
    }
}
