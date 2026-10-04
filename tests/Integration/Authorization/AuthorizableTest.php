<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Integration\Authorization;

use Enlivenapp\FlightShield\Models\User;
use Enlivenapp\FlightShield\Tests\TestHelper;
use PDO;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Groups, direct permissions, denied permissions and the group fallback.
 */
class AuthorizableTest extends TestCase
{
    protected PDO $pdo;
    protected User $user;

    protected function setUp(): void
    {
        $this->pdo = TestHelper::createDatabase();
        TestHelper::resetFlight();
        TestHelper::registerFlightDb($this->pdo);

        $this->user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'bob', true);
    }

    protected function tearDown(): void
    {
        TestHelper::resetFlight();
    }

    private function grantToGroup(string $group, string $permission): void
    {
        $stmt = $this->pdo->prepare(
            'INSERT INTO auth_group_permissions (group_alias, permission_alias, created_at) VALUES (?, ?, ?)'
        );
        $stmt->execute([$group, $permission, (new \DateTimeImmutable())->format('Y-m-d H:i:s')]);
    }

    // -----------------------------------------------------------------
    // Groups
    // -----------------------------------------------------------------

    #[Test]
    public function newUserHasNoGroups(): void
    {
        $this->assertSame([], $this->user->getGroups());
    }

    #[Test]
    public function addGroupAddsAndInGroupSeesIt(): void
    {
        $this->user->addGroup('admin');

        $this->assertTrue($this->user->inGroup('admin'));
        $this->assertContains('admin', $this->user->getGroups());
    }

    #[Test]
    public function addGroupIsIdempotent(): void
    {
        $this->user->addGroup('admin');
        $this->user->addGroup('admin');

        $count = (int) $this->pdo
            ->query("SELECT COUNT(*) FROM auth_groups_users WHERE user_id = {$this->user->id}")
            ->fetchColumn();

        $this->assertSame(1, $count);
    }

    #[Test]
    public function inGroupMatchesAnyOfTheGivenNames(): void
    {
        $this->user->addGroup('staff');

        $this->assertTrue($this->user->inGroup('admin', 'staff'));
        $this->assertFalse($this->user->inGroup('admin', 'superadmin'));
    }

    #[Test]
    public function removeGroupRemovesIt(): void
    {
        $this->user->addGroup('admin');
        $this->user->removeGroup('admin');

        $this->assertFalse($this->user->inGroup('admin'));
    }

    #[Test]
    public function removingAGroupTheUserIsNotInIsSafe(): void
    {
        $this->user->removeGroup('admin');

        $this->assertSame([], $this->user->getGroups());
    }

    #[Test]
    public function syncGroupsReplacesExistingMemberships(): void
    {
        $this->user->addGroup('admin');
        $this->user->syncGroups(['staff', 'editor']);

        $groups = $this->user->getGroups();
        sort($groups);

        $this->assertSame(['editor', 'staff'], $groups);
        $this->assertFalse($this->user->inGroup('admin'));
    }

    // -----------------------------------------------------------------
    // Direct permissions
    // -----------------------------------------------------------------

    #[Test]
    public function newUserHasNoPermissions(): void
    {
        $this->assertSame([], $this->user->getPermissions());
        $this->assertSame([], $this->user->getDeniedPermissions());
    }

    #[Test]
    public function directGrantIsHonoured(): void
    {
        $this->user->addPermission('users.list');

        $this->assertTrue($this->user->can('users.list'));
        $this->assertFalse($this->user->can('users.delete'));
    }

    #[Test]
    public function wildcardGrantCoversDescendantsButNotTheNodeItself(): void
    {
        $this->user->addPermission('users.*');

        $this->assertTrue($this->user->can('users.create'));
        $this->assertFalse($this->user->can('users'));
    }

    #[Test]
    public function denyOverridesADirectGrant(): void
    {
        $this->user->addPermission('users.list');
        $this->user->denyPermission('users.list');

        $this->assertFalse($this->user->can('users.list'));
    }

    #[Test]
    public function removePermissionRemovesIt(): void
    {
        $this->user->addPermission('users.list');
        $this->user->removePermission('users.list');

        $this->assertFalse($this->user->can('users.list'));
    }

    #[Test]
    public function addPermissionFlipsAnExistingDenyToGrant(): void
    {
        $this->user->denyPermission('users.list');
        $this->user->addPermission('users.list');

        $this->assertTrue($this->user->can('users.list'));
        $this->assertSame([], $this->user->getDeniedPermissions());
    }

    #[Test]
    public function syncPermissionsReplacesGrantsAndDenies(): void
    {
        $this->user->addPermission('users.list');
        $this->user->syncPermissions(['posts.edit'], ['posts.delete']);

        $this->assertTrue($this->user->can('posts.edit'));
        $this->assertFalse($this->user->can('posts.delete'));
        $this->assertFalse($this->user->can('users.list'));
        $this->assertSame(['posts.delete'], $this->user->getDeniedPermissions());
    }

    // -----------------------------------------------------------------
    // Group permissions and precedence
    // -----------------------------------------------------------------

    #[Test]
    public function groupPermissionGrantsAccess(): void
    {
        $this->grantToGroup('admin', 'users.manage');
        $this->user->addGroup('admin');

        $this->assertTrue($this->user->can('users.manage'));
        $this->assertFalse($this->user->can('users.other'));
    }

    #[Test]
    public function directDenyBeatsAGroupGrant(): void
    {
        $this->grantToGroup('admin', 'users.manage');
        $this->user->addGroup('admin');
        $this->user->denyPermission('users.manage');

        $this->assertFalse($this->user->can('users.manage'));
    }

    #[Test]
    public function superadminBypassesEveryCheck(): void
    {
        $this->user->addGroup('superadmin');

        $this->assertTrue($this->user->can('anything.at.all'));
    }
}
