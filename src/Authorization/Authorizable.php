<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Authorization;

use Cycle\ORM\EntityManager;
use Cycle\ORM\ORMInterface;
use Enlivenapp\FlightShield\Entities\GroupUser;
use Enlivenapp\FlightShield\Entities\PermissionUser;

/**
 * Authorization trait for the User entity.
 *
 * Groups and permissions are loaded from the user's relations.
 * Write operations (add/remove/sync) require an ORM instance.
 */
trait Authorizable
{
    protected ?array $groupsCache = null;
    protected ?array $permissionsCache = null;

    // -----------------------------------------------------------------
    // Groups
    // -----------------------------------------------------------------

    public function getGroups(): array
    {
        if ($this->groupsCache !== null) {
            return $this->groupsCache;
        }

        $this->groupsCache = array_map(
            fn(GroupUser $r) => $r->group,
            $this->group_records ?? []
        );

        return $this->groupsCache;
    }

    public function addGroup(string $group, ORMInterface $orm): static
    {
        // Check if already in group
        if ($this->inGroup($group)) {
            return $this;
        }

        $record = new GroupUser();
        $record->user_id = $this->id;
        $record->group = $group;
        $record->created_at = new \DateTimeImmutable();

        $em = new EntityManager($orm);
        $em->persist($record)->run();

        $this->groupsCache = null;
        return $this;
    }

    public function removeGroup(string $group, ORMInterface $orm): static
    {
        $repo = $orm->getRepository(GroupUser::class);
        $record = $repo->select()
            ->where('user_id', $this->id)
            ->where('group', $group)
            ->fetchOne();

        if ($record) {
            $em = new EntityManager($orm);
            $em->delete($record)->run();
        }

        $this->groupsCache = null;
        return $this;
    }

    public function syncGroups(array $groups, ORMInterface $orm): static
    {
        $repo = $orm->getRepository(GroupUser::class);
        $existing = $repo->select()->where('user_id', $this->id)->fetchAll();

        $em = new EntityManager($orm);
        foreach ($existing as $record) {
            $em->delete($record);
        }
        $em->run();

        foreach ($groups as $group) {
            $record = new GroupUser();
            $record->user_id = $this->id;
            $record->group = $group;
            $record->created_at = new \DateTimeImmutable();

            $em = new EntityManager($orm);
            $em->persist($record)->run();
        }

        $this->groupsCache = null;
        return $this;
    }

    public function inGroup(string ...$groups): bool
    {
        $userGroups = $this->getGroups();

        foreach ($groups as $group) {
            if (in_array($group, $userGroups, true)) {
                return true;
            }
        }

        return false;
    }

    // -----------------------------------------------------------------
    // Permissions
    // -----------------------------------------------------------------

    public function getPermissions(): array
    {
        if ($this->permissionsCache !== null) {
            return $this->permissionsCache;
        }

        $this->permissionsCache = array_map(
            fn(PermissionUser $r) => $r->permission,
            $this->permission_records ?? []
        );

        return $this->permissionsCache;
    }

    public function addPermission(string $permission, ORMInterface $orm): static
    {
        $repo = $orm->getRepository(PermissionUser::class);
        $existing = $repo->select()
            ->where('user_id', $this->id)
            ->where('permission', $permission)
            ->fetchOne();

        if ($existing === null) {
            $record = new PermissionUser();
            $record->user_id = $this->id;
            $record->permission = $permission;
            $record->created_at = new \DateTimeImmutable();

            $em = new EntityManager($orm);
            $em->persist($record)->run();
        }

        $this->permissionsCache = null;
        return $this;
    }

    public function removePermission(string $permission, ORMInterface $orm): static
    {
        $repo = $orm->getRepository(PermissionUser::class);
        $record = $repo->select()
            ->where('user_id', $this->id)
            ->where('permission', $permission)
            ->fetchOne();

        if ($record) {
            $em = new EntityManager($orm);
            $em->delete($record)->run();
        }

        $this->permissionsCache = null;
        return $this;
    }

    public function syncPermissions(array $permissions, ORMInterface $orm): static
    {
        $repo = $orm->getRepository(PermissionUser::class);
        $existing = $repo->select()->where('user_id', $this->id)->fetchAll();

        $em = new EntityManager($orm);
        foreach ($existing as $record) {
            $em->delete($record);
        }
        $em->run();

        foreach ($permissions as $permission) {
            $record = new PermissionUser();
            $record->user_id = $this->id;
            $record->permission = $permission;
            $record->created_at = new \DateTimeImmutable();

            $em = new EntityManager($orm);
            $em->persist($record)->run();
        }

        $this->permissionsCache = null;
        return $this;
    }

    /**
     * Check if user has permission — checks direct permissions first,
     * then group permissions from the database.
     */
    public function can(string $permission): bool
    {
        // Check direct user permissions
        $userPerms = $this->getPermissions();

        if ($this->matchesPermission($permission, $userPerms)) {
            return true;
        }

        // Check group-level permissions
        $userGroups = $this->getGroups();

        foreach ($userGroups as $group) {
            $groupPerms = $this->getGroupPermissionsFromDb($group);

            if ($this->matchesPermission($permission, $groupPerms)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Load a group's permissions from the auth_group_permissions table.
     * Results are cached per group for the lifetime of the request.
     */
    protected function getGroupPermissionsFromDb(string $group): array
    {
        static $cache = [];

        if (isset($cache[$group])) {
            return $cache[$group];
        }

        $orm = \Flight::app()->orm();
        $repo = $orm->getRepository(\Enlivenapp\FlightShield\Entities\AuthGroupPermission::class);
        $records = $repo->select()->where('group_alias', $group)->fetchAll();

        $cache[$group] = array_map(
            fn(\Enlivenapp\FlightShield\Entities\AuthGroupPermission $r) => $r->permission_alias,
            $records
        );

        return $cache[$group];
    }

    /**
     * Check if a permission matches a list, supporting wildcards (e.g. "users.*").
     */
    protected function matchesPermission(string $permission, array $permissions): bool
    {
        if (in_array($permission, $permissions, true)) {
            return true;
        }

        // Wildcard: '*' matches everything
        if (in_array('*', $permissions, true)) {
            return true;
        }

        // Partial wildcards: "users.*" matches "users.create"
        foreach ($permissions as $perm) {
            if (str_contains($perm, '*')) {
                $pattern = str_replace('*', '.*', preg_quote($perm, '/'));
                if (preg_match('/^' . $pattern . '$/', $permission)) {
                    return true;
                }
            }
        }

        return false;
    }
}
