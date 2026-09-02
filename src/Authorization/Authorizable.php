<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Authorization;

use Enlivenapp\FlightShield\Models\AuthGroupPermission;
use Enlivenapp\FlightShield\Models\GroupUser;
use Enlivenapp\FlightShield\Models\PermissionUser;

/**
 * Authorization trait for the User entity.
 *
 * Groups and permissions are loaded directly from the database via AR.
 * $this inside this trait IS the User AR entity — $this->id is the user's ID.
 */
trait Authorizable
{
    protected ?array $groupsCache = null;
    protected ?array $permissionsCache = null;
    protected ?array $deniedCache = null;

    // -----------------------------------------------------------------
    // Groups
    // -----------------------------------------------------------------

    public function getGroups(): array
    {
        if ($this->groupsCache !== null) {
            return $this->groupsCache;
        }

        $records = (new GroupUser(\Flight::db()))
            ->eq('user_id', $this->id)
            ->findAll();

        $this->groupsCache = array_map(
            fn(GroupUser $r) => $r->group_alias,
            $records
        );

        return $this->groupsCache;
    }

    public function addGroup(string $group): static
    {
        // Check if already in group
        if ($this->inGroup($group)) {
            return $this;
        }

        $record = new GroupUser(\Flight::db());
        $record->user_id = $this->id;
        $record->group_alias = $group;
        $record->created_at = (new \DateTimeImmutable())->format('Y-m-d H:i:s');
        $record->insert();

        $this->groupsCache = null;
        return $this;
    }

    public function removeGroup(string $group): static
    {
        $record = (new GroupUser(\Flight::db()))
            ->eq('user_id', $this->id)
            ->eq('group_alias', $group)
            ->find();

        if ($record->isHydrated()) {
            $record->delete();
        }

        $this->groupsCache = null;
        return $this;
    }

    public function syncGroups(array $groups): static
    {
        $existing = (new GroupUser(\Flight::db()))
            ->eq('user_id', $this->id)
            ->findAll();

        foreach ($existing as $record) {
            $record->delete();
        }

        foreach ($groups as $group) {
            $record = new GroupUser(\Flight::db());
            $record->user_id = $this->id;
            $record->group_alias = $group;
            $record->created_at = (new \DateTimeImmutable())->format('Y-m-d H:i:s');
            $record->insert();
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
        $this->hydratePermissions();
        return $this->permissionsCache;
    }

    public function getDeniedPermissions(): array
    {
        $this->hydratePermissions();
        return $this->deniedCache;
    }

    protected function hydratePermissions(): void
    {
        if ($this->permissionsCache !== null) {
            return;
        }

        $records = (new PermissionUser(\Flight::db()))
            ->eq('user_id', $this->id)
            ->findAll();

        $this->permissionsCache = [];
        $this->deniedCache = [];

        foreach ($records as $r) {
            if ($r->deny) {
                $this->deniedCache[] = $r->permission;
            } else {
                $this->permissionsCache[] = $r->permission;
            }
        }
    }

    public function addPermission(string $permission, bool $deny = false): static
    {
        $existing = (new PermissionUser(\Flight::db()))
            ->eq('user_id', $this->id)
            ->eq('permission', $permission)
            ->find();

        if ($existing->isHydrated()) {
            $existing->deny = $deny;
            // Explicit dirty(): typed property assignment bypasses __set(),
            // and loose comparison misses bool flips (deny true -> false == 0/'0').
            $existing->dirty(['deny' => $deny]);
            $existing->save();
        } else {
            $record = new PermissionUser(\Flight::db());
            $record->user_id = $this->id;
            $record->permission = $permission;
            $record->deny = $deny;
            $record->created_at = (new \DateTimeImmutable())->format('Y-m-d H:i:s');
            $record->insert();
        }

        $this->permissionsCache = null;
        $this->deniedCache = null;
        return $this;
    }

    public function denyPermission(string $permission): static
    {
        return $this->addPermission($permission, true);
    }

    public function removePermission(string $permission): static
    {
        $record = (new PermissionUser(\Flight::db()))
            ->eq('user_id', $this->id)
            ->eq('permission', $permission)
            ->find();

        if ($record->isHydrated()) {
            $record->delete();
        }

        $this->permissionsCache = null;
        $this->deniedCache = null;
        return $this;
    }

    /**
     * Sync user permissions.
     *
     * @param array $grants  Permission aliases to grant
     * @param array $denies  Permission aliases to deny
     */
    public function syncPermissions(array $grants, array $denies = []): static
    {
        $existing = (new PermissionUser(\Flight::db()))
            ->eq('user_id', $this->id)
            ->findAll();

        foreach ($existing as $record) {
            $record->delete();
        }

        $now = (new \DateTimeImmutable())->format('Y-m-d H:i:s');

        foreach ($grants as $permission) {
            $record = new PermissionUser(\Flight::db());
            $record->user_id = $this->id;
            $record->permission = $permission;
            $record->deny = false;
            $record->created_at = $now;
            $record->insert();
        }

        foreach ($denies as $permission) {
            $record = new PermissionUser(\Flight::db());
            $record->user_id = $this->id;
            $record->permission = $permission;
            $record->deny = true;
            $record->created_at = $now;
            $record->insert();
        }

        $this->permissionsCache = null;
        $this->deniedCache = null;
        return $this;
    }

    /**
     * Check if user has permission.
     *
     * 1. Check direct user denies — if denied, return false immediately
     * 2. Check direct user grants — if granted, return true
     * 3. Check group permissions — if matched, return true
     * 4. Return false
     *
     * Matching uses the hierarchical wildcard semantics of
     * PermissionMatcher: "users.*" grants "users.create" and every
     * descendant, but never "users" itself. A standalone "*" grant no
     * longer matches everything — superadmins bypass via group
     * membership instead.
     */
    public function can(string $permission): bool
    {
        // Superadmin bypasses all permission checks
        if ($this->inGroup('superadmin')) {
            return true;
        }

        // 1. Direct deny overrides everything
        $denied = $this->getDeniedPermissions();
        if (PermissionMatcher::matches($permission, $denied)) {
            return false;
        }

        // 2. Direct grant
        $granted = $this->getPermissions();
        if (PermissionMatcher::matches($permission, $granted)) {
            return true;
        }

        // 3. Group permissions
        $userGroups = $this->getGroups();
        foreach ($userGroups as $group) {
            $groupPerms = $this->getGroupPermissionsFromDb($group);
            if (PermissionMatcher::matches($permission, $groupPerms)) {
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

        $records = (new AuthGroupPermission(\Flight::db()))
            ->eq('group_alias', $group)
            ->findAll();

        $cache[$group] = array_map(
            fn(AuthGroupPermission $r) => $r->permission_alias,
            $records
        );

        return $cache[$group];
    }
}
