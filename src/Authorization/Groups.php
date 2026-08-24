<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Authorization;

use Enlivenapp\FlightShield\Models\AuthGroup;
use Enlivenapp\FlightShield\Models\AuthGroupPermission;
use Enlivenapp\FlightShield\Models\GroupUser;

/**
 * Utility class for working with groups — backed by the auth_groups table.
 */
class Groups
{
    protected $pdo;

    public function __construct($pdo)
    {
        $this->pdo = $pdo;
    }

    /**
     * Get a single group by alias.
     */
    public function info(string $group): ?AuthGroup
    {
        $record = (new AuthGroup($this->pdo))
            ->eq('alias', strtolower($group))
            ->find();

        return $record->isHydrated() ? $record : null;
    }

    /**
     * Get a single group by ID.
     */
    public function findById(int $id): ?AuthGroup
    {
        $record = (new AuthGroup($this->pdo))
            ->eq('id', $id)
            ->find();

        return $record->isHydrated() ? $record : null;
    }

    /**
     * Create a group.
     */
    public function create(string $alias, string $title, string $description = ''): AuthGroup
    {
        $group = new AuthGroup($this->pdo);
        $group->alias = strtolower(trim($alias));
        $group->title = trim($title);
        $group->description = trim($description);
        $this->save($group);

        return $group;
    }

    /**
     * Get all groups.
     *
     * @return AuthGroup[]
     */
    public function all(): array
    {
        return (new AuthGroup($this->pdo))
            ->order('alias ASC')
            ->findAll();
    }

    /**
     * Save (create or update) a group.
     *
     * All editable columns are pushed through dirty() explicitly — writes
     * to the model's declared typed properties bypass ActiveRecord's dirty
     * tracker, and loose property/data comparison misses value flips like
     * description -> ''.
     */
    public function save(AuthGroup $group): void
    {
        $now = (new \DateTimeImmutable())->format('Y-m-d H:i:s');

        if ($group->created_at === null) {
            $group->created_at = $now;
        }
        $group->updated_at = $now;

        $group->dirty([
            'alias'       => $group->alias,
            'title'       => $group->title,
            'description' => $group->description,
            'created_at'  => $group->created_at,
            'updated_at'  => $group->updated_at,
        ]);

        if (!isset($group->id)) {
            $group->insert();
        } else {
            $group->save();
        }
    }

    /**
     * Delete a group, its permission mappings, and all user memberships.
     *
     * Any user who would be left with no groups after removal is
     * automatically added to the default 'user' group.
     */
    public function delete(string $alias): void
    {
        $group = $this->info($alias);
        if ($group === null) {
            return;
        }

        // --- 1. Handle user memberships ---

        // Collect all membership records for this group
        $memberships = (new GroupUser($this->pdo))
            ->eq('group_alias', $alias)
            ->findAll();

        // Determine which affected users will be left with no groups
        $affectedUserIds = array_unique(
            array_map(fn(GroupUser $r) => $r->user_id, $memberships)
        );

        foreach ($affectedUserIds as $userId) {
            // Count remaining groups for this user, excluding the group being deleted
            $remaining = (new GroupUser($this->pdo))
                ->eq('user_id', $userId)
                ->ne('group_alias', $alias)
                ->findAll();

            if (count($remaining) === 0 && $alias !== 'user') {
                // Re-assign to the default group before deleting the membership
                $fallback = new GroupUser($this->pdo);
                $fallback->user_id = $userId;
                $fallback->group_alias = 'user';
                $fallback->created_at = (new \DateTimeImmutable())->format('Y-m-d H:i:s');
                $fallback->insert();
            }
        }

        // Delete all membership records for this group
        foreach ($memberships as $membership) {
            $membership->delete();
        }

        // --- 2. Remove group-permission mappings ---
        $permMappings = (new AuthGroupPermission($this->pdo))
            ->eq('group_alias', $alias)
            ->findAll();

        foreach ($permMappings as $mapping) {
            $mapping->delete();
        }

        // --- 3. Delete the group itself ---
        $group->delete();
    }

    /**
     * Get permissions for a group.
     *
     * @return string[]
     */
    public function permissions(string $alias): array
    {
        $records = (new AuthGroupPermission($this->pdo))
            ->eq('group_alias', $alias)
            ->findAll();

        return array_map(
            fn(AuthGroupPermission $r) => $r->permission_alias,
            $records
        );
    }

    /**
     * Add a permission to a group.
     */
    public function addPermission(string $groupAlias, string $permissionAlias): void
    {
        $existing = (new AuthGroupPermission($this->pdo))
            ->eq('group_alias', $groupAlias)
            ->eq('permission_alias', $permissionAlias)
            ->find();

        if ($existing->isHydrated()) {
            return;
        }

        $record = new AuthGroupPermission($this->pdo);
        $record->group_alias = $groupAlias;
        $record->permission_alias = $permissionAlias;
        $record->created_at = (new \DateTimeImmutable())->format('Y-m-d H:i:s');
        $record->insert();
    }

    /**
     * Remove a permission from a group.
     */
    public function removePermission(string $groupAlias, string $permissionAlias): void
    {
        $record = (new AuthGroupPermission($this->pdo))
            ->eq('group_alias', $groupAlias)
            ->eq('permission_alias', $permissionAlias)
            ->find();

        if (!$record->isHydrated()) {
            return;
        }

        $record->delete();
    }

    /**
     * Replace a group's permission set with the given aliases.
     *
     * Existing mappings not in the list are removed; missing ones are added.
     * Unknown aliases (not present in auth_permissions) are skipped so a
     * stale form submission cannot create orphan mappings.
     */
    public function syncPermissions(string $groupAlias, array $permissionAliases): void
    {
        $current = $this->permissions($groupAlias);
        $target = [];

        foreach ($permissionAliases as $alias) {
            $alias = strtolower(trim($alias));
            if ($alias !== '' && !in_array($alias, $target, true)) {
                $target[] = $alias;
            }
        }

        // Remove mappings no longer wanted
        foreach (array_diff($current, $target) as $remove) {
            $this->removePermission($groupAlias, $remove);
        }

        // Add mappings that don't exist yet — skip unknown permissions
        $permissionsUtil = new Permissions($this->pdo);
        foreach (array_diff($target, $current) as $add) {
            if ($permissionsUtil->info($add) === null) {
                continue;
            }
            $this->addPermission($groupAlias, $add);
        }
    }
}
