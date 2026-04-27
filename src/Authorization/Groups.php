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
     */
    public function save(AuthGroup $group): void
    {
        $now = (new \DateTimeImmutable())->format('Y-m-d H:i:s');

        if ($group->created_at === null) {
            $group->created_at = $now;
        }
        $group->updated_at = $now;

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
}
