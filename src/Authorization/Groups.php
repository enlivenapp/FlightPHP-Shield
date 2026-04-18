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
use Enlivenapp\FlightShield\Entities\AuthGroup;
use Enlivenapp\FlightShield\Entities\AuthGroupPermission;
use Enlivenapp\FlightShield\Entities\GroupUser;

/**
 * Utility class for working with groups — backed by the auth_groups table.
 */
class Groups
{
    protected ORMInterface $orm;

    public function __construct(ORMInterface $orm)
    {
        $this->orm = $orm;
    }

    /**
     * Get a single group by alias.
     */
    public function info(string $group): ?AuthGroup
    {
        $repo = $this->orm->getRepository(AuthGroup::class);
        return $repo->select()
            ->where('alias', strtolower($group))
            ->fetchOne();
    }

    /**
     * Get all groups.
     *
     * @return AuthGroup[]
     */
    public function all(): array
    {
        $repo = $this->orm->getRepository(AuthGroup::class);
        return $repo->select()->orderBy('alias')->fetchAll();
    }

    /**
     * Save (create or update) a group.
     */
    public function save(AuthGroup $group): void
    {
        $now = new \DateTimeImmutable();
        if ($group->created_at === null) {
            $group->created_at = $now;
        }
        $group->updated_at = $now;

        $em = new EntityManager($this->orm);
        $em->persist($group)->run();
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
        $guRepo = $this->orm->getRepository(GroupUser::class);

        // Collect all membership records for this group
        $memberships = $guRepo->select()->where('group', $alias)->fetchAll();

        // Determine which affected users will be left with no groups
        $affectedUserIds = array_unique(
            array_map(fn(GroupUser $r) => $r->user_id, $memberships)
        );

        $em = new EntityManager($this->orm);

        foreach ($affectedUserIds as $userId) {
            // Count remaining groups for this user, excluding the group being deleted
            $remainingCount = $guRepo->select()
                ->where('user_id', $userId)
                ->where('group', '!=', $alias)
                ->count();

            if ($remainingCount === 0 && $alias !== 'user') {
                // Re-assign to the default group before deleting the membership
                $fallback = new GroupUser();
                $fallback->user_id = $userId;
                $fallback->group = 'user';
                $fallback->created_at = new \DateTimeImmutable();
                $em->persist($fallback);
            }
        }

        // Delete all membership records for this group
        foreach ($memberships as $membership) {
            $em->delete($membership);
        }

        // --- 2. Remove group-permission mappings ---
        $gpRepo = $this->orm->getRepository(AuthGroupPermission::class);
        $permMappings = $gpRepo->select()->where('group_alias', $alias)->fetchAll();
        foreach ($permMappings as $mapping) {
            $em->delete($mapping);
        }

        // --- 3. Delete the group itself ---
        $em->delete($group)->run();
    }

    /**
     * Get permissions for a group.
     *
     * @return string[]
     */
    public function permissions(string $alias): array
    {
        $repo = $this->orm->getRepository(AuthGroupPermission::class);
        $records = $repo->select()->where('group_alias', $alias)->fetchAll();

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
        $repo = $this->orm->getRepository(AuthGroupPermission::class);
        $existing = $repo->select()
            ->where('group_alias', $groupAlias)
            ->where('permission_alias', $permissionAlias)
            ->fetchOne();

        if ($existing !== null) {
            return;
        }

        $record = new AuthGroupPermission();
        $record->group_alias = $groupAlias;
        $record->permission_alias = $permissionAlias;
        $record->created_at = new \DateTimeImmutable();

        $em = new EntityManager($this->orm);
        $em->persist($record)->run();
    }

    /**
     * Remove a permission from a group.
     */
    public function removePermission(string $groupAlias, string $permissionAlias): void
    {
        $repo = $this->orm->getRepository(AuthGroupPermission::class);
        $record = $repo->select()
            ->where('group_alias', $groupAlias)
            ->where('permission_alias', $permissionAlias)
            ->fetchOne();

        if ($record === null) {
            return;
        }

        $em = new EntityManager($this->orm);
        $em->delete($record)->run();
    }
}
