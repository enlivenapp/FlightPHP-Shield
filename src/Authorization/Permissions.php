<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Authorization;

use Enlivenapp\FlightShield\Models\AuthGroupPermission;
use Enlivenapp\FlightShield\Models\AuthPermission;
use Enlivenapp\FlightShield\Models\PermissionUser;

/**
 * Utility class for working with permissions — backed by the auth_permissions table.
 */
class Permissions
{
    protected $pdo;

    public function __construct($pdo)
    {
        $this->pdo = $pdo;
    }

    /**
     * Get all permissions.
     *
     * @return AuthPermission[]
     */
    public function all(): array
    {
        return (new AuthPermission($this->pdo))
            ->order('alias ASC')
            ->findAll();
    }

    /**
     * Get a single permission by alias.
     */
    public function info(string $alias): ?AuthPermission
    {
        $record = (new AuthPermission($this->pdo))
            ->eq('alias', strtolower($alias))
            ->find();

        return $record->isHydrated() ? $record : null;
    }

    /**
     * Get a single permission by ID.
     */
    public function findById(int $id): ?AuthPermission
    {
        $record = (new AuthPermission($this->pdo))
            ->eq('id', $id)
            ->find();

        return $record->isHydrated() ? $record : null;
    }

    /**
     * Create a permission.
     */
    public function create(string $alias, string $description = ''): AuthPermission
    {
        $permission = new AuthPermission($this->pdo);
        $permission->alias = strtolower(trim($alias));
        $permission->description = trim($description);
        $permission->created_at = (new \DateTimeImmutable())->format('Y-m-d H:i:s');
        $permission->insert();

        return $permission;
    }

    /**
     * Save (create or update) a permission.
     *
     * All editable columns are pushed through dirty() explicitly — writes
     * to the model's declared typed properties bypass ActiveRecord's dirty
     * tracker, and loose property/data comparison misses value flips like
     * description -> ''.
     */
    public function save(AuthPermission $permission): void
    {
        $now = (new \DateTimeImmutable())->format('Y-m-d H:i:s');

        if ($permission->created_at === null) {
            $permission->created_at = $now;
        }
        $permission->updated_at = $now;

        $permission->dirty([
            'alias'       => $permission->alias,
            'description' => $permission->description,
            'created_at'  => $permission->created_at,
            'updated_at'  => $permission->updated_at,
        ]);

        if (!isset($permission->id)) {
            $permission->insert();
        } else {
            $permission->save();
        }
    }

    /**
     * Delete a permission and all of its assignments.
     *
     * Removes group mappings and direct user grants/denies first,
     * then deletes the permission itself.
     */
    public function delete(string $alias): void
    {
        $permission = $this->info($alias);
        if ($permission === null) {
            return;
        }

        // Remove group-permission mappings
        $mappings = (new AuthGroupPermission($this->pdo))
            ->eq('permission_alias', $permission->alias)
            ->findAll();

        foreach ($mappings as $mapping) {
            $mapping->delete();
        }

        // Remove direct user grants/denies
        $userPerms = (new PermissionUser($this->pdo))
            ->eq('permission', $permission->alias)
            ->findAll();

        foreach ($userPerms as $userPerm) {
            $userPerm->delete();
        }

        $permission->delete();
    }
}
