<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Models;

namespace Enlivenapp\FlightShield\Models;

/**
 * @deprecated Use \Enlivenapp\FlightShield\Models\AuthGroup instead.
 *             This value object is kept for backward compatibility only.
 */
class Group
{
    public string $alias;
    public string $title;
    public string $description;
    protected ?array $permissions = null;

    public function __construct(array $data = [])
    {
        $this->alias       = $data['alias'] ?? '';
        $this->title       = $data['title'] ?? '';
        $this->description = $data['description'] ?? '';
    }

    public function permissions(): array
    {
        $this->populatePermissions();
        return $this->permissions;
    }

    public function setPermissions(array $permissions): void
    {
        $this->permissions = $permissions;
    }

    public function addPermission(string $permission): void
    {
        $this->populatePermissions();
        array_unshift($this->permissions, $permission);
        $this->setPermissions($this->permissions);
    }

    public function removePermission(string $permission): void
    {
        $this->populatePermissions();
        $key = array_search($permission, $this->permissions, true);
        if ($key !== false) {
            unset($this->permissions[$key]);
        }
        $this->setPermissions(array_values($this->permissions));
    }

    public function can(string $permission): bool
    {
        $this->populatePermissions();

        if (in_array($permission, $this->permissions, true)) {
            return true;
        }

        // Wildcard check
        $check = substr($permission, 0, strpos($permission, '.')) . '.*';

        return in_array($check, $this->permissions, true);
    }

    protected function populatePermissions(): void
    {
        if ($this->permissions !== null) {
            return;
        }

        $this->permissions = [];
    }
}
