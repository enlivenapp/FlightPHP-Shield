<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Models;

use Enlivenapp\FlightSettings\Services\Settings;

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
    protected ?Settings $settings = null;

    public function __construct(array $data = [], ?Settings $settings = null)
    {
        $this->alias       = $data['alias'] ?? '';
        $this->title       = $data['title'] ?? '';
        $this->description = $data['description'] ?? '';
        $this->settings    = $settings;
    }

    public function permissions(): array
    {
        $this->populatePermissions();
        return $this->permissions;
    }

    public function setPermissions(array $permissions): void
    {
        $this->permissions = $permissions;

        if ($this->settings !== null) {
            $matrix = $this->settings->get('AuthGroups.matrix') ?? [];
            $matrix[$this->alias] = $permissions;
            $this->settings->set('AuthGroups.matrix', $matrix);
        }
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

        if ($this->settings !== null) {
            $matrix = $this->settings->get('AuthGroups.matrix') ?? [];
            $this->permissions = $matrix[$this->alias] ?? [];
        } else {
            $this->permissions = [];
        }
    }
}
