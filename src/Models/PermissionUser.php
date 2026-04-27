<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Models;

class PermissionUser extends \flight\ActiveRecord
{
    public function __construct($pdo = null, array $config = [])
    {
        parent::__construct($pdo, 'auth_permissions_users', $config);
    }

    public int $id;
    public int $user_id;
    public string $permission;
    public bool $deny = false;
    public ?string $created_at = null;
}
