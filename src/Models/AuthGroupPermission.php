<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Models;

class AuthGroupPermission extends \flight\ActiveRecord
{
    public function __construct($pdo = null, array $config = [])
    {
        parent::__construct($pdo, 'auth_group_permissions', $config);
    }

    public int $id;
    public string $group_alias;
    public string $permission_alias;
    public ?string $created_at = null;
}
