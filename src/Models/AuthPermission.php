<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Models;

class AuthPermission extends \flight\ActiveRecord
{
    public function __construct($pdo = null, array $config = [])
    {
        parent::__construct($pdo, 'auth_permissions', $config);
    }

    public int $id;
    public string $alias;
    public ?string $description = null;
    public ?string $created_at = null;
    public ?string $updated_at = null;
}
