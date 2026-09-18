<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Database\Migrations;

use Enlivenapp\Migrations\Services\Migration;

class AddUpdatedAtToAuthGroupPermissions extends Migration
{
    public function up(): void
    {
        if (!$this->table('auth_group_permissions')->hasColumn('updated_at')) {
            $this->table('auth_group_permissions')
                ->addColumn('updated_at', 'datetime', ['nullable' => true, 'default' => null])
                ->addColumns();
        }
    }

    public function down(): void
    {
        $this->table('auth_group_permissions')->dropColumns(['updated_at']);
    }
}