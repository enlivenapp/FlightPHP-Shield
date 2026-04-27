<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Database\Migrations;

use Enlivenapp\Migrations\Services\Migration;

class CreateGroupPermissionTables extends Migration
{
    public function up(): void
    {
        // auth_groups
        $this->table('auth_groups')
            ->addColumn('id', 'primary', [])
            ->addColumn('alias', 'string', ['length' => 255])
            ->addColumn('title', 'string', ['length' => 255])
            ->addColumn('description', 'string', ['length' => 255, 'nullable' => true, 'default' => null])
            ->addColumn('created_at', 'datetime', ['nullable' => true, 'default' => null])
            ->addColumn('updated_at', 'datetime', ['nullable' => true, 'default' => null])
            ->addIndex(['alias'], ['unique' => true])
            ->create();

        // auth_permissions
        $this->table('auth_permissions')
            ->addColumn('id', 'primary', [])
            ->addColumn('alias', 'string', ['length' => 255])
            ->addColumn('description', 'string', ['length' => 255, 'nullable' => true, 'default' => null])
            ->addColumn('created_at', 'datetime', ['nullable' => true, 'default' => null])
            ->addColumn('updated_at', 'datetime', ['nullable' => true, 'default' => null])
            ->addIndex(['alias'], ['unique' => true])
            ->create();

        // auth_group_permissions
        $this->table('auth_group_permissions')
            ->addColumn('id', 'primary', [])
            ->addColumn('group_alias', 'string', ['length' => 255])
            ->addColumn('permission_alias', 'string', ['length' => 255])
            ->addColumn('created_at', 'datetime', ['nullable' => true, 'default' => null])
            ->addIndex(['group_alias', 'permission_alias'], ['unique' => true])
            ->create();
    }

    public function down(): void
    {
        $this->table('auth_group_permissions')->drop();
        $this->table('auth_permissions')->drop();
        $this->table('auth_groups')->drop();
    }
}
