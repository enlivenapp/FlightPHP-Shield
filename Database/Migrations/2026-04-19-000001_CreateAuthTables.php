<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Database\Migrations;

use Enlivenapp\Migrations\Services\Migration;

class CreateAuthTables extends Migration
{
    public function up(): void
    {
        // users
        $this->table('users')
            ->addColumn('id', 'primary', [])
            ->addColumn('username', 'string', ['length' => 30, 'nullable' => true, 'default' => null])
            ->addColumn('status', 'string', ['length' => 255, 'nullable' => true, 'default' => null])
            ->addColumn('status_message', 'string', ['length' => 255, 'nullable' => true, 'default' => null])
            ->addColumn('active', 'boolean', ['default' => false])
            ->addColumn('last_active', 'datetime', ['nullable' => true, 'default' => null])
            ->addColumn('created_at', 'datetime', ['nullable' => true, 'default' => null])
            ->addColumn('updated_at', 'datetime', ['nullable' => true, 'default' => null])
            ->addColumn('deleted_at', 'datetime', ['nullable' => true, 'default' => null])
            ->addIndex(['username'], ['unique' => true])
            ->create();

        // auth_identities
        $this->table('auth_identities')
            ->addColumn('id', 'primary', [])
            ->addColumn('user_id', 'integer', ['unsigned' => true])
            ->addColumn('type', 'string', ['length' => 255])
            ->addColumn('name', 'string', ['length' => 255, 'nullable' => true, 'default' => null])
            ->addColumn('secret', 'string', ['length' => 255])
            ->addColumn('secret2', 'string', ['length' => 255, 'nullable' => true, 'default' => null])
            ->addColumn('expires', 'datetime', ['nullable' => true, 'default' => null])
            ->addColumn('extra', 'text', ['nullable' => true, 'default' => null])
            ->addColumn('force_reset', 'boolean', ['default' => false])
            ->addColumn('last_used_at', 'datetime', ['nullable' => true, 'default' => null])
            ->addColumn('created_at', 'datetime', ['nullable' => true, 'default' => null])
            ->addColumn('updated_at', 'datetime', ['nullable' => true, 'default' => null])
            ->addIndex(['type', 'secret'], ['unique' => true])
            ->addIndex(['user_id'])
            ->addForeignKey(['user_id'], 'users', ['id'], ['delete' => 'CASCADE'])
            ->create();

        // auth_logins
        $this->table('auth_logins')
            ->addColumn('id', 'primary', [])
            ->addColumn('ip_address', 'string', ['length' => 255])
            ->addColumn('user_agent', 'string', ['length' => 255, 'nullable' => true, 'default' => null])
            ->addColumn('id_type', 'string', ['length' => 255])
            ->addColumn('identifier', 'string', ['length' => 255])
            ->addColumn('user_id', 'integer', ['unsigned' => true, 'nullable' => true, 'default' => null])
            ->addColumn('date', 'datetime', [])
            ->addColumn('success', 'boolean', [])
            ->addIndex(['id_type', 'identifier'])
            ->addIndex(['user_id'])
            ->create();

        // auth_token_logins
        $this->table('auth_token_logins')
            ->addColumn('id', 'primary', [])
            ->addColumn('ip_address', 'string', ['length' => 255])
            ->addColumn('user_agent', 'string', ['length' => 255, 'nullable' => true, 'default' => null])
            ->addColumn('id_type', 'string', ['length' => 255])
            ->addColumn('identifier', 'string', ['length' => 255])
            ->addColumn('user_id', 'integer', ['unsigned' => true, 'nullable' => true, 'default' => null])
            ->addColumn('date', 'datetime', [])
            ->addColumn('success', 'boolean', [])
            ->addIndex(['id_type', 'identifier'])
            ->addIndex(['user_id'])
            ->create();

        // auth_remember_tokens
        $this->table('auth_remember_tokens')
            ->addColumn('id', 'primary', [])
            ->addColumn('selector', 'string', ['length' => 255])
            ->addColumn('hashed_validator', 'string', ['length' => 255])
            ->addColumn('user_id', 'integer', ['unsigned' => true])
            ->addColumn('expires', 'datetime', [])
            ->addColumn('created_at', 'datetime', ['nullable' => true, 'default' => null])
            ->addColumn('updated_at', 'datetime', ['nullable' => true, 'default' => null])
            ->addIndex(['selector'], ['unique' => true])
            ->addIndex(['user_id'])
            ->addForeignKey(['user_id'], 'users', ['id'], ['delete' => 'CASCADE'])
            ->create();

        // auth_groups_users
        $this->table('auth_groups_users')
            ->addColumn('id', 'primary', [])
            ->addColumn('user_id', 'integer', ['unsigned' => true])
            ->addColumn('group_alias', 'string', ['length' => 255])
            ->addColumn('created_at', 'datetime', ['nullable' => true, 'default' => null])
            ->addIndex(['user_id'])
            ->addForeignKey(['user_id'], 'users', ['id'], ['delete' => 'CASCADE'])
            ->create();

        // auth_permissions_users
        $this->table('auth_permissions_users')
            ->addColumn('id', 'primary', [])
            ->addColumn('user_id', 'integer', ['unsigned' => true])
            ->addColumn('permission', 'string', ['length' => 255])
            ->addColumn('deny', 'boolean', ['default' => false])
            ->addColumn('created_at', 'datetime', ['nullable' => true, 'default' => null])
            ->addIndex(['user_id'])
            ->addForeignKey(['user_id'], 'users', ['id'], ['delete' => 'CASCADE'])
            ->create();
    }

    public function down(): void
    {
        $this->table('auth_permissions_users')->drop();
        $this->table('auth_groups_users')->drop();
        $this->table('auth_remember_tokens')->drop();
        $this->table('auth_token_logins')->drop();
        $this->table('auth_logins')->drop();
        $this->table('auth_identities')->drop();
        $this->table('users')->drop();
    }
}
