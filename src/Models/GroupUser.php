<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Models;

class GroupUser extends \flight\ActiveRecord
{
    public function __construct($pdo = null, array $config = [])
    {
        parent::__construct($pdo, 'auth_groups_users', $config);
    }

    public int $id;
    public int $user_id;
    public string $group_alias;
    public ?string $created_at = null;

    /**
     * User count per group (excluding soft-deleted users).
     *
     * @return array<string, int> group_alias => count
     */
    public function countByGroup(): array
    {
        $results = (new self($this->getDatabaseConnection()))
            ->select('group_alias', 'COUNT(*) as cnt')
            ->join('users', 'users.id = auth_groups_users.user_id')
            ->where('users.deleted_at IS NULL')
            ->group('group_alias')
            ->order('cnt DESC')
            ->findAll();

        $data = [];
        foreach ($results as $row) {
            $data[$row->group_alias] = (int) $row->cnt;
        }
        return $data;
    }
}
