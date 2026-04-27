<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Models;

use Enlivenapp\FlightShield\Authorization\Authorizable;
use Enlivenapp\FlightShield\Traits\Activatable;
use Enlivenapp\FlightShield\Traits\Bannable;
use Enlivenapp\FlightShield\Traits\HasAccessTokens;
use Enlivenapp\FlightShield\Traits\HasHmacTokens;
use Enlivenapp\FlightShield\Traits\Resettable;
use Enlivenapp\FlightShield\Passwords\Passwords;

class User extends \flight\ActiveRecord
{
    use Authorizable;
    use Activatable;
    use Bannable;
    use HasAccessTokens;
    use HasHmacTokens;
    use Resettable;

    public function __construct($pdo = null, array $config = [])
    {
        parent::__construct($pdo, 'users', $config);
    }

    public int $id;
    public ?string $username = null;
    public ?string $status = null;
    public ?string $status_message = null;
    public bool $active = false;
    public ?string $last_active = null;
    public ?string $created_at = null;
    public ?string $updated_at = null;
    public ?string $deleted_at = null;

    // -----------------------------------------------------------------
    // Finders (from UserRepository)
    // -----------------------------------------------------------------

    /**
     * Find a user by ID.
     *
     * When $includeSuperadmins is false and the target user is in the
     * superadmin group, returns null — as if the user doesn't exist.
     */
    public function findById(int|string $id, bool $includeSuperadmins = true): ?self
    {
        $user = new self($this->getDatabaseConnection());
        $user->eq('id', $id)->isNull('deleted_at')->find();

        if (!$user->isHydrated()) {
            return null;
        }

        if (!$includeSuperadmins && $user->inGroup('superadmin')) {
            return null;
        }

        return $user;
    }

    public function findByCredentials(array $credentials): ?self
    {
        if (isset($credentials['email'])) {
            $identity = new UserIdentity($this->getDatabaseConnection());
            $identity->eq('type', UserIdentity::TYPE_EMAIL_PASSWORD)
                     ->eq('secret', $credentials['email'])
                     ->find();

            if (!$identity->isHydrated()) {
                return null;
            }

            return $this->findById($identity->user_id);
        }

        if (isset($credentials['username'])) {
            $user = new self($this->getDatabaseConnection());
            $user->eq('username', $credentials['username'])->isNull('deleted_at')->find();

            return $user->isHydrated() ? $user : null;
        }

        return null;
    }

    public function findActive(): array
    {
        $user = new self($this->getDatabaseConnection());

        return $user->eq('active', 1)->isNull('deleted_at')->findAll();
    }

    /**
     * Get all non-deleted users, paginated.
     *
     * When $includeSuperadmins is false, users in the superadmin group
     * are excluded from results. Pass true only when the caller is a
     * superadmin themselves.
     *
     * @return self[]
     */
    public function findAllPaginated(int $page = 1, int $perPage = 20, bool $includeSuperadmins = false): array
    {
        $offset = ($page - 1) * $perPage;

        $results = (new self($this->getDatabaseConnection()))
            ->isNull('deleted_at')
            ->order('id asc')
            ->limit($perPage)
            ->offset($offset)
            ->findAll();

        if (!$includeSuperadmins) {
            $results = array_values(array_filter($results, fn($u) => !$u->inGroup('superadmin')));
        }

        return $results;
    }

    /**
     * Count all non-deleted users.
     *
     * When $includeSuperadmins is false, users in the superadmin group
     * are excluded from the count.
     */
    public function countAll(bool $includeSuperadmins = false): int
    {
        if ($includeSuperadmins) {
            $result = (new self($this->getDatabaseConnection()))
                ->select('COUNT(*) as cnt')
                ->isNull('deleted_at')
                ->find();

            return (int) $result->cnt;
        }

        // Post-fetch filter — count all then subtract superadmins
        $all = (new self($this->getDatabaseConnection()))
            ->isNull('deleted_at')
            ->findAll();

        $filtered = array_filter($all, fn($u) => !$u->inGroup('superadmin'));

        return count($filtered);
    }

    /**
     * Count active users (active = 1, not deleted).
     */
    public function countActive(): int
    {
        $result = (new self($this->getDatabaseConnection()))
            ->select('COUNT(*) as cnt')
            ->eq('active', 1)
            ->isNull('deleted_at')
            ->find();

        return (int) $result->cnt;
    }

    /**
     * Count inactive users (active = 0, not deleted, not banned).
     */
    public function countInactive(): int
    {
        $result = (new self($this->getDatabaseConnection()))
            ->select('COUNT(*) as cnt')
            ->eq('active', 0)
            ->isNull('deleted_at')
            ->startWrap()
            ->isNull('status')
            ->ne('status', 'banned')
            ->endWrap('OR')
            ->find();

        return (int) $result->cnt;
    }

    /**
     * Count banned users (not deleted).
     */
    public function countBanned(): int
    {
        $result = (new self($this->getDatabaseConnection()))
            ->select('COUNT(*) as cnt')
            ->eq('status', 'banned')
            ->isNull('deleted_at')
            ->find();

        return (int) $result->cnt;
    }

    /**
     * Count non-deleted users created on or after a given date.
     */
    public function countNewSince(string $since): int
    {
        $result = (new self($this->getDatabaseConnection()))
            ->select('COUNT(*) as cnt')
            ->isNull('deleted_at')
            ->gte('created_at', $since)
            ->find();

        return (int) $result->cnt;
    }

    /**
     * Count non-deleted users created between two dates [from, to).
     */
    public function countNewBetween(string $from, string $to): int
    {
        $result = (new self($this->getDatabaseConnection()))
            ->select('COUNT(*) as cnt')
            ->isNull('deleted_at')
            ->gte('created_at', $from)
            ->lt('created_at', $to)
            ->find();

        return (int) $result->cnt;
    }

    /**
     * New user registrations grouped by month.
     *
     * @param int $months Number of months to look back
     * @return array<string, int> 'YYYY-MM' => count
     */
    public function countNewByMonth(int $months = 12): array
    {
        $since = (new \DateTimeImmutable())->modify("-{$months} months")->format('Y-m-d');

        $results = (new self($this->getDatabaseConnection()))
            ->select("DATE_FORMAT(created_at, '%Y-%m') AS month", 'COUNT(*) AS cnt')
            ->isNull('deleted_at')
            ->gte('created_at', $since)
            ->group("DATE_FORMAT(created_at, '%Y-%m')")
            ->order('month ASC')
            ->findAll();

        $data = [];
        foreach ($results as $row) {
            $data[$row->month] = (int) $row->cnt;
        }
        return $data;
    }

    /**
     * Create a new user with email identity and group.
     */
    public function createUser(string $username, string $email, string $password, string $group = 'user'): self
    {
        $now = (new \DateTimeImmutable())->format('Y-m-d H:i:s');

        $user = new self($this->getDatabaseConnection());
        $user->username   = $username;
        $user->active     = true;
        $user->created_at = $now;
        $user->updated_at = $now;
        $user->insert();

        $identity = new UserIdentity($this->getDatabaseConnection());
        $identity->user_id    = $user->id;
        $identity->type       = UserIdentity::TYPE_EMAIL_PASSWORD;
        $identity->secret     = $email;
        $identity->secret2    = (new Passwords())->hash($password);
        $identity->created_at = $now;
        $identity->updated_at = $now;
        $identity->insert();

        $user->addGroup($group);

        return $user;
    }

    /**
     * Update this user record.
     */
    public function updateUser(): void
    {
        $this->updated_at = (new \DateTimeImmutable())->format('Y-m-d H:i:s');
        $this->save();
    }

    /**
     * Soft-delete this user.
     */
    public function softDelete(): void
    {
        $this->deleted_at = (new \DateTimeImmutable())->format('Y-m-d H:i:s');
        $this->updated_at = (new \DateTimeImmutable())->format('Y-m-d H:i:s');
        $this->save();
    }
}
