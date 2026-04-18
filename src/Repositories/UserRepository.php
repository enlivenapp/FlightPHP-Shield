<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Repositories;

use Cycle\ORM\Select\Repository;
use Enlivenapp\FlightShield\Entities\User;
use Enlivenapp\FlightShield\Entities\UserIdentity;

/**
 * @extends Repository<User>
 */
class UserRepository extends Repository
{
    public function findById(int|string $id): ?User
    {
        return $this->select()
            ->where('id', $id)
            ->where('deleted_at', null)
            ->fetchOne();
    }

    public function findByCredentials(array $credentials): ?User
    {
        if (isset($credentials['email'])) {
            /** @var \Cycle\ORM\RepositoryInterface $identityRepo */
            $identityRepo = \Flight::app()->orm()->getRepository(UserIdentity::class);
            $identity = $identityRepo->select()
                ->where('type', UserIdentity::TYPE_EMAIL_PASSWORD)
                ->where('secret', $credentials['email'])
                ->fetchOne();

            if ($identity === null) {
                return null;
            }

            return $this->findById($identity->user_id);
        }

        if (isset($credentials['username'])) {
            return $this->select()
                ->where('username', $credentials['username'])
                ->where('deleted_at', null)
                ->fetchOne();
        }

        return null;
    }

    public function findActive(): array
    {
        return $this->select()
            ->where('active', true)
            ->where('deleted_at', null)
            ->fetchAll();
    }
}
