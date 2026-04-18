<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Repositories;

use Cycle\ORM\EntityManager;
use Cycle\ORM\ORMInterface;
use Cycle\ORM\Select\Repository;
use Enlivenapp\FlightShield\Entities\RememberToken;
use Enlivenapp\FlightShield\Entities\User;

/**
 * @extends Repository<RememberToken>
 */
class RememberTokenRepository extends Repository
{
    public function findBySelector(string $selector): ?RememberToken
    {
        return $this->select()
            ->where('selector', $selector)
            ->fetchOne();
    }

    public function deleteByUser(int $userId, ORMInterface $orm): void
    {
        $tokens = $this->select()
            ->where('user_id', $userId)
            ->fetchAll();

        $em = new EntityManager($orm);
        foreach ($tokens as $token) {
            $em->delete($token);
        }
        $em->run();
    }

    public function purgeExpired(ORMInterface $orm): void
    {
        $now = new \DateTimeImmutable();
        $tokens = $this->select()
            ->where('expires', '<', $now)
            ->fetchAll();

        $em = new EntityManager($orm);
        foreach ($tokens as $token) {
            $em->delete($token);
        }
        $em->run();
    }
}
