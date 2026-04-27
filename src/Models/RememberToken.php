<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Models;

class RememberToken extends \flight\ActiveRecord
{
    public function __construct($pdo = null, array $config = [])
    {
        parent::__construct($pdo, 'auth_remember_tokens', $config);
    }

    public int $id;
    public string $selector;
    public string $hashed_validator;
    public int $user_id;
    public string $expires;
    public ?string $created_at = null;
    public ?string $updated_at = null;

    public function isExpired(): bool
    {
        return new \DateTimeImmutable($this->expires) < new \DateTimeImmutable();
    }

    // -----------------------------------------------------------------
    // Finders (from RememberTokenRepository)
    // -----------------------------------------------------------------

    public function findBySelector(string $selector): ?self
    {
        $token = new self($this->getDatabaseConnection());
        $token->eq('selector', $selector)->find();

        return $token->isHydrated() ? $token : null;
    }

    public function deleteByUser(int $userId): void
    {
        $token = new self($this->getDatabaseConnection());
        $tokens = $token->eq('user_id', $userId)->findAll();

        foreach ($tokens as $t) {
            $t->delete();
        }
    }

    public function purgeExpired(): void
    {
        $now = (new \DateTimeImmutable())->format('Y-m-d H:i:s');

        $token = new self($this->getDatabaseConnection());
        $tokens = $token->lt('expires', $now)->findAll();

        foreach ($tokens as $t) {
            $t->delete();
        }
    }
}
