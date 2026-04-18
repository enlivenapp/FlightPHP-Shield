<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Entities;

use Cycle\Annotated\Annotation\Column;
use Cycle\Annotated\Annotation\Entity;
use Cycle\Annotated\Annotation\Relation\BelongsTo;
use Cycle\Annotated\Annotation\Table\Index;
use Enlivenapp\FlightShield\Repositories\RememberTokenRepository;

#[Entity(table: 'auth_remember_tokens', repository: RememberTokenRepository::class)]
#[Index(columns: ['selector'], unique: true)]
#[Index(columns: ['user_id'])]
class RememberToken
{
    #[Column(type: 'primary')]
    public int $id;

    #[Column(type: 'string')]
    public string $selector;

    #[Column(type: 'string')]
    public string $hashed_validator;

    #[Column(type: 'integer', unsigned: true)]
    public int $user_id;

    #[Column(type: 'datetime', typecast: 'datetime')]
    public \DateTimeImmutable $expires;

    #[Column(type: 'datetime', nullable: true, typecast: 'datetime')]
    public ?\DateTimeImmutable $created_at = null;

    #[Column(type: 'datetime', nullable: true, typecast: 'datetime')]
    public ?\DateTimeImmutable $updated_at = null;

    #[BelongsTo(target: User::class, innerKey: 'user_id')]
    public ?User $user = null;

    public function isExpired(): bool
    {
        return $this->expires < new \DateTimeImmutable();
    }
}
