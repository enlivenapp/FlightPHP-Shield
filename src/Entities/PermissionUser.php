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

#[Entity(table: 'auth_permissions_users')]
#[Index(columns: ['user_id'])]
class PermissionUser
{
    #[Column(type: 'primary')]
    public int $id;

    #[Column(type: 'integer', unsigned: true)]
    public int $user_id;

    #[Column(type: 'string')]
    public string $permission;

    #[Column(type: 'datetime', nullable: true, typecast: 'datetime')]
    public ?\DateTimeImmutable $created_at = null;

    #[BelongsTo(target: User::class, innerKey: 'user_id')]
    public ?User $user = null;
}
