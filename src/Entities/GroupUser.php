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

#[Entity(table: 'auth_groups_users')]
#[Index(columns: ['user_id'])]
class GroupUser
{
    #[Column(type: 'primary')]
    public int $id;

    #[Column(type: 'integer', unsigned: true)]
    public int $user_id;

    #[Column(type: 'string', name: 'group')]
    public string $group;

    #[Column(type: 'datetime', nullable: true, typecast: 'datetime')]
    public ?\DateTimeImmutable $created_at = null;

    #[BelongsTo(target: User::class, innerKey: 'user_id')]
    public ?User $user = null;
}
