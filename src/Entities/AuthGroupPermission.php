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
use Cycle\Annotated\Annotation\Table\Index;

#[Entity(table: 'auth_group_permissions')]
#[Index(columns: ['group_alias', 'permission_alias'], unique: true)]
class AuthGroupPermission
{
    #[Column(type: 'primary')]
    public int $id;

    #[Column(type: 'string')]
    public string $group_alias;

    #[Column(type: 'string')]
    public string $permission_alias;

    #[Column(type: 'datetime', nullable: true, typecast: 'datetime')]
    public ?\DateTimeImmutable $created_at = null;
}
