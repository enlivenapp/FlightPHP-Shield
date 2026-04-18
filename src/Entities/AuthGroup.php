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

#[Entity(table: 'auth_groups')]
#[Index(columns: ['alias'], unique: true)]
class AuthGroup
{
    #[Column(type: 'primary')]
    public int $id;

    #[Column(type: 'string')]
    public string $alias;

    #[Column(type: 'string')]
    public string $title;

    #[Column(type: 'string', nullable: true)]
    public ?string $description = null;

    #[Column(type: 'datetime', nullable: true, typecast: 'datetime')]
    public ?\DateTimeImmutable $created_at = null;

    #[Column(type: 'datetime', nullable: true, typecast: 'datetime')]
    public ?\DateTimeImmutable $updated_at = null;
}
