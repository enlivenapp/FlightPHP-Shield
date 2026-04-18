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

#[Entity(table: 'auth_logins')]
#[Index(columns: ['id_type', 'identifier'])]
#[Index(columns: ['user_id'])]
class Login
{
    #[Column(type: 'primary')]
    public int $id;

    #[Column(type: 'string')]
    public string $ip_address;

    #[Column(type: 'string', nullable: true)]
    public ?string $user_agent = null;

    #[Column(type: 'string')]
    public string $id_type;

    #[Column(type: 'string')]
    public string $identifier;

    #[Column(type: 'integer', unsigned: true, nullable: true)]
    public ?int $user_id = null;

    #[Column(type: 'datetime', typecast: 'datetime')]
    public \DateTimeImmutable $date;

    #[Column(type: 'boolean', typecast: 'bool')]
    public bool $success;
}
