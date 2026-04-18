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
use Cycle\Annotated\Annotation\Relation\HasMany;
use Cycle\Annotated\Annotation\Table\Index;
use Enlivenapp\FlightShield\Authorization\Authorizable;
use Enlivenapp\FlightShield\Repositories\UserRepository;
use Enlivenapp\FlightShield\Traits\Activatable;
use Enlivenapp\FlightShield\Traits\Bannable;
use Enlivenapp\FlightShield\Traits\HasAccessTokens;
use Enlivenapp\FlightShield\Traits\HasHmacTokens;
use Enlivenapp\FlightShield\Traits\Resettable;

#[Entity(table: 'users', repository: UserRepository::class)]
#[Index(columns: ['username'], unique: true)]
class User
{
    use Authorizable;
    use Activatable;
    use Bannable;
    use HasAccessTokens;
    use HasHmacTokens;
    use Resettable;

    #[Column(type: 'primary')]
    public int $id;

    #[Column(type: 'string', length: 30, nullable: true)]
    public ?string $username = null;

    #[Column(type: 'string', nullable: true)]
    public ?string $status = null;

    #[Column(type: 'string', nullable: true)]
    public ?string $status_message = null;

    #[Column(type: 'boolean', default: false, typecast: 'bool')]
    public bool $active = false;

    #[Column(type: 'datetime', nullable: true, typecast: 'datetime')]
    public ?\DateTimeImmutable $last_active = null;

    #[Column(type: 'datetime', nullable: true, typecast: 'datetime')]
    public ?\DateTimeImmutable $created_at = null;

    #[Column(type: 'datetime', nullable: true, typecast: 'datetime')]
    public ?\DateTimeImmutable $updated_at = null;

    #[Column(type: 'datetime', nullable: true, typecast: 'datetime')]
    public ?\DateTimeImmutable $deleted_at = null;

    #[HasMany(target: UserIdentity::class, outerKey: 'user_id')]
    public array $identities = [];

    #[HasMany(target: RememberToken::class, outerKey: 'user_id')]
    public array $remember_tokens = [];

    #[HasMany(target: GroupUser::class, outerKey: 'user_id')]
    public array $group_records = [];

    #[HasMany(target: PermissionUser::class, outerKey: 'user_id')]
    public array $permission_records = [];
}
