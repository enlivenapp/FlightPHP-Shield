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
use Enlivenapp\FlightShield\Repositories\UserIdentityRepository;

#[Entity(table: 'auth_identities', repository: UserIdentityRepository::class)]
#[Index(columns: ['type', 'secret'], unique: true)]
#[Index(columns: ['user_id'])]
class UserIdentity
{
    // Identity type constants
    public const TYPE_EMAIL_PASSWORD = 'email_password';
    public const TYPE_MAGIC_LINK     = 'magic-link';
    public const TYPE_EMAIL_2FA      = 'email_2fa';
    public const TYPE_EMAIL_ACTIVATE = 'email_activate';
    public const TYPE_ACCESS_TOKEN   = 'access_token';
    public const TYPE_HMAC_TOKEN     = 'hmac_sha256';

    #[Column(type: 'primary')]
    public int $id;

    #[Column(type: 'integer', unsigned: true)]
    public int $user_id;

    #[Column(type: 'string')]
    public string $type;

    #[Column(type: 'string', nullable: true)]
    public ?string $name = null;

    #[Column(type: 'string')]
    public string $secret;

    #[Column(type: 'string', nullable: true)]
    public ?string $secret2 = null;

    #[Column(type: 'datetime', nullable: true, typecast: 'datetime')]
    public ?\DateTimeImmutable $expires = null;

    #[Column(type: 'text', nullable: true)]
    public ?string $extra = null;

    #[Column(type: 'boolean', default: false, typecast: 'bool')]
    public bool $force_reset = false;

    #[Column(type: 'datetime', nullable: true, typecast: 'datetime')]
    public ?\DateTimeImmutable $last_used_at = null;

    #[Column(type: 'datetime', nullable: true, typecast: 'datetime')]
    public ?\DateTimeImmutable $created_at = null;

    #[Column(type: 'datetime', nullable: true, typecast: 'datetime')]
    public ?\DateTimeImmutable $updated_at = null;

    #[BelongsTo(target: User::class, innerKey: 'user_id')]
    public ?User $user = null;

    public function __debugInfo(): array
    {
        return array_diff_key(get_object_vars($this), array_flip(['secret', 'secret2']));
    }

    public function isExpired(): bool
    {
        if ($this->expires === null) {
            return false;
        }

        return $this->expires < new \DateTimeImmutable();
    }
}
