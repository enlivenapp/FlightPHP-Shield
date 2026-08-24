<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Models;

use Enlivenapp\FlightShield\Authentication\HMAC\HmacEncrypter;

class UserIdentity extends \flight\ActiveRecord
{
    // Identity type constants
    public const TYPE_EMAIL_PASSWORD = 'email_password';
    public const TYPE_MAGIC_LINK     = 'magic-link';
    public const TYPE_EMAIL_2FA      = 'email_2fa';
    public const TYPE_EMAIL_ACTIVATE = 'email_activate';
    public const TYPE_ACCESS_TOKEN   = 'access_token';
    public const TYPE_HMAC_TOKEN     = 'hmac_sha256';

    public function __construct($pdo = null, array $config = [])
    {
        parent::__construct($pdo, 'auth_identities', $config);
    }

    public int $id;
    public int $user_id;
    public string $type;
    public ?string $name = null;
    public string $secret;
    public ?string $secret2 = null;
    public ?string $expires = null;
    public ?string $extra = null;
    public bool $force_reset = false;
    public ?string $last_used_at = null;
    public ?string $created_at = null;
    public ?string $updated_at = null;

    public function __debugInfo(): array
    {
        return array_diff_key(get_object_vars($this), array_flip(['secret', 'secret2']));
    }

    public function isExpired(): bool
    {
        if ($this->expires === null) {
            return false;
        }

        return new \DateTimeImmutable($this->expires) < new \DateTimeImmutable();
    }

    // -----------------------------------------------------------------
    // Email/Password (from UserIdentityRepository)
    // -----------------------------------------------------------------

    public function getEmailIdentity(User $user): ?self
    {
        $identity = new self($this->getDatabaseConnection());
        $identity->eq('user_id', $user->id)
                 ->eq('type', self::TYPE_EMAIL_PASSWORD)
                 ->find();

        return $identity->isHydrated() ? $identity : null;
    }

    public function createEmailIdentity(User $user, array $credentials): self
    {
        $identity = new self($this->getDatabaseConnection());
        $identity->user_id    = $user->id;
        $identity->type       = self::TYPE_EMAIL_PASSWORD;
        $identity->secret     = $credentials['email'];
        $identity->secret2    = $credentials['password_hash'];
        $identity->created_at = (new \DateTimeImmutable())->format('Y-m-d H:i:s');
        $identity->updated_at = (new \DateTimeImmutable())->format('Y-m-d H:i:s');
        $identity->insert();

        return $identity;
    }

    // -----------------------------------------------------------------
    // Access Tokens (from UserIdentityRepository)
    // -----------------------------------------------------------------

    public function generateAccessToken(User $user, string $name, array $scopes, ?\DateTimeImmutable $expiresAt): AccessToken
    {
        $rawToken = bin2hex(random_bytes(32));

        $identity = new self($this->getDatabaseConnection());
        $identity->user_id    = $user->id;
        $identity->type       = self::TYPE_ACCESS_TOKEN;
        $identity->name       = $name;
        $identity->secret     = hash('sha256', $rawToken);
        $identity->extra      = json_encode($scopes);
        $identity->expires    = $expiresAt?->format('Y-m-d H:i:s');
        $identity->created_at = (new \DateTimeImmutable())->format('Y-m-d H:i:s');
        $identity->updated_at = (new \DateTimeImmutable())->format('Y-m-d H:i:s');
        $identity->insert();

        $token = AccessToken::fromIdentity($identity);
        $token->rawToken = $rawToken;

        return $token;
    }

    public function getAccessTokenByRawToken(string $rawToken): ?self
    {
        $identity = new self($this->getDatabaseConnection());
        $identity->eq('type', self::TYPE_ACCESS_TOKEN)
                 ->eq('secret', hash('sha256', $rawToken))
                 ->find();

        return $identity->isHydrated() ? $identity : null;
    }

    public function getAccessToken(User $user, string $rawToken): ?AccessToken
    {
        $identity = new self($this->getDatabaseConnection());
        $identity->eq('user_id', $user->id)
                 ->eq('type', self::TYPE_ACCESS_TOKEN)
                 ->eq('secret', hash('sha256', $rawToken))
                 ->find();

        return $identity->isHydrated() ? AccessToken::fromIdentity($identity) : null;
    }

    public function getAccessTokenById(int $id, User $user): ?AccessToken
    {
        $identity = new self($this->getDatabaseConnection());
        $identity->eq('id', $id)
                 ->eq('user_id', $user->id)
                 ->eq('type', self::TYPE_ACCESS_TOKEN)
                 ->find();

        return $identity->isHydrated() ? AccessToken::fromIdentity($identity) : null;
    }

    public function getAllAccessTokens(User $user): array
    {
        $identity = new self($this->getDatabaseConnection());
        $identities = $identity->eq('user_id', $user->id)
                               ->eq('type', self::TYPE_ACCESS_TOKEN)
                               ->findAll();

        return array_map(fn(self $i) => AccessToken::fromIdentity($i), $identities);
    }

    public function revokeAccessToken(User $user, string $rawToken): void
    {
        $identity = new self($this->getDatabaseConnection());
        $identity->eq('user_id', $user->id)
                 ->eq('type', self::TYPE_ACCESS_TOKEN)
                 ->eq('secret', hash('sha256', $rawToken))
                 ->find();

        if ($identity->isHydrated()) {
            $identity->delete();
        }
    }

    public function revokeAllAccessTokens(User $user): void
    {
        $identity = new self($this->getDatabaseConnection());
        $identities = $identity->eq('user_id', $user->id)
                               ->eq('type', self::TYPE_ACCESS_TOKEN)
                               ->findAll();

        foreach ($identities as $i) {
            $i->delete();
        }
    }

    // -----------------------------------------------------------------
    // HMAC Tokens (from UserIdentityRepository)
    // -----------------------------------------------------------------

    public function generateHmacToken(User $user, string $name, array $scopes, ?\DateTimeImmutable $expiresAt, ?HmacEncrypter $encrypter = null): AccessToken
    {
        $key       = bin2hex(random_bytes(16));
        $secretKey = base64_encode(random_bytes(32));

        $identity = new self($this->getDatabaseConnection());
        $identity->user_id    = $user->id;
        $identity->type       = self::TYPE_HMAC_TOKEN;
        $identity->name       = $name;
        $identity->secret     = $key;
        $identity->secret2    = $encrypter !== null ? $encrypter->encrypt($secretKey) : $secretKey;
        $identity->extra      = json_encode($scopes);
        $identity->expires    = $expiresAt?->format('Y-m-d H:i:s');
        $identity->created_at = (new \DateTimeImmutable())->format('Y-m-d H:i:s');
        $identity->updated_at = (new \DateTimeImmutable())->format('Y-m-d H:i:s');
        $identity->insert();

        $token = AccessToken::fromIdentity($identity);
        $token->rawToken = $key;

        return $token;
    }

    public function getHmacTokenByKey(string $key): ?self
    {
        $identity = new self($this->getDatabaseConnection());
        $identity->eq('type', self::TYPE_HMAC_TOKEN)
                 ->eq('secret', $key)
                 ->find();

        return $identity->isHydrated() ? $identity : null;
    }

    public function getHmacToken(User $user, string $key): ?AccessToken
    {
        $identity = new self($this->getDatabaseConnection());
        $identity->eq('user_id', $user->id)
                 ->eq('type', self::TYPE_HMAC_TOKEN)
                 ->eq('secret', $key)
                 ->find();

        return $identity->isHydrated() ? AccessToken::fromIdentity($identity) : null;
    }

    public function getHmacTokenById(int $id, User $user): ?AccessToken
    {
        $identity = new self($this->getDatabaseConnection());
        $identity->eq('id', $id)
                 ->eq('user_id', $user->id)
                 ->eq('type', self::TYPE_HMAC_TOKEN)
                 ->find();

        return $identity->isHydrated() ? AccessToken::fromIdentity($identity) : null;
    }

    public function getAllHmacTokens(User $user): array
    {
        $identity = new self($this->getDatabaseConnection());
        $identities = $identity->eq('user_id', $user->id)
                               ->eq('type', self::TYPE_HMAC_TOKEN)
                               ->findAll();

        return array_map(fn(self $i) => AccessToken::fromIdentity($i), $identities);
    }

    public function revokeHmacToken(User $user, string $key): void
    {
        $identity = new self($this->getDatabaseConnection());
        $identity->eq('user_id', $user->id)
                 ->eq('type', self::TYPE_HMAC_TOKEN)
                 ->eq('secret', $key)
                 ->find();

        if ($identity->isHydrated()) {
            $identity->delete();
        }
    }

    public function revokeAllHmacTokens(User $user): void
    {
        $identity = new self($this->getDatabaseConnection());
        $identities = $identity->eq('user_id', $user->id)
                               ->eq('type', self::TYPE_HMAC_TOKEN)
                               ->findAll();

        foreach ($identities as $i) {
            $i->delete();
        }
    }

    // -----------------------------------------------------------------
    // Action Identities (2FA, Email Activation, Magic Link)
    // -----------------------------------------------------------------

    public function createCodeIdentity(User $user, array $data, callable $generator): string
    {
        $code = $generator();

        $expires = $data['expires'] ?? new \DateTimeImmutable('+10 minutes');
        if ($expires instanceof \DateTimeImmutable) {
            $expires = $expires->format('Y-m-d H:i:s');
        }

        $identity = new self($this->getDatabaseConnection());
        $identity->user_id    = $user->id;
        $identity->type       = $data['type'];
        $identity->name       = $data['name'] ?? null;
        $identity->secret     = hash('sha256', $code);
        $identity->extra      = $data['extra'] ?? null;
        $identity->expires    = $expires;
        $identity->created_at = (new \DateTimeImmutable())->format('Y-m-d H:i:s');
        $identity->updated_at = (new \DateTimeImmutable())->format('Y-m-d H:i:s');
        $identity->insert();

        return $code;
    }

    public function getIdentityByType(User $user, string $type): ?self
    {
        $identity = new self($this->getDatabaseConnection());
        $identity->eq('user_id', $user->id)
                 ->eq('type', $type)
                 ->find();

        return $identity->isHydrated() ? $identity : null;
    }

    public function getIdentityBySecret(string $type, string $secret): ?self
    {
        $identity = new self($this->getDatabaseConnection());
        $identity->eq('type', $type)
                 ->eq('secret', $secret)
                 ->find();

        return $identity->isHydrated() ? $identity : null;
    }

    public function deleteIdentitiesByType(User $user, string $type): void
    {
        $identity = new self($this->getDatabaseConnection());
        $identities = $identity->eq('user_id', $user->id)
                               ->eq('type', $type)
                               ->findAll();

        foreach ($identities as $i) {
            $i->delete();
        }
    }

    public function getIdentitiesByUser(User $user): array
    {
        $identity = new self($this->getDatabaseConnection());

        return $identity->eq('user_id', $user->id)->findAll();
    }

    // -----------------------------------------------------------------
    // Utility
    // -----------------------------------------------------------------

    public function touchIdentity(self $identity): void
    {
        $identity->last_used_at = (new \DateTimeImmutable())->format('Y-m-d H:i:s');
        $identity->save();
    }

    public function setIdentityExpirationById(int $id, User $user, ?string $expiresAt): bool
    {
        $identity = new self($this->getDatabaseConnection());
        $identity->eq('id', $id)
                 ->eq('user_id', $user->id)
                 ->find();

        if (!$identity->isHydrated()) {
            return false;
        }

        $identity->expires = $expiresAt;
        // Explicit dirty(): covers null-clearing when $data lacks the key.
        $identity->dirty(['expires' => $expiresAt]);
        $identity->save();

        return true;
    }

    public function forcePasswordReset(User $user, bool $force): void
    {
        $identity = $this->getEmailIdentity($user);

        if ($identity === null) {
            return;
        }

        $identity->force_reset = $force;
        // Explicit dirty(): typed property assignment bypasses __set(),
        // and loose comparison misses bool flips (force_reset true -> false == 0/'0').
        $identity->dirty(['force_reset' => $force]);
        $identity->save();
    }
}
