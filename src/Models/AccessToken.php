<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Models;

/**
 * Represents an access token or HMAC token.
 * Wraps a UserIdentity with token-specific convenience methods.
 */
class AccessToken
{
    public int $id;
    public int $user_id;
    public string $name;
    public string $secret;
    public ?string $secret2;
    public ?string $rawToken = null;
    public ?string $expires = null;
    public ?string $last_used_at = null;
    public ?string $created_at = null;
    public ?string $updated_at = null;
    public ?string $extra = null;

    /**
     * The scopes/permissions this token grants.
     *
     * @var list<string>
     */
    protected array $scopes = [];

    public static function fromIdentity(UserIdentity $identity): static
    {
        $token = new static();
        $token->id           = $identity->id;
        $token->user_id      = $identity->user_id;
        $token->name         = $identity->name ?? '';
        $token->secret       = $identity->secret;
        $token->secret2      = $identity->secret2;
        $token->expires      = $identity->expires;
        $token->last_used_at = $identity->last_used_at;
        $token->created_at   = $identity->created_at;
        $token->updated_at   = $identity->updated_at;

        if ($identity->extra !== null) {
            $decoded = json_decode($identity->extra, true);
            if (is_array($decoded)) {
                $token->scopes = $decoded;
            }
        }

        return $token;
    }

    /**
     * Determines if this token grants the given scope.
     */
    public function can(string $scope): bool
    {
        if (in_array('*', $this->scopes, true)) {
            return true;
        }

        return in_array($scope, $this->scopes, true);
    }

    /**
     * Determines if this token does NOT grant the given scope.
     */
    public function cant(string $scope): bool
    {
        if (in_array('*', $this->scopes, true)) {
            return false;
        }

        return ! in_array($scope, $this->scopes, true);
    }

    /**
     * @return list<string>
     */
    public function getScopes(): array
    {
        return $this->scopes;
    }

    public function setScopes(array $scopes): void
    {
        $this->scopes = $scopes;
    }

    public function __debugInfo(): array
    {
        return array_diff_key(get_object_vars($this), array_flip(['secret', 'secret2', 'rawToken']));
    }

    public function isExpired(): bool
    {
        if ($this->expires === null) {
            return false;
        }

        return new \DateTimeImmutable($this->expires) < new \DateTimeImmutable();
    }
}
