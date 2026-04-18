<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Repositories;

use Cycle\ORM\EntityManager;
use Cycle\ORM\ORMInterface;
use Cycle\ORM\Select\Repository;
use Enlivenapp\FlightShield\Entities\AccessToken;
use Enlivenapp\FlightShield\Entities\User;
use Enlivenapp\FlightShield\Entities\UserIdentity;

/**
 * @extends Repository<UserIdentity>
 */
class UserIdentityRepository extends Repository
{
    // -----------------------------------------------------------------
    // Email/Password
    // -----------------------------------------------------------------

    public function getEmailIdentity(User $user): ?UserIdentity
    {
        return $this->select()
            ->where('user_id', $user->id)
            ->where('type', UserIdentity::TYPE_EMAIL_PASSWORD)
            ->fetchOne();
    }

    public function createEmailIdentity(User $user, array $credentials, ORMInterface $orm): UserIdentity
    {
        $identity = new UserIdentity();
        $identity->user_id = $user->id;
        $identity->type    = UserIdentity::TYPE_EMAIL_PASSWORD;
        $identity->secret  = $credentials['email'];
        $identity->secret2 = $credentials['password_hash'];
        $identity->created_at = new \DateTimeImmutable();
        $identity->updated_at = new \DateTimeImmutable();

        $em = new EntityManager($orm);
        $em->persist($identity)->run();

        return $identity;
    }

    // -----------------------------------------------------------------
    // Access Tokens
    // -----------------------------------------------------------------

    public function generateAccessToken(User $user, string $name, array $scopes, ?\DateTimeImmutable $expiresAt, ORMInterface $orm): AccessToken
    {
        $rawToken = bin2hex(random_bytes(32));

        $identity = new UserIdentity();
        $identity->user_id = $user->id;
        $identity->type    = UserIdentity::TYPE_ACCESS_TOKEN;
        $identity->name    = $name;
        $identity->secret  = hash('sha256', $rawToken);
        $identity->extra   = json_encode($scopes);
        $identity->expires = $expiresAt;
        $identity->created_at = new \DateTimeImmutable();
        $identity->updated_at = new \DateTimeImmutable();

        $em = new EntityManager($orm);
        $em->persist($identity)->run();

        $token = AccessToken::fromIdentity($identity);
        $token->rawToken = $rawToken;

        return $token;
    }

    public function getAccessTokenByRawToken(string $rawToken): ?UserIdentity
    {
        return $this->select()
            ->where('type', UserIdentity::TYPE_ACCESS_TOKEN)
            ->where('secret', hash('sha256', $rawToken))
            ->fetchOne();
    }

    public function getAccessToken(User $user, string $rawToken): ?AccessToken
    {
        $identity = $this->select()
            ->where('user_id', $user->id)
            ->where('type', UserIdentity::TYPE_ACCESS_TOKEN)
            ->where('secret', hash('sha256', $rawToken))
            ->fetchOne();

        return $identity ? AccessToken::fromIdentity($identity) : null;
    }

    public function getAccessTokenById(int $id, User $user): ?AccessToken
    {
        $identity = $this->select()
            ->where('id', $id)
            ->where('user_id', $user->id)
            ->where('type', UserIdentity::TYPE_ACCESS_TOKEN)
            ->fetchOne();

        return $identity ? AccessToken::fromIdentity($identity) : null;
    }

    public function getAllAccessTokens(User $user): array
    {
        $identities = $this->select()
            ->where('user_id', $user->id)
            ->where('type', UserIdentity::TYPE_ACCESS_TOKEN)
            ->fetchAll();

        return array_map(fn(UserIdentity $i) => AccessToken::fromIdentity($i), $identities);
    }

    public function revokeAccessToken(User $user, string $rawToken, ORMInterface $orm): void
    {
        $identity = $this->select()
            ->where('user_id', $user->id)
            ->where('type', UserIdentity::TYPE_ACCESS_TOKEN)
            ->where('secret', hash('sha256', $rawToken))
            ->fetchOne();

        if ($identity) {
            $em = new EntityManager($orm);
            $em->delete($identity)->run();
        }
    }

    public function revokeAllAccessTokens(User $user, ORMInterface $orm): void
    {
        $identities = $this->select()
            ->where('user_id', $user->id)
            ->where('type', UserIdentity::TYPE_ACCESS_TOKEN)
            ->fetchAll();

        $em = new EntityManager($orm);
        foreach ($identities as $identity) {
            $em->delete($identity);
        }
        $em->run();
    }

    // -----------------------------------------------------------------
    // HMAC Tokens
    // -----------------------------------------------------------------

    public function generateHmacToken(User $user, string $name, array $scopes, ?\DateTimeImmutable $expiresAt, ORMInterface $orm): AccessToken
    {
        $key       = bin2hex(random_bytes(16));
        $secretKey = base64_encode(random_bytes(32));

        $identity = new UserIdentity();
        $identity->user_id = $user->id;
        $identity->type    = UserIdentity::TYPE_HMAC_TOKEN;
        $identity->name    = $name;
        $identity->secret  = $key;
        $identity->secret2 = $secretKey;
        $identity->extra   = json_encode($scopes);
        $identity->expires = $expiresAt;
        $identity->created_at = new \DateTimeImmutable();
        $identity->updated_at = new \DateTimeImmutable();

        $em = new EntityManager($orm);
        $em->persist($identity)->run();

        $token = AccessToken::fromIdentity($identity);
        $token->rawToken = $key;

        return $token;
    }

    public function getHmacTokenByKey(string $key): ?UserIdentity
    {
        return $this->select()
            ->where('type', UserIdentity::TYPE_HMAC_TOKEN)
            ->where('secret', $key)
            ->fetchOne();
    }

    public function getHmacToken(User $user, string $key): ?AccessToken
    {
        $identity = $this->select()
            ->where('user_id', $user->id)
            ->where('type', UserIdentity::TYPE_HMAC_TOKEN)
            ->where('secret', $key)
            ->fetchOne();

        return $identity ? AccessToken::fromIdentity($identity) : null;
    }

    public function getHmacTokenById(int $id, User $user): ?AccessToken
    {
        $identity = $this->select()
            ->where('id', $id)
            ->where('user_id', $user->id)
            ->where('type', UserIdentity::TYPE_HMAC_TOKEN)
            ->fetchOne();

        return $identity ? AccessToken::fromIdentity($identity) : null;
    }

    public function getAllHmacTokens(User $user): array
    {
        $identities = $this->select()
            ->where('user_id', $user->id)
            ->where('type', UserIdentity::TYPE_HMAC_TOKEN)
            ->fetchAll();

        return array_map(fn(UserIdentity $i) => AccessToken::fromIdentity($i), $identities);
    }

    public function revokeHmacToken(User $user, string $key, ORMInterface $orm): void
    {
        $identity = $this->select()
            ->where('user_id', $user->id)
            ->where('type', UserIdentity::TYPE_HMAC_TOKEN)
            ->where('secret', $key)
            ->fetchOne();

        if ($identity) {
            $em = new EntityManager($orm);
            $em->delete($identity)->run();
        }
    }

    public function revokeAllHmacTokens(User $user, ORMInterface $orm): void
    {
        $identities = $this->select()
            ->where('user_id', $user->id)
            ->where('type', UserIdentity::TYPE_HMAC_TOKEN)
            ->fetchAll();

        $em = new EntityManager($orm);
        foreach ($identities as $identity) {
            $em->delete($identity);
        }
        $em->run();
    }

    // -----------------------------------------------------------------
    // Action Identities (2FA, Email Activation, Magic Link)
    // -----------------------------------------------------------------

    public function createCodeIdentity(User $user, array $data, callable $generator, ORMInterface $orm): string
    {
        $code = $generator();

        $identity = new UserIdentity();
        $identity->user_id = $user->id;
        $identity->type    = $data['type'];
        $identity->name    = $data['name'] ?? null;
        $identity->secret  = $code;
        $identity->extra   = $data['extra'] ?? null;
        $identity->expires = $data['expires'] ?? new \DateTimeImmutable('+10 minutes');
        $identity->created_at = new \DateTimeImmutable();
        $identity->updated_at = new \DateTimeImmutable();

        $em = new EntityManager($orm);
        $em->persist($identity)->run();

        return $code;
    }

    public function getIdentityByType(User $user, string $type): ?UserIdentity
    {
        return $this->select()
            ->where('user_id', $user->id)
            ->where('type', $type)
            ->fetchOne();
    }

    public function getIdentityBySecret(string $type, string $secret): ?UserIdentity
    {
        return $this->select()
            ->where('type', $type)
            ->where('secret', $secret)
            ->fetchOne();
    }

    public function deleteIdentitiesByType(User $user, string $type, ORMInterface $orm): void
    {
        $identities = $this->select()
            ->where('user_id', $user->id)
            ->where('type', $type)
            ->fetchAll();

        $em = new EntityManager($orm);
        foreach ($identities as $identity) {
            $em->delete($identity);
        }
        $em->run();
    }

    public function getIdentitiesByUser(User $user): array
    {
        return $this->select()
            ->where('user_id', $user->id)
            ->fetchAll();
    }

    // -----------------------------------------------------------------
    // Utility
    // -----------------------------------------------------------------

    public function touchIdentity(UserIdentity $identity, ORMInterface $orm): void
    {
        $identity->last_used_at = new \DateTimeImmutable();
        $em = new EntityManager($orm);
        $em->persist($identity)->run();
    }

    public function setIdentityExpirationById(int $id, User $user, ?\DateTimeImmutable $expiresAt, ORMInterface $orm): bool
    {
        $identity = $this->select()
            ->where('id', $id)
            ->where('user_id', $user->id)
            ->fetchOne();

        if ($identity === null) {
            return false;
        }

        $identity->expires = $expiresAt;
        $em = new EntityManager($orm);
        $em->persist($identity)->run();

        return true;
    }

    public function forcePasswordReset(User $user, bool $force, ORMInterface $orm): void
    {
        $identity = $this->getEmailIdentity($user);

        if ($identity === null) {
            return;
        }

        $identity->force_reset = $force;
        $em = new EntityManager($orm);
        $em->persist($identity)->run();
    }
}
