<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Authentication\Authenticators;

use Cycle\ORM\EntityManager;
use Enlivenapp\FlightShield\Authentication\AuthenticatorInterface;
use Enlivenapp\FlightShield\Entities\AccessToken;
use Enlivenapp\FlightShield\Entities\TokenLogin;
use Enlivenapp\FlightShield\Entities\User;
use Enlivenapp\FlightShield\Entities\UserIdentity;
use Enlivenapp\FlightShield\Exceptions\AuthenticationException;
use Enlivenapp\FlightShield\Repositories\UserIdentityRepository;
use Enlivenapp\FlightShield\Repositories\UserRepository;
use Enlivenapp\FlightShield\Result;
use flight\Engine;

class AccessTokens implements AuthenticatorInterface
{
    public const ID_TYPE_ACCESS_TOKEN = 'access_token';

    protected Engine $app;
    protected array $config;
    protected ?User $user = null;

    public function __construct(Engine $app, array $config)
    {
        $this->app = $app;
        $this->config = $config;
    }

    public function attempt(array $credentials): Result
    {
        $result = $this->check($credentials);

        if (! $result->isOK()) {
            $this->recordTokenLogin($credentials['token'] ?? '', false);
            return $result;
        }

        $user = $result->extraInfo();

        if ($user->isBanned()) {
            $this->recordTokenLogin($user->currentAccessToken()->name ?? '', false, $user->id);
            $this->user = null;

            return (new Result())
                ->setSuccess(false)
                ->setReason('Account is not active.');
        }

        $this->login($user);
        $this->recordTokenLogin($user->currentAccessToken()->name ?? '', true, $user->id);

        return $result;
    }

    public function check(array $credentials): Result
    {
        if (! isset($credentials['token']) || $credentials['token'] === '') {
            return (new Result())
                ->setSuccess(false)
                ->setReason('No token provided.');
        }

        $rawToken = $credentials['token'];
        if (str_starts_with($rawToken, 'Bearer')) {
            $rawToken = trim(substr($rawToken, 6));
        }

        /** @var UserIdentityRepository $identityRepo */
        $identityRepo = $this->app->orm()->getRepository(UserIdentity::class);
        $identity = $identityRepo->getAccessTokenByRawToken($rawToken);

        if ($identity === null) {
            return (new Result())
                ->setSuccess(false)
                ->setReason('Invalid token.');
        }

        // Expired?
        if ($identity->isExpired()) {
            return (new Result())
                ->setSuccess(false)
                ->setReason('Token has expired.');
        }

        // Unused too long?
        $unusedLifetime = $this->config['unused_token_lifetime'] ?? null;
        if ($unusedLifetime && $identity->last_used_at) {
            $cutoff = new \DateTimeImmutable("-{$unusedLifetime} seconds");
            if ($identity->last_used_at < $cutoff) {
                return (new Result())
                    ->setSuccess(false)
                    ->setReason('Token has expired from disuse.');
            }
        }

        // Touch last_used_at
        $identityRepo->touchIdentity($identity, $this->app->orm());

        /** @var UserRepository $userRepo */
        $userRepo = $this->app->orm()->getRepository(User::class);
        $user = $userRepo->findById($identity->user_id);

        if ($user === null) {
            return (new Result())
                ->setSuccess(false)
                ->setReason('Invalid token.');
        }

        $token = AccessToken::fromIdentity($identity);
        $user->setAccessToken($token);

        return (new Result())
            ->setSuccess(true)
            ->setExtraInfo($user);
    }

    public function loggedIn(): bool
    {
        if ($this->user !== null) {
            return true;
        }

        $header = $this->config['token_header'] ?? 'Authorization';
        $headerValue = $_SERVER['HTTP_' . strtoupper(str_replace('-', '_', $header))] ?? '';

        return $this->attempt(['token' => $headerValue])->isOK();
    }

    public function login(User $user): void
    {
        $this->user = $user;
    }

    public function loginById(int|string $userId): void
    {
        /** @var UserRepository $userRepo */
        $userRepo = $this->app->orm()->getRepository(User::class);
        $user = $userRepo->findById($userId);

        if ($user === null) {
            throw AuthenticationException::forInvalidUser();
        }

        $this->login($user);
    }

    public function logout(): void
    {
        $this->user = null;
    }

    public function getUser(): ?User
    {
        return $this->user;
    }

    public function recordActiveDate(): void
    {
        if ($this->user === null) {
            return;
        }

        $this->user->last_active = new \DateTimeImmutable();
        $em = new EntityManager($this->app->orm());
        $em->persist($this->user)->run();
    }

    protected function recordTokenLogin(string $identifier, bool $success, ?int $userId = null): void
    {
        $recordLevel = $this->config['record_login_attempt'] ?? 'none';

        if ($recordLevel === 'none') {
            return;
        }
        if ($recordLevel === 'failure' && $success) {
            return;
        }

        $login = new TokenLogin();
        $login->id_type    = self::ID_TYPE_ACCESS_TOKEN;
        $login->identifier = $identifier;
        $login->success    = $success;
        $login->user_id    = $userId;
        $login->ip_address = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
        $login->user_agent = $_SERVER['HTTP_USER_AGENT'] ?? null;
        $login->date       = new \DateTimeImmutable();

        $em = new EntityManager($this->app->orm());
        $em->persist($login)->run();
    }
}
