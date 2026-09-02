<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Authentication\Authenticators;

use Enlivenapp\FlightShield\Authentication\AuthenticatorInterface;
use Enlivenapp\FlightShield\Models\AccessToken;
use Enlivenapp\FlightShield\Models\TokenLogin;
use Enlivenapp\FlightShield\Models\User;
use Enlivenapp\FlightShield\Models\UserIdentity;
use Enlivenapp\FlightShield\Exceptions\AuthenticationException;
use Enlivenapp\FlightShield\Result;
use flight\Engine;

class AccessTokens implements AuthenticatorInterface
{
    public const ID_TYPE_ACCESS_TOKEN = 'access_token';

    protected Engine $app;
    protected array $config;
    protected ?User $user = null;
    protected bool $tokenChecked = false;

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

        $identityModel = new UserIdentity(\Flight::db());
        $identity = $identityModel->getAccessTokenByRawToken($rawToken);

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
        $identityModel->touchIdentity($identity);

        $userModel = new User(\Flight::db());
        $user = $userModel->findById($identity->user_id);

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

        if ($this->tokenChecked) {
            return false;
        }

        $this->tokenChecked = true;

        $header = $this->config['token_header'] ?? 'Authorization';
        $headerValue = $_SERVER['HTTP_' . strtoupper(str_replace('-', '_', $header))] ?? '';

        $result = $this->check(['token' => $headerValue]);

        if ($result->isOK()) {
            $user = $result->extraInfo();
            if (!$user->isBanned()) {
                $this->login($user);
                return true;
            }
        }

        return false;
    }

    public function login(User $user): void
    {
        $this->user = $user;
    }

    public function loginById(int|string $userId): void
    {
        $userModel = new User(\Flight::db());
        $user = $userModel->findById($userId);

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

        // Only record the active date for activated, non-banned users.
        if ($this->user->isBanned() || ! $this->user->isActivated()) {
            return;
        }

        $this->user->last_active = (new \DateTimeImmutable())->format('Y-m-d H:i:s');
        $this->user->save();
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

        $login = new TokenLogin(\Flight::db());
        $login->id_type    = self::ID_TYPE_ACCESS_TOKEN;
        $login->identifier = $identifier;
        $login->success    = $success;
        $login->user_id    = $userId;
        $login->ip_address = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
        $login->user_agent = $_SERVER['HTTP_USER_AGENT'] ?? null;
        $login->date       = (new \DateTimeImmutable())->format('Y-m-d H:i:s');
        $login->insert();
    }
}
