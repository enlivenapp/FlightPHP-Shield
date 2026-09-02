<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Authentication\Authenticators;

use Enlivenapp\FlightShield\Authentication\AuthenticatorInterface;
use Enlivenapp\FlightShield\Authentication\JWTManager;
use Enlivenapp\FlightShield\Models\TokenLogin;
use Enlivenapp\FlightShield\Models\User;
use Enlivenapp\FlightShield\Exceptions\AuthenticationException;
use Enlivenapp\FlightShield\Result;
use flight\Engine;
use stdClass;

/**
 * Stateless JWT Authenticator.
 * Requires firebase/php-jwt (suggested dependency).
 */
class JWT implements AuthenticatorInterface
{
    public const ID_TYPE_JWT = 'jwt';

    protected Engine $app;
    protected array $config;
    protected ?User $user = null;
    protected bool $tokenChecked = false;
    protected ?JWTManager $jwtManager = null;
    protected ?stdClass $payload = null;
    protected string $keyset = 'default';

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
            $this->recordTokenLogin(
                'sha256:' . hash('sha256', $credentials['token'] ?? ''),
                false,
                $user->id
            );
            $this->user = null;

            return (new Result())
                ->setSuccess(false)
                ->setReason($user->getBanMessage() ?? 'User is banned.');
        }

        $this->login($user);

        $this->recordTokenLogin(
            'sha256:' . hash('sha256', $credentials['token']),
            true,
            $user->id
        );

        return $result;
    }

    public function check(array $credentials): Result
    {
        if (! isset($credentials['token']) || $credentials['token'] === '') {
            return (new Result())
                ->setSuccess(false)
                ->setReason('No JWT provided.');
        }

        try {
            $this->payload = $this->getJWTManager()->parse($credentials['token'], $this->keyset);
        } catch (\Throwable $e) {
            return (new Result())
                ->setSuccess(false)
                ->setReason('Invalid or expired token.');
        }

        $userId = $this->payload->sub ?? null;

        if ($userId === null) {
            return (new Result())
                ->setSuccess(false)
                ->setReason('Invalid JWT: missing subject.');
        }

        /** @var UserRepository $userRepo */
        $userModel = new User(\Flight::db());
        $user = $userModel->findById($userId);

        if ($user === null) {
            return (new Result())
                ->setSuccess(false)
                ->setReason('Invalid user.');
        }

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

        $token = $this->getTokenFromHeader();
        $result = $this->check(['token' => $token]);

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
        $this->payload = null;
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

    public function getPayload(): ?stdClass
    {
        return $this->payload;
    }

    public function setKeyset(string $keyset): void
    {
        $this->keyset = $keyset;
    }

    /**
     * Generate a JWT for the given user.
     */
    public function generateToken(User $user, array $claims = [], ?int $ttl = null): string
    {
        return $this->getJWTManager()->generateToken($user, $claims, $ttl, $this->keyset);
    }

    protected function getJWTManager(): JWTManager
    {
        if ($this->jwtManager === null) {
            $jwtConfig = $this->config['jwt'] ?? [];
            $this->jwtManager = new JWTManager($jwtConfig);
        }

        return $this->jwtManager;
    }

    protected function getTokenFromHeader(): string
    {
        $jwtConfig = $this->config['jwt'] ?? [];
        $header = $jwtConfig['header'] ?? null;

        // The header is config-driven: when unset or empty there is no
        // token source (no implicit Authorization fallback).
        if ($header === null || $header === '') {
            return '';
        }

        $headerValue = $_SERVER['HTTP_' . strtoupper(str_replace('-', '_', $header))] ?? '';

        if (str_starts_with($headerValue, 'Bearer')) {
            return trim(substr($headerValue, 6));
        }

        return $headerValue;
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
        $login->id_type    = self::ID_TYPE_JWT;
        $login->identifier = $identifier;
        $login->success    = $success;
        $login->user_id    = $userId;
        $login->ip_address = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
        $login->user_agent = $_SERVER['HTTP_USER_AGENT'] ?? null;
        $login->date       = (new \DateTimeImmutable())->format('Y-m-d H:i:s');
        $login->insert();
    }
}
