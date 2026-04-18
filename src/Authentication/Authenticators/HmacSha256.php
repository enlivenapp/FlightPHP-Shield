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

class HmacSha256 implements AuthenticatorInterface
{
    public const ID_TYPE_HMAC_TOKEN = 'hmac_sha256';

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
            $this->recordTokenLogin($user->currentHmacToken()->name ?? '', false, $user->id);
            $this->user = null;

            return (new Result())
                ->setSuccess(false)
                ->setReason('Account is not active.');
        }

        $this->login($user);
        $this->recordTokenLogin($user->currentHmacToken()->name ?? '', true, $user->id);

        return $result;
    }

    public function check(array $credentials): Result
    {
        if (! isset($credentials['token']) || $credentials['token'] === '') {
            return (new Result())
                ->setSuccess(false)
                ->setReason('No HMAC token provided.');
        }

        $token = $credentials['token'];
        if (str_starts_with($token, 'HMAC-SHA256')) {
            $token = trim(substr($token, 11));
        }

        $parts = preg_split('/:/', $token, -1, PREG_SPLIT_NO_EMPTY);
        if (count($parts) !== 2) {
            return (new Result())
                ->setSuccess(false)
                ->setReason('Invalid HMAC token format.');
        }

        [$userKey, $signature] = $parts;

        /** @var UserIdentityRepository $identityRepo */
        $identityRepo = $this->app->orm()->getRepository(UserIdentity::class);
        $identity = $identityRepo->getHmacTokenByKey($userKey);

        if ($identity === null) {
            return (new Result())
                ->setSuccess(false)
                ->setReason('Invalid HMAC token.');
        }

        // Validate the request timestamp (replay protection)
        if (! isset($credentials['timestamp']) || $credentials['timestamp'] === '') {
            return (new Result())
                ->setSuccess(false)
                ->setReason('Missing X-Request-Timestamp header.');
        }

        $timestamp = (int) $credentials['timestamp'];
        if (abs(time() - $timestamp) > 300) {
            return (new Result())
                ->setSuccess(false)
                ->setReason('Request timestamp is outside the acceptable window.');
        }

        // Verify the HMAC signature against the timestamp and request body
        $body = $credentials['body'] ?? '';
        $secretKey = $identity->secret2;
        $hash = hash_hmac('sha256', $timestamp . "\n" . $body, $secretKey);

        if (! hash_equals($hash, $signature)) {
            return (new Result())
                ->setSuccess(false)
                ->setReason('HMAC signature verification failed.');
        }

        // Check unused lifetime
        $unusedLifetime = $this->config['unused_token_lifetime'] ?? null;
        if ($unusedLifetime && $identity->last_used_at) {
            $cutoff = new \DateTimeImmutable("-{$unusedLifetime} seconds");
            if ($identity->last_used_at < $cutoff) {
                return (new Result())
                    ->setSuccess(false)
                    ->setReason('HMAC token expired from disuse.');
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
        $user->setHmacToken($token);

        return (new Result())
            ->setSuccess(true)
            ->setExtraInfo($user);
    }

    public function loggedIn(): bool
    {
        if ($this->user !== null) {
            return true;
        }

        $header = $this->config['hmac_header'] ?? 'Authorization';
        $headerValue = $_SERVER['HTTP_' . strtoupper(str_replace('-', '_', $header))] ?? '';
        $body = file_get_contents('php://input') ?: '';
        $timestamp = $_SERVER['HTTP_X_REQUEST_TIMESTAMP'] ?? '';

        return $this->attempt(['token' => $headerValue, 'body' => $body, 'timestamp' => $timestamp])->isOK();
    }

    public function login(User $user): void
    {
        $this->user = $user;
    }

    public function loginById(int|string $userId): void
    {
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
        $login->id_type    = self::ID_TYPE_HMAC_TOKEN;
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
