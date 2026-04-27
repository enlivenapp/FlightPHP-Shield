<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Authentication\Authenticators;

use Enlivenapp\FlightShield\Authentication\AuthenticatorInterface;
use Enlivenapp\FlightShield\Authentication\HMAC\HmacEncrypter;
use Enlivenapp\FlightShield\Models\AccessToken;
use Enlivenapp\FlightShield\Models\TokenLogin;
use Enlivenapp\FlightShield\Models\User;
use Enlivenapp\FlightShield\Models\UserIdentity;
use Enlivenapp\FlightShield\Exceptions\AuthenticationException;
use Enlivenapp\FlightShield\Result;
use flight\Engine;

class HmacSha256 implements AuthenticatorInterface
{
    public const ID_TYPE_HMAC_TOKEN = 'hmac_sha256';

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
        $identityModel = new UserIdentity(\Flight::db());
        $identity = $identityModel->getHmacTokenByKey($userKey);

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

        // Verify the HMAC signature against method, path, timestamp, and request body
        $method = strtoupper($credentials['method'] ?? 'GET');
        $path   = $credentials['path'] ?? '/';
        $body   = $credentials['body'] ?? '';
        $secretKey = $identity->secret2;

        // Decrypt if HMAC encryption is configured
        if ($this->hasHmacEncryption()) {
            $encrypter = $this->getHmacEncrypter();
            if ($encrypter->isEncrypted($secretKey)) {
                $secretKey = $encrypter->decrypt($secretKey);
            }
        }

        $hash = hash_hmac('sha256', $method . "\n" . $path . "\n" . $timestamp . "\n" . $body, $secretKey);

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
        $identityModel->touchIdentity($identity);

        /** @var UserRepository $userRepo */
        $userModel = new User(\Flight::db());
        $user = $userModel->findById($identity->user_id);

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

        if ($this->tokenChecked) {
            return false;
        }

        $this->tokenChecked = true;

        $header = $this->config['hmac_header'] ?? 'Authorization';
        $headerValue = $_SERVER['HTTP_' . strtoupper(str_replace('-', '_', $header))] ?? '';
        $body = file_get_contents('php://input') ?: '';
        $timestamp = $_SERVER['HTTP_X_REQUEST_TIMESTAMP'] ?? '';

        $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
        $path   = $_SERVER['REQUEST_URI'] ?? '/';

        $result = $this->check(['token' => $headerValue, 'body' => $body, 'timestamp' => $timestamp, 'method' => $method, 'path' => $path]);

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
        $login->id_type    = self::ID_TYPE_HMAC_TOKEN;
        $login->identifier = $identifier;
        $login->success    = $success;
        $login->user_id    = $userId;
        $login->ip_address = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
        $login->user_agent = $_SERVER['HTTP_USER_AGENT'] ?? null;
        $login->date       = (new \DateTimeImmutable())->format('Y-m-d H:i:s');
        $login->insert();
    }

    protected function hasHmacEncryption(): bool
    {
        $hmac = $this->config['hmac'] ?? [];

        return !empty($hmac['encryption_current_key']) && !empty($hmac['encryption_keys'][$hmac['encryption_current_key'] ?? '']);
    }

    protected function getHmacEncrypter(): HmacEncrypter
    {
        return new HmacEncrypter($this->config);
    }
}
