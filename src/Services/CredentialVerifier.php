<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Services;

use Enlivenapp\FlightShield\Authentication\Actions\EmailActivator;
use Enlivenapp\FlightShield\Models\Login;
use Enlivenapp\FlightShield\Models\User;
use Enlivenapp\FlightShield\Models\UserIdentity;
use Enlivenapp\FlightShield\Passwords\Passwords;
use flight\Engine;

/**
 * The credential steps shared by the login flow and the plugin-facing
 * verifyCredentials() call.
 *
 * Both the session authenticator and the Auth facade depend on this, which
 * neither can do for the other.
 */
class CredentialVerifier
{
    /**
     * A real bcrypt hash (cost 12) of a string nobody can guess. Burned when
     * the identifier does not exist so a miss costs the same time as a real
     * password check. Never a valid password for any account.
     */
    public const TIMING_EQUALISER_HASH = '$2y$12$2AkJ3vs6onhio1lp0HriZuBeTb6ixMDpZk7F5L9/NwVLq1PoDmFN2';

    protected Engine $app;
    /** @var array<string, mixed> */
    protected array $config;
    protected Passwords $passwords;

    /**
     * @param array<string, mixed> $config
     */
    public function __construct(Engine $app, array $config, ?Passwords $passwords = null)
    {
        $this->app = $app;
        $this->config = $config;
        $this->passwords = $passwords ?? new Passwords($config['passwords'] ?? []);
    }

    /**
     * Whether the password matches the user's email/password identity.
     */
    public function passwordMatches(User $user, string $password): bool
    {
        $identity = (new UserIdentity($this->app->db()))->getEmailIdentity($user);

        if ($identity === null || $identity->secret2 === null) {
            return false;
        }

        return $this->passwords->verify($password, $identity->secret2);
    }

    /**
     * Burn the same time as a real password check.
     *
     * Call this when no account matched the identifier, so an unknown
     * identifier cannot be told apart from a wrong password by how long the
     * answer took. The result is discarded.
     */
    public function burnTiming(string $password): void
    {
        $this->passwords->verify($password, self::TIMING_EQUALISER_HASH);
    }

    /**
     * Write one attempt to auth_logins. Honours record_login_attempt.
     */
    public function recordAttempt(string $identifier, string $idType, bool $success, ?int $userId = null): void
    {
        if (! $this->shouldRecord($success)) {
            return;
        }

        $this->writeAttempt($identifier, $idType, $success, $userId);
    }

    /**
     * Write one row whatever record_login_attempt says.
     *
     * This backs a rate-limit counter, not a login log, so turning that
     * setting off must not switch the counter off with it.
     */
    public function recordThrottleHit(string $identifier, string $idType, ?int $userId = null): void
    {
        $this->writeAttempt($identifier, $idType, true, $userId);
    }

    protected function shouldRecord(bool $success): bool
    {
        $level = $this->config['record_login_attempt'] ?? 'none';

        return $level !== 'none' && ! ($level === 'failure' && $success);
    }

    protected function writeAttempt(string $identifier, string $idType, bool $success, ?int $userId): void
    {
        $login = new Login($this->app->db());
        $login->id_type    = $idType;
        $login->identifier = $identifier;
        $login->success    = $success;
        $login->user_id    = $userId;
        $login->ip_address = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
        $login->user_agent = $_SERVER['HTTP_USER_AGENT'] ?? null;
        $login->date       = (new \DateTimeImmutable())->format('Y-m-d H:i:s');
        $login->insert();
    }

    /**
     * Send an activation link, turning a mail failure into false rather than
     * a server error.
     */
    public function sendActivation(User $user): bool
    {
        try {
            (new EmailActivator())->begin($user, $this->app);
            return true;
        } catch (\Throwable $e) {
            return false;
        }
    }
}
