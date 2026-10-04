<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Authentication\Actions;

use Enlivenapp\FlightShield\Authentication\Authenticators\Session;
use Enlivenapp\FlightShield\Models\User;
use Enlivenapp\FlightShield\Models\UserIdentity;
use Enlivenapp\FlightShield\Result;
use Enlivenapp\FlightShield\Support\RobotDetector;
use flight\Engine;

/**
 * Email activation.
 *
 * Session-free on both ends. Registration calls begin() with the new User to
 * mint the token and send the mail; verify() resolves the account from the
 * token alone, activates it, and only then starts a session for the login
 * hand-off.
 */
class EmailActivator
{
    private string $type = Session::ID_TYPE_EMAIL_ACTIVATE;

    /**
     * Mint an activation token for a freshly created user and email it.
     *
     * Called by registration, which already holds the new User. No session
     * is read or written here.
     */
    public function begin(User $user, Engine $app): void
    {
        $code = $this->createIdentity($user);
        $this->sendActivationEmail($user, $code, $app);
    }

    /**
     * Resolve an activation token to a User and burn it.
     *
     * Token-only: no session is involved. Returns a failed Result with a
     * user-facing reason when the token is unknown, expired, or the account
     * is gone; on success the User is in extraInfo().
     */
    public function consume(string $token): Result
    {
        $identityModel = new UserIdentity(\Flight::db());
        $identity = $identityModel->getIdentityBySecret($this->type, hash('sha256', $token));

        if ($identity === null) {
            return (new Result())
                ->setSuccess(false)
                ->setReason('Invalid or already used activation token.');
        }

        if ($identity->isExpired()) {
            $identity->delete();
            return (new Result())
                ->setSuccess(false)
                ->setReason('The activation token has expired.');
        }

        $user = (new User(\Flight::db()))->findById($identity->user_id);

        // Single use: burn the token whichever way this goes.
        $identity->delete();

        if ($user === null) {
            return (new Result())
                ->setSuccess(false)
                ->setReason('Invalid activation token.');
        }

        return (new Result())
            ->setSuccess(true)
            ->setExtraInfo($user);
    }

    /**
     * Verify an activation token from an email link.
     *
     * The token alone identifies the account, so the link works from any
     * browser or device. Once the account is activated the token is spent,
     * and a session takes over for the login hand-off.
     */
    public function verify(Engine $app): string
    {
        if (RobotDetector::isBot($_SERVER['HTTP_USER_AGENT'] ?? '', $this->getBotDetectionConfig($app))) {
            $app->halt(404);
            return '';
        }

        $config = $app->get('enlivenapp.flight-shield') ?? [];
        $token  = (string) ($app->request()->query->token ?? $app->request()->data->token ?? '');

        $result = $this->consume($token);

        if (! $result->isOK()) {
            return $app->view()->fetch('activate', ['error' => $result->reason()]);
        }

        /** @var User $user */
        $user = $result->extraInfo();

        if ($user->isBanned()) {
            $app->redirect($config['redirects']['login'] ?? '/auth/login');
            return '';
        }

        if ($user->isNotActivated()) {
            try {
                $user->activate();
                $user->updated_at = (new \DateTimeImmutable())->format('Y-m-d H:i:s');
                // Explicit dirty(): typed property assignment bypasses __set().
                $user->dirty(['active' => true, 'updated_at' => $user->updated_at]);
                $user->save();
            } catch (\Exception $e) {
                return $app->view()->fetch('activate', [
                    'error' => 'The account could not be activated. Please try again.',
                ]);
            }
        }

        // The token is spent. Sessions take over from here for the login step.
        /** @var Session $authenticator */
        $authenticator = $app->auth()->setAuthenticator('session')->getAuthenticator();

        if ($authenticator->startUpAction('login', $user)) {
            $app->redirect('/auth/2fa');
            return '';
        }

        $authenticator->loginById($user->id);
        $app->redirect($config['redirects']['after_register'] ?? '/');
        return '';
    }

    public function getType(): string
    {
        return $this->type;
    }

    /**
     * @return array<string, mixed>
     */
    protected function getBotDetectionConfig(Engine $app): array
    {
        return $app->get('enlivenapp.flight-shield')['bot_detection'] ?? [];
    }

    protected function sendActivationEmail(User $user, string $code, Engine $app): void
    {
        $config = $app->get('enlivenapp.flight-shield') ?? [];
        $sender = $config['email_sender'] ?? null;

        if ($sender === null || !is_callable($sender)) {
            throw new \RuntimeException('Shield email_sender callback is not configured.');
        }

        $identityModel = new UserIdentity(\Flight::db());
        $identity = $identityModel->getEmailIdentity($user);
        $to = $identity ? $identity->secret : '';

        $baseUrl = rtrim($app->get('flight.base_url') ?? '', '/');
        $activationUrl = $baseUrl . '/auth/activate/verify?token=' . urlencode($code);

        $body = $app->view()->fetch('Email/email_activate_email', [
            'activationUrl' => $activationUrl,
            'ipAddress'     => $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0',
            'userAgent'     => $_SERVER['HTTP_USER_AGENT'] ?? '',
            'date'          => date('Y-m-d H:i:s'),
        ]);

        $sender($to, 'Activate Your Account', $body);
    }

    protected function createIdentity(User $user): string
    {
        $identityModel = new UserIdentity(\Flight::db());

        $identityModel->deleteIdentitiesByType($user, $this->type);

        $generator = static fn(): string => bin2hex(random_bytes(20));

        return $identityModel->createCodeIdentity(
            $user,
            [
                'type'    => $this->type,
                'name'    => 'register',
                'extra'   => 'Email verification required.',
                'expires' => new \DateTimeImmutable('+24 hours'),
            ],
            $generator
        );
    }
}
