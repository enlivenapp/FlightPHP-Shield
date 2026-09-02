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
use Enlivenapp\FlightShield\Support\RobotDetector;
use flight\Engine;

class Email2FA implements ActionInterface
{
    private string $type = Session::ID_TYPE_EMAIL_2FA;

    public function show(Engine $app): string
    {
        if (RobotDetector::isBot($_SERVER['HTTP_USER_AGENT'] ?? '', $this->getBotDetectionConfig($app))) {
            $app->halt(404);
            return '';
        }

        /** @var Session $authenticator */
        $authenticator = $app->auth()->getAuthenticator();
        $user = $authenticator->getPendingUser();

        if ($user === null) {
            throw new \RuntimeException('Cannot get the pending login user.');
        }

        // Only send a new code if no unexpired one exists and we haven't already sent one this session
        $identityModel = new UserIdentity(\Flight::db());
        $existing = $identityModel->getIdentityByType($user, $this->type);

        if ($existing === null || $existing->isExpired() || ! $app->session()->has('2fa_code_sent')) {
            $code = $this->createIdentity($user, $app);
            $this->sendCodeEmail($user, $code, $app);
            $app->session()->set('2fa_code_sent', true);
        }

        return $app->view()->fetch('2fa_verify');
    }

    public function handle(Engine $app): string
    {
        /** @var Session $authenticator */
        $authenticator = $app->auth()->getAuthenticator();
        $user = $authenticator->getPendingUser();

        if ($user === null) {
            throw new \RuntimeException('Cannot get the pending login user.');
        }

        // Server-side cooldown: reject resend if last code was created < 300 seconds ago
        $identityModel = new UserIdentity(\Flight::db());
        $existing = $identityModel->getIdentityByType($user, $this->type);

        if ($existing !== null && $existing->created_at !== null) {
            $createdAt = new \DateTimeImmutable($existing->created_at);
            $elapsed = time() - $createdAt->getTimestamp();
            if ($elapsed < 300) {
                $remaining = 300 - $elapsed;
                $m = intdiv($remaining, 60);
                $s = $remaining % 60;
                return $app->view()->fetch('2fa_verify', [
                    'error' => "Please wait {$m}:" . str_pad((string) $s, 2, '0', STR_PAD_LEFT) . ' before requesting a new code.',
                ]);
            }
        }

        $code = $this->createIdentity($user, $app);
        $this->sendCodeEmail($user, $code, $app);

        return $app->view()->fetch('2fa_verify', ['message' => 'A new code has been sent.']);
    }

    public function verify(Engine $app): string
    {
        if (RobotDetector::isBot($_SERVER['HTTP_USER_AGENT'] ?? '', $this->getBotDetectionConfig($app))) {
            $app->halt(404);
            return '';
        }

        /** @var Session $authenticator */
        $authenticator = $app->auth()->getAuthenticator();
        $postedToken = $app->request()->data->token ?? '';

        $user = $authenticator->getPendingUser();
        if ($user === null) {
            throw new \RuntimeException('Cannot get the pending login user.');
        }

        /** @var UserIdentityRepository $identityRepo */
        $identityModel = new UserIdentity(\Flight::db());
        $identity = $identityModel->getIdentityByType($user, $this->type);

        if ($identity === null) {
            return $app->view()->fetch('2fa_verify', ['error' => 'No 2FA code found. Please log in again.']);
        }

        if ($identity->isExpired()) {
            return $app->view()->fetch('2fa_verify', ['error' => 'The 2FA code has expired. Please log in again.']);
        }

        if (! $authenticator->checkAction($identity, $postedToken)) {
            return $app->view()->fetch('2fa_verify', ['error' => 'Invalid 2FA code.']);
        }

        $redirect = $app->get('enlivenapp.flight-shield')['redirects']['after_login'] ?? '/';
        $app->redirect($redirect);
        return '';
    }

    public function getType(): string
    {
        return $this->type;
    }

    protected function getBotDetectionConfig(Engine $app): array
    {
        return $app->get('enlivenapp.flight-shield')['bot_detection'] ?? [];
    }

    protected function sendCodeEmail(User $user, string $code, Engine $app): void
    {
        $config = $app->get('enlivenapp.flight-shield') ?? [];
        $sender = $config['email_sender'] ?? null;

        if ($sender === null || !is_callable($sender)) {
            throw new \RuntimeException('Shield email_sender callback is not configured.');
        }

        /** @var UserIdentityRepository $identityRepo */
        $identityModel = new UserIdentity(\Flight::db());
        $identity = $identityModel->getEmailIdentity($user);
        $to = $identity ? $identity->secret : '';

        $body = $app->view()->fetch('Email/email_2fa_email', [
            'code'      => $code,
            'ipAddress' => $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0',
            'userAgent' => $_SERVER['HTTP_USER_AGENT'] ?? '',
            'date'      => date('Y-m-d H:i:s'),
        ]);

        $sender($to, 'Your Verification Code', $body);
    }

    public function createIdentity(User $user, Engine $app): string
    {
        /** @var UserIdentityRepository $identityRepo */
        $identityModel = new UserIdentity(\Flight::db());

        $identityModel->deleteIdentitiesByType($user, $this->type);

        $generator = static fn(): string => (string) random_int(100000, 999999);

        return $identityModel->createCodeIdentity(
            $user,
            ['type' => $this->type, 'name' => 'login', 'extra' => 'Two-factor authentication required.'],
            $generator
        );
    }
}
