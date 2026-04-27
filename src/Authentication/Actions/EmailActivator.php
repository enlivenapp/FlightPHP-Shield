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
use flight\Engine;

class EmailActivator implements ActionInterface
{
    private string $type = Session::ID_TYPE_EMAIL_ACTIVATE;

    public function show(Engine $app): string
    {
        /** @var Session $authenticator */
        $authenticator = $app->auth()->getAuthenticator();
        $user = $authenticator->getPendingUser();

        if ($user === null) {
            throw new \RuntimeException('Cannot get the pending login user.');
        }

        $code = $this->createIdentity($user, $app);
        $this->sendActivationEmail($user, $code, $app);

        return $app->view()->fetch('activate', ['user' => $user]);
    }

    public function handle(Engine $app): string
    {
        // Not used for email activation — the user clicks a link in the email
        throw new \RuntimeException('Not supported for email activation.');
    }

    public function verify(Engine $app): string
    {
        /** @var Session $authenticator */
        $authenticator = $app->auth()->getAuthenticator();
        $postedToken = $app->request()->query->token ?? $app->request()->data->token ?? '';

        $user = $authenticator->getPendingUser();
        if ($user === null) {
            throw new \RuntimeException('Cannot get the pending login user.');
        }

        /** @var UserIdentityRepository $identityRepo */
        $identityModel = new UserIdentity(\Flight::db());
        $identity = $identityModel->getIdentityByType($user, $this->type);

        if ($identity === null) {
            return $app->view()->fetch('activate', ['error' => 'No activation token found. Please register again.']);
        }

        if ($identity->isExpired()) {
            return $app->view()->fetch('activate', ['error' => 'The activation token has expired. Please register again.']);
        }

        if (! $authenticator->checkAction($identity, $postedToken)) {
            return $app->view()->fetch('activate', ['error' => 'Invalid activation token.']);
        }

        // Activate the user
        $user->activate();
        $user->save();

        $redirect = $app->get('enlivenapp.flight-shield')['redirects']['after_register'] ?? '/';
        $app->redirect($redirect);
        return '';
    }

    public function getType(): string
    {
        return $this->type;
    }

    protected function sendActivationEmail(User $user, string $code, Engine $app): void
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

    public function createIdentity(User $user, Engine $app): string
    {
        /** @var UserIdentityRepository $identityRepo */
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
