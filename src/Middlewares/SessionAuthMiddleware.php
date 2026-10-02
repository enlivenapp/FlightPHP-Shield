<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Middlewares;

use Enlivenapp\FlightShield\Authentication\Actions\Email2FA;
use flight\Engine;

class SessionAuthMiddleware
{
    protected Engine $app;

    public function __construct(Engine $app)
    {
        $this->app = $app;
    }

    public function before(): void
    {
        $auth = $this->app->auth();
        $config = $this->app->get('enlivenapp.flight-shield') ?? [];
        $loginUrl = $config['redirects']['login'] ?? '/auth/login';

        if (! $auth->loggedIn()) {
            // Users mid-action (2FA / activation) are directed to their
            // action page instead of being bounced back to login.
            $authenticator = $auth->getAuthenticator();
            if ($authenticator->isPending()) {
                $action = $authenticator->getAction();
                if ($action instanceof Email2FA) {
                    $this->app->redirect('/auth/2fa');
                } else {
                    $this->app->redirect($loginUrl);
                }
                $this->app->halt(303);
                return;
            }

            $this->app->redirect($loginUrl);
            $this->app->halt(303);
            return;
        }

        $user = $auth->user();

        // Banned users are logged out and sent to login
        if ($user !== null && $user->isBanned()) {
            $auth->logout();
            $this->app->redirect($loginUrl);
            $this->app->halt(303);
            return;
        }

        // Inactive users cannot hold a session
        if ($user !== null && ! $user->isActivated()) {
            $auth->logout();
            $this->app->redirect($loginUrl);
            $this->app->halt(303);
            return;
        }

        $auth->recordActiveDate();
    }
}
