<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Middlewares;

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

        if (! $auth->loggedIn()) {
            $config = $this->app->get('enlivenapp.flight-shield') ?? [];
            $loginUrl = $config['redirects']['login'] ?? '/auth/login';
            $this->app->redirect($loginUrl);
            return;
        }

        $auth->recordActiveDate();
    }
}
