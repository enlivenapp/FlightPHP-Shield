<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Middlewares;

use flight\Engine;

class ForcePasswordResetMiddleware
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
            return;
        }

        $user = $auth->user();

        if ($user !== null && $user->requiresPasswordReset()) {
            $config = $this->app->get('enlivenapp.flight-shield') ?? [];
            $resetUrl = $config['redirects']['force_reset'] ?? '/auth/reset-password';
            $this->app->redirect($resetUrl);
            return;
        }
    }
}
