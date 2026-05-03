<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Middlewares;

use flight\Engine;

/**
 * Tries each authenticator in the configured chain until one succeeds.
 */
class ChainAuthMiddleware
{
    protected Engine $app;

    public function __construct(Engine $app)
    {
        $this->app = $app;
    }

    public function before(): void
    {
        $config = $this->app->get('enlivenapp.flight-shield') ?? [];
        $chain = $config['authentication_chain'] ?? ['session', 'tokens', 'hmac'];

        foreach ($chain as $alias) {
            $this->app->auth()->setAuthenticator($alias);

            if ($this->app->auth()->loggedIn()) {
                $this->app->auth()->recordActiveDate();
                return;
            }
        }

        $accept = $_SERVER['HTTP_ACCEPT'] ?? '';
        if (str_contains($accept, 'application/json')) {
            $this->app->jsonHalt(['message' => 'Unauthorized'], 401);
        } else {
            $loginUrl = $config['redirects']['login'] ?? '/auth/login';
            $this->app->redirect($loginUrl);
            $this->app->halt(303);
        }
    }
}
