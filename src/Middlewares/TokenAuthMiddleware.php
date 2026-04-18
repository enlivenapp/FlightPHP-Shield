<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Middlewares;

use flight\Engine;

class TokenAuthMiddleware
{
    protected Engine $app;

    public function __construct(Engine $app)
    {
        $this->app = $app;
    }

    public function before(): void
    {
        $auth = $this->app->auth();
        $auth->setAuthenticator('tokens');

        $config = $this->app->get('enlivenapp.flight-shield') ?? [];
        $header = $config['token_header'] ?? 'Authorization';
        $headerValue = $_SERVER['HTTP_' . strtoupper(str_replace('-', '_', $header))] ?? '';

        $result = $auth->getAuthenticator()->attempt(['token' => $headerValue]);

        if (! $result->isOK()) {
            $this->app->json(['message' => $result->reason() ?? 'Unauthorized'], 401);
            return;
        }

        $user = $auth->getAuthenticator()->getUser();
        if ($user !== null && ! $user->isActivated()) {
            $auth->getAuthenticator()->logout();
            $this->app->json(['message' => 'Account not activated.'], 403);
            return;
        }

        $auth->recordActiveDate();
    }
}
