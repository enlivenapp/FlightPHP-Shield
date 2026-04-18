<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Middlewares;

use Enlivenapp\FlightShield\Authentication\Authenticators\JWT;
use flight\Engine;

class JWTAuthMiddleware
{
    protected Engine $app;

    public function __construct(Engine $app)
    {
        $this->app = $app;
    }

    public function before(): void
    {
        $this->app->auth()->setAuthenticator('jwt');

        /** @var JWT $authenticator */
        $authenticator = $this->app->auth()->getAuthenticator();

        $jwtConfig = $this->app->get('enlivenapp.flight-shield')['jwt'] ?? [];
        $header = $jwtConfig['header'] ?? 'Authorization';
        $headerValue = $_SERVER['HTTP_' . strtoupper(str_replace('-', '_', $header))] ?? '';

        if (str_starts_with($headerValue, 'Bearer')) {
            $headerValue = trim(substr($headerValue, 6));
        }

        $result = $authenticator->attempt(['token' => $headerValue]);

        if (! $result->isOK()) {
            $this->app->json(['error' => $result->reason() ?? 'Unauthorized'], 401);
            return;
        }

        $user = $authenticator->getUser();
        if ($user !== null && ! $user->isActivated()) {
            $authenticator->logout();
            $this->app->json(['error' => 'Account not activated.'], 403);
            return;
        }

        $authenticator->recordActiveDate();
    }
}
