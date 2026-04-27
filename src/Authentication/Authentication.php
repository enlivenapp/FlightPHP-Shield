<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Authentication;

use Enlivenapp\FlightShield\Exceptions\AuthenticationException;
use flight\Engine;

class Authentication
{
    protected array $instances = [];
    protected Engine $app;
    protected array $config;

    public function __construct(Engine $app, array $config)
    {
        $this->app = $app;
        $this->config = $config;
    }

    public function factory(?string $alias = null): AuthenticatorInterface
    {
        $alias ??= $this->config['default_authenticator'] ?? 'session';

        if (isset($this->instances[$alias])) {
            return $this->instances[$alias];
        }

        $authenticators = $this->config['authenticators'] ?? [];

        if (! isset($authenticators[$alias])) {
            throw AuthenticationException::forUnknownAuthenticator($alias);
        }

        $className = $authenticators[$alias];
        $this->instances[$alias] = new $className($this->app, $this->config);

        return $this->instances[$alias];
    }
}
