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
    /** @var array<string, AuthenticatorInterface> */
    protected array $instances = [];
    protected Engine $app;
    /** @var array<string, mixed> */
    protected array $config;

    /**
     * @param array<string, mixed> $config
     */
    public function __construct(Engine $app, array $config)
    {
        $this->app = $app;
        $this->config = $config;
    }

    public function factory(?string $alias = null): AuthenticatorInterface
    {
        if ($alias === null) {
            $alias = (string) ($this->config['default_authenticator'] ?? 'session');
        }

        if (isset($this->instances[$alias])) {
            return $this->instances[$alias];
        }

        $authenticators = $this->config['authenticators'] ?? [];
        if (! is_array($authenticators)) {
            $authenticators = [];
        }

        if (! isset($authenticators[$alias])) {
            throw AuthenticationException::forUnknownAuthenticator($alias);
        }

        $className = $authenticators[$alias];

        if (! is_string($className) || ! class_exists($className)) {
            throw AuthenticationException::forUnknownAuthenticator($alias);
        }

        $instance = new $className($this->app, $this->config);

        if (! $instance instanceof AuthenticatorInterface) {
            throw AuthenticationException::forUnknownAuthenticator($alias);
        }

        $this->instances[$alias] = $instance;

        return $instance;
    }
}
