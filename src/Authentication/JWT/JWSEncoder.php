<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Authentication\JWT;

use Enlivenapp\FlightShield\Authentication\JWT\Adapters\FirebaseAdapter;

class JWSEncoder
{
    protected JWSAdapterInterface $adapter;
    /** @var array<string, mixed> */
    protected array $config;

    /**
     * @param array<string, mixed> $config
     */
    public function __construct(array $config, ?JWSAdapterInterface $adapter = null)
    {
        $this->config = $config;
        $this->adapter = $adapter ?? new FirebaseAdapter($config['keys'] ?? []);
    }

    /**
     * @param array<string, mixed>       $claims  Payload items.
     * @param int|null                   $ttl     Time to live in seconds.
     * @param string                     $keyset  Key group name.
     * @param array<string, string>|null $headers Header elements.
     */
    public function encode(array $claims, ?int $ttl = null, string $keyset = 'default', ?array $headers = null): string
    {
        $defaults = $this->config['default_claims'] ?? [];
        if (! is_array($defaults)) {
            $defaults = [];
        }

        /** @var array<string, mixed> $payload */
        $payload = array_merge($defaults, $claims);

        if (! isset($claims['iat'])) {
            $payload['iat'] = time();
        }

        if (isset($claims['exp'])) {
            // Explicit exp claim takes precedence
            $payload['exp'] = $claims['exp'];
        } else {
            $defaultTtl = (int) ($this->config['time_to_live'] ?? 3600);
            $payload['exp'] = (int) $payload['iat'] + ($ttl ?? $defaultTtl);
        }

        return $this->adapter->encode($payload, $keyset, $headers);
    }
}
