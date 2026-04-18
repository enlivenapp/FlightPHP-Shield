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
    protected array $config;

    public function __construct(array $config, ?JWSAdapterInterface $adapter = null)
    {
        $this->config = $config;
        $this->adapter = $adapter ?? new FirebaseAdapter($config['keys'] ?? []);
    }

    /**
     * @param array                      $claims  Payload items.
     * @param int|null                   $ttl     Time to live in seconds.
     * @param string                     $keyset  Key group name.
     * @param array<string, string>|null $headers Header elements.
     */
    public function encode(array $claims, ?int $ttl = null, string $keyset = 'default', ?array $headers = null): string
    {
        $payload = array_merge(
            $this->config['default_claims'] ?? [],
            $claims,
        );

        if (! isset($claims['iat'])) {
            $payload['iat'] = time();
        }

        if (! isset($claims['exp'])) {
            $defaultTtl = $this->config['time_to_live'] ?? 3600;
            $payload['exp'] = $payload['iat'] + ($ttl ?? $defaultTtl);
        } elseif ($ttl !== null) {
            $payload['exp'] = $payload['iat'] + $ttl;
        }

        return $this->adapter->encode($payload, $keyset, $headers);
    }
}
