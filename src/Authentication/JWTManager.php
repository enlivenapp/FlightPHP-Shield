<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Authentication;

use Enlivenapp\FlightShield\Authentication\JWT\JWSDecoder;
use Enlivenapp\FlightShield\Authentication\JWT\JWSEncoder;
use Enlivenapp\FlightShield\Models\User;
use stdClass;

class JWTManager
{
    protected JWSEncoder $encoder;
    protected JWSDecoder $decoder;

    /**
     * @param array<string, mixed> $config
     */
    public function __construct(array $config)
    {
        $this->encoder = new JWSEncoder($config);

        $keys = $config['keys'] ?? [];
        if (! is_array($keys)) {
            $keys = [];
        }
        /** @var array<string, mixed> $keys */
        $this->decoder = new JWSDecoder($keys);
    }

    /**
     * Generate a JWT for the given user.
     */
    /**
     * @param array<string, mixed> $claims
     * @param array<string, string>|null $headers
     */
    public function generateToken(
        User $user,
        array $claims = [],
        ?int $ttl = null,
        string $keyset = 'default',
        ?array $headers = null,
    ): string {
        $payload = array_merge($claims, [
            'sub' => (string) $user->id,
        ]);

        return $this->encoder->encode($payload, $ttl, $keyset, $headers);
    }

    /**
     * Issue a JWT with arbitrary claims.
     */
    /**
     * @param array<string, mixed> $claims
     * @param array<string, string>|null $headers
     */
    public function issue(array $claims, ?int $ttl = null, string $keyset = 'default', ?array $headers = null): string
    {
        return $this->encoder->encode($claims, $ttl, $keyset, $headers);
    }

    /**
     * Parse and validate a JWT, returning the payload.
     */
    public function parse(string $encodedToken, string $keyset = 'default'): stdClass
    {
        return $this->decoder->decode($encodedToken, $keyset);
    }
}
