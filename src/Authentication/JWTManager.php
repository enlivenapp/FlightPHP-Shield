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
use Enlivenapp\FlightShield\Entities\User;
use stdClass;

class JWTManager
{
    protected JWSEncoder $encoder;
    protected JWSDecoder $decoder;

    public function __construct(array $config)
    {
        $this->encoder = new JWSEncoder($config);
        $this->decoder = new JWSDecoder($config['keys'] ?? []);
    }

    /**
     * Generate a JWT for the given user.
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
