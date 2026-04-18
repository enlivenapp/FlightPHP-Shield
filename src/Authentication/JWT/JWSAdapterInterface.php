<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Authentication\JWT;

use stdClass;

interface JWSAdapterInterface
{
    /**
     * @param array<string, mixed>       $payload The payload.
     * @param string                     $keyset  The key group.
     * @param array<string, string>|null $headers Header elements to attach.
     *
     * @return string JWT (JWS)
     */
    public function encode(array $payload, string $keyset, ?array $headers = null): string;

    /**
     * @param string $keyset The key group.
     *
     * @return stdClass Payload
     */
    public function decode(string $encodedToken, string $keyset): stdClass;
}
