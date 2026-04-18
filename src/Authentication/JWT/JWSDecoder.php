<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Authentication\JWT;

use Enlivenapp\FlightShield\Authentication\JWT\Adapters\FirebaseAdapter;
use stdClass;

class JWSDecoder
{
    protected JWSAdapterInterface $adapter;

    public function __construct(array $keys, ?JWSAdapterInterface $adapter = null)
    {
        $this->adapter = $adapter ?? new FirebaseAdapter($keys);
    }

    public function decode(string $encodedToken, string $keyset = 'default'): stdClass
    {
        return $this->adapter->decode($encodedToken, $keyset);
    }
}
