<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Authentication\JWT\Adapters;

use Enlivenapp\FlightShield\Authentication\JWT\JWSAdapterInterface;
use Enlivenapp\FlightShield\Exceptions\AuthenticationException;
use stdClass;

/**
 * Firebase JWT adapter.
 * Requires firebase/php-jwt ^6.0 (suggested dependency).
 */
class FirebaseAdapter implements JWSAdapterInterface
{
    protected array $keys;

    public function __construct(array $keys)
    {
        $this->keys = $keys;
    }

    public function decode(string $encodedToken, string $keyset): stdClass
    {
        if (! class_exists(\Firebase\JWT\JWT::class)) {
            throw new \RuntimeException(
                'firebase/php-jwt is required for JWT authentication. Run: composer require firebase/php-jwt'
            );
        }

        $configKeys = $this->keys[$keyset] ?? null;
        if ($configKeys === null) {
            throw new \InvalidArgumentException("Unknown JWT keyset: {$keyset}");
        }

        try {
            $keys = $this->createKeysForDecode($configKeys);
            return \Firebase\JWT\JWT::decode($encodedToken, $keys);
        } catch (\Firebase\JWT\SignatureInvalidException $e) {
            throw AuthenticationException::forInvalidCredentials();
        } catch (\Firebase\JWT\BeforeValidException $e) {
            throw new AuthenticationException('Invalid or expired token.');
        } catch (\Firebase\JWT\ExpiredException $e) {
            throw new AuthenticationException('Invalid or expired token.');
        } catch (\UnexpectedValueException $e) {
            throw AuthenticationException::forInvalidCredentials();
        }
    }

    public function encode(array $payload, string $keyset, ?array $headers = null): string
    {
        if (! class_exists(\Firebase\JWT\JWT::class)) {
            throw new \RuntimeException(
                'firebase/php-jwt is required for JWT authentication. Run: composer require firebase/php-jwt'
            );
        }

        $configKeys = $this->keys[$keyset] ?? null;
        if ($configKeys === null) {
            throw new \InvalidArgumentException("Unknown JWT keyset: {$keyset}");
        }

        [$key, $keyId, $algorithm] = $this->createKeysForEncode($configKeys);

        return \Firebase\JWT\JWT::encode($payload, $key, $algorithm, $keyId, $headers);
    }

    protected function createKeysForDecode(array $configKeys): array|\Firebase\JWT\Key
    {
        if (count($configKeys) === 1) {
            $key       = $configKeys[0]['secret'] ?? $configKeys[0]['public'];
            $algorithm = $configKeys[0]['alg'];
            return new \Firebase\JWT\Key($key, $algorithm);
        }

        $keys = [];
        foreach ($configKeys as $item) {
            $key       = $item['secret'] ?? $item['public'];
            $algorithm = $item['alg'];
            $keys[$item['kid']] = new \Firebase\JWT\Key($key, $algorithm);
        }

        return $keys;
    }

    protected function createKeysForEncode(array $configKeys): array
    {
        if (isset($configKeys[0]['secret'])) {
            $key = $configKeys[0]['secret'];
        } else {
            $passphrase = $configKeys[0]['passphrase'] ?? '';
            if ($passphrase !== '') {
                $key = openssl_pkey_get_private($configKeys[0]['private'], $passphrase);
            } else {
                $key = $configKeys[0]['private'];
            }
        }

        $algorithm = $configKeys[0]['alg'];
        $keyId = $configKeys[0]['kid'] ?? null;
        if ($keyId === '') {
            $keyId = null;
        }

        return [$key, $keyId, $algorithm];
    }
}
