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
 * Requires firebase/php-jwt ^7.0 (suggested dependency).
 *
 * Generator decode signature for php-jwt v7 removed the $headers
 * parameter, so a single keyset resolves to a single Key.
 */
class FirebaseAdapter implements JWSAdapterInterface
{
    /** @var array<string, mixed> */
    protected array $keys;

    /**
     * @param array<string, mixed> $keys
     */
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
        if (! is_array($configKeys)) {
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
        } catch (\Throwable $e) {
            // Anything else the parser throws on a malformed token (a
            // DomainException on invalid encoding, for example) is still a
            // credential failure, not a server error.
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
        if (! is_array($configKeys)) {
            throw new \InvalidArgumentException("Unknown JWT keyset: {$keyset}");
        }

        [$key, $keyId, $algorithm] = $this->createKeysForEncode($configKeys);

        return \Firebase\JWT\JWT::encode($payload, $key, $algorithm, $keyId, $headers);
    }

    /**
     * @param array<array-key, mixed> $configKeys
     *
     * @return array<string, \Firebase\JWT\Key>|\Firebase\JWT\Key
     */
    protected function createKeysForDecode(array $configKeys): array|\Firebase\JWT\Key
    {
        if (count($configKeys) === 1 && is_array($configKeys[0] ?? null)) {
            $item      = $configKeys[0];
            $key       = (string) ($item['secret'] ?? $item['public'] ?? '');
            $algorithm = (string) ($item['alg'] ?? '');

            return new \Firebase\JWT\Key($key, $algorithm);
        }

        /** @var array<string, \Firebase\JWT\Key> $keys */
        $keys = [];
        foreach ($configKeys as $item) {
            if (! is_array($item)) {
                continue;
            }

            $key       = (string) ($item['secret'] ?? $item['public'] ?? '');
            $algorithm = (string) ($item['alg'] ?? '');
            $keys[(string) ($item['kid'] ?? '')] = new \Firebase\JWT\Key($key, $algorithm);
        }

        return $keys;
    }

    /**
     * @param array<array-key, mixed> $configKeys
     *
     * @return array{0: mixed, 1: string|null, 2: string}
     */
    protected function createKeysForEncode(array $configKeys): array
    {
        $first = $configKeys[0] ?? null;
        if (! is_array($first)) {
            throw new \InvalidArgumentException('JWT keyset is missing a key configuration.');
        }

        if (isset($first['secret'])) {
            $key = $first['secret'];
        } else {
            $passphrase = (string) ($first['passphrase'] ?? '');
            if ($passphrase !== '') {
                $key = openssl_pkey_get_private((string) ($first['private'] ?? ''), $passphrase);
            } else {
                $key = $first['private'] ?? '';
            }
        }

        $algorithm = (string) ($first['alg'] ?? '');
        $keyId = $first['kid'] ?? null;
        if ($keyId === '') {
            $keyId = null;
        }

        return [$key, is_string($keyId) ? $keyId : null, $algorithm];
    }
}
