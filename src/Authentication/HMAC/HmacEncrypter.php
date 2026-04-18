<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Authentication\HMAC;

use Enlivenapp\FlightShield\Exceptions\RuntimeException;
use Enlivenapp\FlightShield\Exceptions\SecurityException;

/**
 * HMAC Encrypter — encrypts/decrypts HMAC secret keys for storage.
 *
 * Uses OpenSSL directly instead of CI4's Encryption service.
 * Keys are stored in the format: $b6$<keyId>$<base64(iv + tag + encrypted)>
 */
class HmacEncrypter
{
    protected array $keys;
    protected string $currentKey;
    protected string $cipher = 'aes-256-gcm';
    protected int $storageLimitBytes;

    public function __construct(array $config)
    {
        $hmac = $config['hmac'] ?? [];
        $this->keys = $hmac['encryption_keys'] ?? [];
        $this->currentKey = $hmac['encryption_current_key'] ?? '';
        $this->cipher = $hmac['encryption_cipher'] ?? 'aes-256-gcm';
        $this->storageLimitBytes = $hmac['secret2_storage_limit'] ?? 255;

        if (empty($this->currentKey) || ! isset($this->keys[$this->currentKey])) {
            throw new RuntimeException('HMAC encryption key not configured.');
        }
    }

    public function encrypt(string $rawString): string
    {
        $key = $this->getKey($this->currentKey);
        $iv = random_bytes(12);
        $tag = '';

        $encrypted = openssl_encrypt($rawString, $this->cipher, $key, OPENSSL_RAW_DATA, $iv, $tag, '', 16);

        if ($encrypted === false) {
            throw new SecurityException('Encryption failed.');
        }

        $result = '$b6$' . $this->currentKey . '$' . base64_encode($iv . $tag . $encrypted);

        if (strlen($result) > $this->storageLimitBytes) {
            throw new RuntimeException('Encrypted key too long. Unable to store value.');
        }

        return $result;
    }

    public function decrypt(string $encString): string
    {
        $matches = [];
        if (preg_match('/^\$b6\$(\w+?)\$(.+)\z/', $encString, $matches) !== 1) {
            throw new SecurityException('Unable to decrypt string.');
        }

        $keyId = $matches[1];
        $payload = base64_decode($matches[2], true);

        if ($payload === false) {
            throw new SecurityException('Unable to decrypt string.');
        }

        $key = $this->getKey($keyId);
        $iv = substr($payload, 0, 12);
        $tag = substr($payload, 12, 16);
        $encrypted = substr($payload, 28);

        $decrypted = openssl_decrypt($encrypted, $this->cipher, $key, OPENSSL_RAW_DATA, $iv, $tag);

        if ($decrypted === false) {
            throw new SecurityException('Decryption failed.');
        }

        return $decrypted;
    }

    public function isEncrypted(string $string): bool
    {
        return preg_match('/^\$b6\$/', $string) === 1;
    }

    public function isEncryptedWithCurrentKey(string $string): bool
    {
        return preg_match('/^\$b6\$' . preg_quote($this->currentKey, '/') . '\$/', $string) === 1;
    }

    public function generateSecretKey(int $bytes = 32): string
    {
        return base64_encode(random_bytes($bytes));
    }

    protected function getKey(string $keyId): string
    {
        if (! isset($this->keys[$keyId])) {
            throw new RuntimeException("Encryption key '{$keyId}' does not exist.");
        }

        $derived = hash_hkdf('sha256', $this->keys[$keyId], 32, 'flight-shield-hmac-enc-v1');

        if (strlen($derived) !== 32) {
            throw new SecurityException('Key derivation produced an invalid key length.');
        }

        return $derived;
    }
}
