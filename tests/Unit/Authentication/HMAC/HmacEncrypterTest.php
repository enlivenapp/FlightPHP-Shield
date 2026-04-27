<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Unit\Authentication\HMAC;

use Enlivenapp\FlightShield\Authentication\HMAC\HmacEncrypter;
use Enlivenapp\FlightShield\Exceptions\RuntimeException;
use Enlivenapp\FlightShield\Exceptions\SecurityException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(HmacEncrypter::class)]
class HmacEncrypterTest extends TestCase
{
    private function makeConfig(array $overrides = []): array
    {
        return array_merge_recursive([
            'hmac' => [
                'encryption_keys'        => ['k1' => 'my-secret-encryption-key-here-32chars'],
                'encryption_current_key' => 'k1',
                'encryption_cipher'      => 'aes-256-gcm',
                'secret2_storage_limit'  => 255,
            ],
        ], $overrides);
    }

    private function makeEncrypter(array $overrides = []): HmacEncrypter
    {
        return new HmacEncrypter($this->makeConfig($overrides));
    }

    // -----------------------------------------------------------------
    // Constructor validation
    // -----------------------------------------------------------------

    #[Test]
    public function constructorThrowsWhenNoKeysConfigured(): void
    {
        $this->expectException(RuntimeException::class);
        new HmacEncrypter([
            'hmac' => [
                'encryption_keys'        => [],
                'encryption_current_key' => 'k1',
                'encryption_cipher'      => 'aes-256-gcm',
                'secret2_storage_limit'  => 255,
            ],
        ]);
    }

    #[Test]
    public function constructorThrowsWhenCurrentKeyIsEmpty(): void
    {
        $this->expectException(RuntimeException::class);
        new HmacEncrypter([
            'hmac' => [
                'encryption_keys'        => ['k1' => 'my-secret-encryption-key-here-32chars'],
                'encryption_current_key' => '',
                'encryption_cipher'      => 'aes-256-gcm',
                'secret2_storage_limit'  => 255,
            ],
        ]);
    }

    #[Test]
    public function constructorThrowsWhenCurrentKeyNotInMap(): void
    {
        $this->expectException(RuntimeException::class);
        new HmacEncrypter([
            'hmac' => [
                'encryption_keys'        => ['k1' => 'my-secret-encryption-key-here-32chars'],
                'encryption_current_key' => 'k2',
                'encryption_cipher'      => 'aes-256-gcm',
                'secret2_storage_limit'  => 255,
            ],
        ]);
    }

    // -----------------------------------------------------------------
    // encrypt / decrypt
    // -----------------------------------------------------------------

    #[Test]
    public function encryptDecryptRoundtrip(): void
    {
        $enc = $this->makeEncrypter();

        $plaintext  = 'super-secret-hmac-key';
        $ciphertext = $enc->encrypt($plaintext);

        $this->assertSame($plaintext, $enc->decrypt($ciphertext));
    }

    #[Test]
    public function encryptedFormatStartsWithMarker(): void
    {
        $enc = $this->makeEncrypter();

        $ciphertext = $enc->encrypt('hello');

        $this->assertStringStartsWith('$b6$k1$', $ciphertext);
    }

    #[Test]
    public function multipleEncryptionsProduceDifferentCiphertexts(): void
    {
        $enc = $this->makeEncrypter();

        $a = $enc->encrypt('same-string');
        $b = $enc->encrypt('same-string');

        $this->assertNotSame($a, $b);
    }

    #[Test]
    public function decryptWithWrongKeyFails(): void
    {
        $enc1 = new HmacEncrypter([
            'hmac' => [
                'encryption_keys'        => ['k1' => 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'],
                'encryption_current_key' => 'k1',
                'encryption_cipher'      => 'aes-256-gcm',
                'secret2_storage_limit'  => 255,
            ],
        ]);

        $ciphertext = $enc1->encrypt('secret');

        $enc2 = new HmacEncrypter([
            'hmac' => [
                'encryption_keys'        => ['k1' => 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'],
                'encryption_current_key' => 'k1',
                'encryption_cipher'      => 'aes-256-gcm',
                'secret2_storage_limit'  => 255,
            ],
        ]);

        $this->expectException(SecurityException::class);
        $enc2->decrypt($ciphertext);
    }

    #[Test]
    public function decryptWithInvalidBase64ThrowsSecurityException(): void
    {
        $enc = $this->makeEncrypter();

        // Valid prefix but payload is not valid base64
        $this->expectException(SecurityException::class);
        $enc->decrypt('$b6$k1$not!!valid!!base64!!!');
    }

    #[Test]
    public function decryptWithInvalidFormatThrowsSecurityException(): void
    {
        $enc = $this->makeEncrypter();

        $this->expectException(SecurityException::class);
        $enc->decrypt('plaintext-no-marker');
    }

    #[Test]
    public function encryptThrowsWhenResultExceedsStorageLimit(): void
    {
        $enc = new HmacEncrypter([
            'hmac' => [
                'encryption_keys'        => ['k1' => 'my-secret-encryption-key-here-32chars'],
                'encryption_current_key' => 'k1',
                'encryption_cipher'      => 'aes-256-gcm',
                'secret2_storage_limit'  => 10,
            ],
        ]);

        $this->expectException(RuntimeException::class);
        $enc->encrypt('hello');
    }

    // -----------------------------------------------------------------
    // isEncrypted / isEncryptedWithCurrentKey
    // -----------------------------------------------------------------

    #[Test]
    public function isEncryptedReturnsTrueForEncryptedString(): void
    {
        $enc        = $this->makeEncrypter();
        $ciphertext = $enc->encrypt('hello');

        $this->assertTrue($enc->isEncrypted($ciphertext));
    }

    #[Test]
    public function isEncryptedReturnsFalseForPlainString(): void
    {
        $enc = $this->makeEncrypter();

        $this->assertFalse($enc->isEncrypted('plain-text'));
    }

    #[Test]
    public function isEncryptedWithCurrentKeyReturnsTrueForCurrentKey(): void
    {
        $enc        = $this->makeEncrypter();
        $ciphertext = $enc->encrypt('hello');

        $this->assertTrue($enc->isEncryptedWithCurrentKey($ciphertext));
    }

    #[Test]
    public function isEncryptedWithCurrentKeyReturnsFalseForDifferentKey(): void
    {
        // Build ciphertext with k1, then check against an encrypter whose current key is k2
        $enc1       = $this->makeEncrypter();
        $ciphertext = $enc1->encrypt('hello');

        $enc2 = new HmacEncrypter([
            'hmac' => [
                'encryption_keys'        => [
                    'k1' => 'my-secret-encryption-key-here-32chars',
                    'k2' => 'another-secret-key-here-32chars-xx',
                ],
                'encryption_current_key' => 'k2',
                'encryption_cipher'      => 'aes-256-gcm',
                'secret2_storage_limit'  => 255,
            ],
        ]);

        $this->assertFalse($enc2->isEncryptedWithCurrentKey($ciphertext));
    }

    // -----------------------------------------------------------------
    // Multiple keys — decrypt old key with new current
    // -----------------------------------------------------------------

    #[Test]
    public function canDecryptOldKeyWhenNewKeyIsCurrent(): void
    {
        $enc1 = new HmacEncrypter([
            'hmac' => [
                'encryption_keys'        => ['k1' => 'my-secret-encryption-key-here-32chars'],
                'encryption_current_key' => 'k1',
                'encryption_cipher'      => 'aes-256-gcm',
                'secret2_storage_limit'  => 255,
            ],
        ]);

        $ciphertext = $enc1->encrypt('secret-value');

        // New encrypter with k2 as current, but k1 still in keys map
        $enc2 = new HmacEncrypter([
            'hmac' => [
                'encryption_keys'        => [
                    'k1' => 'my-secret-encryption-key-here-32chars',
                    'k2' => 'another-secret-key-here-32chars-xx',
                ],
                'encryption_current_key' => 'k2',
                'encryption_cipher'      => 'aes-256-gcm',
                'secret2_storage_limit'  => 255,
            ],
        ]);

        $this->assertSame('secret-value', $enc2->decrypt($ciphertext));
    }

    // -----------------------------------------------------------------
    // generateSecretKey
    // -----------------------------------------------------------------

    #[Test]
    public function generateSecretKeyReturnsBase64String(): void
    {
        $enc = $this->makeEncrypter();
        $key = $enc->generateSecretKey();

        // base64_decode should succeed and yield exactly 32 bytes
        $decoded = base64_decode($key, true);
        $this->assertNotFalse($decoded);
        $this->assertSame(32, strlen($decoded));
    }

    #[Test]
    public function generateSecretKeyRespectsCustomByteLength(): void
    {
        $enc = $this->makeEncrypter();
        $key = $enc->generateSecretKey(16);

        $decoded = base64_decode($key, true);
        $this->assertNotFalse($decoded);
        $this->assertSame(16, strlen($decoded));
    }

    // -----------------------------------------------------------------
    // Key derivation
    // -----------------------------------------------------------------

    #[Test]
    public function keyDerivationUsesHkdfWithExpectedContext(): void
    {
        // Two encrypters with the SAME raw key must produce the SAME derived key
        // (and therefore identical decryption results) — verifying HKDF is deterministic.
        $config = $this->makeConfig();

        $enc1 = new HmacEncrypter($config);
        $enc2 = new HmacEncrypter($config);

        $ciphertext = $enc1->encrypt('verify-hkdf');

        // enc2 derives the same key from the same material so must decrypt successfully
        $this->assertSame('verify-hkdf', $enc2->decrypt($ciphertext));
    }

    #[Test]
    public function keyDerivationContextIsFlightShieldHmacEncV1(): void
    {
        // Manually reproduce what HmacEncrypter does: HKDF with that context string.
        $rawKey  = 'my-secret-encryption-key-here-32chars';
        $derived = hash_hkdf('sha256', $rawKey, 32, 'flight-shield-hmac-enc-v1');

        $this->assertSame(32, strlen($derived));

        // Verify the encrypter actually uses this key by producing a ciphertext
        // and then manually decrypting it with the derived key.
        $enc        = $this->makeEncrypter();
        $ciphertext = $enc->encrypt('hkdf-context-test');

        // Parse the ciphertext manually
        preg_match('/^\$b6\$(\w+?)\$(.+)\z/', $ciphertext, $m);
        $payload   = base64_decode($m[2], true);
        $iv        = substr($payload, 0, 12);
        $tag       = substr($payload, 12, 16);
        $encrypted = substr($payload, 28);

        $decrypted = openssl_decrypt($encrypted, 'aes-256-gcm', $derived, OPENSSL_RAW_DATA, $iv, $tag);

        $this->assertSame('hkdf-context-test', $decrypted);
    }
}
