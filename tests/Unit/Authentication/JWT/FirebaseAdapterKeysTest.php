<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Unit\Authentication\JWT;

use Enlivenapp\FlightShield\Authentication\JWT\Adapters\FirebaseAdapter;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Asymmetric (RS256) keys: encoding with a private key, decoding with the
 * public key, and the passphrase branch.
 */
#[CoversClass(FirebaseAdapter::class)]
class FirebaseAdapterKeysTest extends TestCase
{
    /**
     * @return array{0: string, 1: string}
     */
    private function rsaKeyPair(?string $passphrase = null): array
    {
        $resource = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);

        openssl_pkey_export($resource, $privatePem, $passphrase);
        $details = openssl_pkey_get_details($resource);

        return [$privatePem, $details['key']];
    }

    private function adapter(string $private, string $public, ?string $passphrase = null): FirebaseAdapter
    {
        $key = ['kid' => 'r1', 'alg' => 'RS256', 'private' => $private, 'public' => $public];
        if ($passphrase !== null) {
            $key['passphrase'] = $passphrase;
        }

        return new FirebaseAdapter(['default' => [$key]]);
    }

    #[Test]
    public function encodeWithAPrivateKeyAndDecodeWithThePublicKey(): void
    {
        [$private, $public] = $this->rsaKeyPair();
        $adapter = $this->adapter($private, $public);

        $token = $adapter->encode(['sub' => '42'], 'default');
        $payload = $adapter->decode($token, 'default');

        $this->assertSame('42', $payload->sub);
    }

    #[Test]
    public function encodeUnlocksAPassphraseProtectedPrivateKey(): void
    {
        [$private, $public] = $this->rsaKeyPair('secret-pass');
        $adapter = $this->adapter($private, $public, 'secret-pass');

        $token = $adapter->encode(['sub' => '7'], 'default');
        $payload = $adapter->decode($token, 'default');

        $this->assertSame('7', $payload->sub);
    }

    #[Test]
    public function decodeRejectsATokenSignedByAnotherKeyPair(): void
    {
        [$privateA] = $this->rsaKeyPair();
        [, $publicB] = $this->rsaKeyPair();

        $signer = new FirebaseAdapter(['default' => [
            ['kid' => 'r1', 'alg' => 'RS256', 'private' => $privateA],
        ]]);

        $token = $signer->encode(['sub' => '1'], 'default');

        $verifier = new FirebaseAdapter(['default' => [
            ['kid' => 'r1', 'alg' => 'RS256', 'public' => $publicB],
        ]]);

        $this->expectException(\Enlivenapp\FlightShield\Exceptions\AuthenticationException::class);

        $verifier->decode($token, 'default');
    }
}
