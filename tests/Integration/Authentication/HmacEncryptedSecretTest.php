<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Integration\Authentication;

use Enlivenapp\FlightShield\Authentication\Authenticators\HmacSha256;
use Enlivenapp\FlightShield\Authentication\HMAC\HmacEncrypter;
use Enlivenapp\FlightShield\Models\User;
use Enlivenapp\FlightShield\Models\UserIdentity;
use Enlivenapp\FlightShield\Tests\TestHelper;
use PDO;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The HMAC authenticator with encryption at rest enabled: the stored secret
 * is decrypted before the signature is checked.
 */
#[CoversClass(HmacSha256::class)]
class HmacEncryptedSecretTest extends TestCase
{
    private const RAW_SECRET = 'raw-secret-value-for-signing';

    protected PDO $pdo;
    protected User $user;
    protected array $config;

    protected function setUp(): void
    {
        $this->pdo = TestHelper::createDatabase();
        TestHelper::resetFlight();
        TestHelper::registerFlightDb($this->pdo);

        $_SERVER['REMOTE_ADDR'] = '10.0.0.1';

        $this->config = TestHelper::getConfig();
        $this->config['hmac'] = [
            'encryption_keys'        => ['k1' => 'my-secret-encryption-key-here-32chars'],
            'encryption_current_key' => 'k1',
            'encryption_cipher'      => 'aes-256-gcm',
        ];

        $this->user = TestHelper::createUser($this->pdo, 'user@example.com', 'Str0ng!Passw0rd', 'user', true);
    }

    protected function tearDown(): void
    {
        TestHelper::resetFlight();
        unset($_SERVER['REMOTE_ADDR']);
    }

    /**
     * Store an encrypted HMAC identity and return the key.
     */
    private function seedEncryptedKey(): string
    {
        $key = bin2hex(random_bytes(16));
        $now = new \DateTimeImmutable();
        $encrypted = (new HmacEncrypter($this->config))->encrypt(self::RAW_SECRET);

        $identity = new UserIdentity($this->pdo);
        $identity->user_id    = $this->user->id;
        $identity->type       = UserIdentity::TYPE_HMAC_TOKEN;
        $identity->name       = 'test';
        $identity->secret     = $key;
        $identity->secret2    = $encrypted;
        $identity->created_at = $now->format('Y-m-d H:i:s');
        $identity->updated_at = $now->format('Y-m-d H:i:s');
        $identity->insert();

        return $key;
    }

    private function sign(string $key, int $ts): string
    {
        $sig = hash_hmac('sha256', 'GET' . "\n" . '/api' . "\n" . $ts . "\n" . '', self::RAW_SECRET);

        return 'HMAC-SHA256 ' . $key . ':' . $sig;
    }

    #[Test]
    public function checkDecryptsTheStoredSecretBeforeVerifying(): void
    {
        $auth = new HmacSha256(\Flight::app(), $this->config);
        $key = $this->seedEncryptedKey();
        $ts = time();

        $result = $auth->check([
            'token'     => $this->sign($key, $ts),
            'timestamp' => (string) $ts,
            'method'    => 'GET',
            'path'      => '/api',
            'body'      => '',
        ]);

        $this->assertTrue($result->isOK());
        $this->assertSame($this->user->id, $result->extraInfo()->id);
    }

    #[Test]
    public function checkStillRejectsAWrongSignatureWithEncryptionOn(): void
    {
        $auth = new HmacSha256(\Flight::app(), $this->config);
        $key = $this->seedEncryptedKey();
        $ts = time();

        $result = $auth->check([
            'token'     => 'HMAC-SHA256 ' . $key . ':deadbeef',
            'timestamp' => (string) $ts,
            'method'    => 'GET',
            'path'      => '/api',
            'body'      => '',
        ]);

        $this->assertFalse($result->isOK());
        $this->assertSame('HMAC signature verification failed.', $result->reason());
    }

    #[Test]
    public function aPartiallyConfiguredEncryptionFallsBackToTheRawSecret(): void
    {
        // A current key that is not present in the key map disables
        // encryption handling, so the raw secret is used as-is.
        $config = $this->config;
        $config['hmac']['encryption_current_key'] = 'missing';
        $auth = new HmacSha256(\Flight::app(), $config);

        $key = bin2hex(random_bytes(16));
        $now = new \DateTimeImmutable();
        $identity = new UserIdentity($this->pdo);
        $identity->user_id    = $this->user->id;
        $identity->type       = UserIdentity::TYPE_HMAC_TOKEN;
        $identity->name       = 'plain';
        $identity->secret     = $key;
        $identity->secret2    = self::RAW_SECRET;
        $identity->created_at = $now->format('Y-m-d H:i:s');
        $identity->updated_at = $now->format('Y-m-d H:i:s');
        $identity->insert();

        $ts = time();
        $result = $auth->check([
            'token'     => $this->sign($key, $ts),
            'timestamp' => (string) $ts,
            'method'    => 'GET',
            'path'      => '/api',
            'body'      => '',
        ]);

        $this->assertTrue($result->isOK());
    }
}
