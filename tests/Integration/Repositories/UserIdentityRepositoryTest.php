<?php

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Integration\Repositories;

use Enlivenapp\FlightShield\Models\AccessToken;
use Enlivenapp\FlightShield\Models\User;
use Enlivenapp\FlightShield\Models\UserIdentity;
use Enlivenapp\FlightShield\Tests\TestHelper;
use PDO;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(UserIdentity::class)]
class UserIdentityRepositoryTest extends TestCase
{
    protected PDO $pdo;
    protected UserIdentity $model;
    protected User $user;

    protected function setUp(): void
    {
        $this->pdo   = TestHelper::createDatabase();
        TestHelper::registerFlightDb($this->pdo);
        $this->model = new UserIdentity($this->pdo);
        $this->user  = TestHelper::createUser($this->pdo, 'user@example.com', 'password123', 'testuser');
    }

    // -----------------------------------------------------------------
    // Email/Password
    // -----------------------------------------------------------------

    #[Test]
    public function getEmailIdentityReturnsIdentityForExistingUser(): void
    {
        $identity = $this->model->getEmailIdentity($this->user);

        $this->assertInstanceOf(UserIdentity::class, $identity);
        $this->assertSame(UserIdentity::TYPE_EMAIL_PASSWORD, $identity->type);
        $this->assertSame('user@example.com', $identity->secret);
        $this->assertSame($this->user->id, $identity->user_id);
    }

    #[Test]
    public function getEmailIdentityReturnsNullForUserWithoutEmailIdentity(): void
    {
        // Create a bare user with no identity row
        $now  = (new \DateTimeImmutable())->format('Y-m-d H:i:s');
        $stmt = $this->pdo->prepare('INSERT INTO users (username, active, created_at, updated_at) VALUES (?, ?, ?, ?)');
        $stmt->execute(['noidentity', 1, $now, $now]);
        $userId = (int) $this->pdo->lastInsertId();

        $bare = new User($this->pdo);
        $bare->eq('id', $userId)->find();

        $result = $this->model->getEmailIdentity($bare);

        $this->assertNull($result);
    }

    #[Test]
    public function createEmailIdentityCreatesAndReturnsIdentity(): void
    {
        $now  = (new \DateTimeImmutable())->format('Y-m-d H:i:s');
        $stmt = $this->pdo->prepare('INSERT INTO users (username, active, created_at, updated_at) VALUES (?, ?, ?, ?)');
        $stmt->execute(['newuser', 1, $now, $now]);
        $userId = (int) $this->pdo->lastInsertId();

        $newUser = new User($this->pdo);
        $newUser->eq('id', $userId)->find();

        $hash     = password_hash('secret', PASSWORD_BCRYPT, ['cost' => 4]);
        $identity = $this->model->createEmailIdentity($newUser, [
            'email'         => 'new@example.com',
            'password_hash' => $hash,
        ]);

        $this->assertInstanceOf(UserIdentity::class, $identity);
        $this->assertSame(UserIdentity::TYPE_EMAIL_PASSWORD, $identity->type);
        $this->assertSame('new@example.com', $identity->secret);
        $this->assertSame($hash, $identity->secret2);
        $this->assertSame($userId, $identity->user_id);
    }

    // -----------------------------------------------------------------
    // Access Tokens
    // -----------------------------------------------------------------

    #[Test]
    public function generateAccessTokenCreatesTokenWithHashedSecret(): void
    {
        $token = $this->model->generateAccessToken($this->user, 'my-token', ['read'], null);

        $this->assertInstanceOf(AccessToken::class, $token);
        $this->assertNotEmpty($token->rawToken);
        $this->assertSame(hash('sha256', $token->rawToken), $token->secret);
        $this->assertSame('my-token', $token->name);
        $this->assertSame($this->user->id, $token->user_id);
    }

    #[Test]
    public function generateAccessTokenRawTokenCanBeUsedToLookUpViaGetAccessTokenByRawToken(): void
    {
        $token = $this->model->generateAccessToken($this->user, 'lookup-token', ['*'], null);

        $identity = $this->model->getAccessTokenByRawToken($token->rawToken);

        $this->assertInstanceOf(UserIdentity::class, $identity);
        $this->assertSame(hash('sha256', $token->rawToken), $identity->secret);
    }

    #[Test]
    public function getAccessTokenByRawTokenReturnsNullForWrongToken(): void
    {
        $this->model->generateAccessToken($this->user, 'token', ['read'], null);

        $result = $this->model->getAccessTokenByRawToken('totallywrongtoken');

        $this->assertNull($result);
    }

    #[Test]
    public function getAccessTokenScopesUserCorrectly(): void
    {
        $other = TestHelper::createUser($this->pdo, 'other@example.com', 'password123', 'otheruser');

        $token = $this->model->generateAccessToken($this->user, 'scoped', ['write'], null);

        // Should find for correct user
        $found = $this->model->getAccessToken($this->user, $token->rawToken);
        $this->assertInstanceOf(AccessToken::class, $found);

        // Should NOT find for different user
        $notFound = $this->model->getAccessToken($other, $token->rawToken);
        $this->assertNull($notFound);
    }

    #[Test]
    public function getAccessTokenByIdWorks(): void
    {
        $token = $this->model->generateAccessToken($this->user, 'byid', ['read'], null);

        $found = $this->model->getAccessTokenById($token->id, $this->user);

        $this->assertInstanceOf(AccessToken::class, $found);
        $this->assertSame($token->id, $found->id);
    }

    #[Test]
    public function getAllAccessTokensReturnsAllTokensForUser(): void
    {
        $this->model->generateAccessToken($this->user, 'token-a', ['read'], null);
        $this->model->generateAccessToken($this->user, 'token-b', ['write'], null);

        $tokens = $this->model->getAllAccessTokens($this->user);

        $this->assertCount(2, $tokens);
        foreach ($tokens as $t) {
            $this->assertInstanceOf(AccessToken::class, $t);
        }
    }

    #[Test]
    public function revokeAccessTokenDeletesSpecificToken(): void
    {
        $tokenA = $this->model->generateAccessToken($this->user, 'revoke-me', ['read'], null);
        $tokenB = $this->model->generateAccessToken($this->user, 'keep-me', ['read'], null);

        $this->model->revokeAccessToken($this->user, $tokenA->rawToken);

        $this->assertNull($this->model->getAccessToken($this->user, $tokenA->rawToken));
        $this->assertInstanceOf(AccessToken::class, $this->model->getAccessToken($this->user, $tokenB->rawToken));
    }

    #[Test]
    public function revokeAllAccessTokensDeletesAll(): void
    {
        $this->model->generateAccessToken($this->user, 'token-1', ['read'], null);
        $this->model->generateAccessToken($this->user, 'token-2', ['write'], null);

        $this->model->revokeAllAccessTokens($this->user);

        $remaining = $this->model->getAllAccessTokens($this->user);
        $this->assertCount(0, $remaining);
    }

    // -----------------------------------------------------------------
    // HMAC Tokens
    // -----------------------------------------------------------------

    #[Test]
    public function generateHmacTokenWithoutEncrypterStoresRawSecretKey(): void
    {
        $token = $this->model->generateHmacToken($this->user, 'hmac-token', ['read'], null, null);

        $this->assertInstanceOf(AccessToken::class, $token);
        $this->assertNotEmpty($token->rawToken);
        // rawToken is the key (secret), stored directly when no encrypter
        $this->assertSame($token->rawToken, $token->secret);
    }

    #[Test]
    public function getHmacTokenByKeyFindsIdentityByKey(): void
    {
        $token = $this->model->generateHmacToken($this->user, 'hmac-find', ['read'], null, null);

        $identity = $this->model->getHmacTokenByKey($token->rawToken);

        $this->assertInstanceOf(UserIdentity::class, $identity);
        $this->assertSame(UserIdentity::TYPE_HMAC_TOKEN, $identity->type);
        $this->assertSame($token->rawToken, $identity->secret);
    }

    #[Test]
    public function getHmacTokenScopesUserCorrectly(): void
    {
        $other = TestHelper::createUser($this->pdo, 'hmacother@example.com', 'password123', 'hmacother');

        $token = $this->model->generateHmacToken($this->user, 'hmac-scope', ['read'], null, null);

        $found = $this->model->getHmacToken($this->user, $token->rawToken);
        $this->assertInstanceOf(AccessToken::class, $found);

        $notFound = $this->model->getHmacToken($other, $token->rawToken);
        $this->assertNull($notFound);
    }

    #[Test]
    public function getHmacTokenByIdWorks(): void
    {
        $token = $this->model->generateHmacToken($this->user, 'hmac-byid', ['read'], null, null);

        $found = $this->model->getHmacTokenById($token->id, $this->user);

        $this->assertInstanceOf(AccessToken::class, $found);
        $this->assertSame($token->id, $found->id);
    }

    #[Test]
    public function getAllHmacTokensReturnsAllForUser(): void
    {
        $this->model->generateHmacToken($this->user, 'hmac-a', ['read'], null, null);
        $this->model->generateHmacToken($this->user, 'hmac-b', ['write'], null, null);

        $tokens = $this->model->getAllHmacTokens($this->user);

        $this->assertCount(2, $tokens);
        foreach ($tokens as $t) {
            $this->assertInstanceOf(AccessToken::class, $t);
        }
    }

    #[Test]
    public function revokeHmacTokenDeletesSpecificToken(): void
    {
        $tokenA = $this->model->generateHmacToken($this->user, 'hmac-revoke', ['read'], null, null);
        $tokenB = $this->model->generateHmacToken($this->user, 'hmac-keep', ['read'], null, null);

        $this->model->revokeHmacToken($this->user, $tokenA->rawToken);

        $this->assertNull($this->model->getHmacToken($this->user, $tokenA->rawToken));
        $this->assertInstanceOf(AccessToken::class, $this->model->getHmacToken($this->user, $tokenB->rawToken));
    }

    #[Test]
    public function revokeAllHmacTokensDeletesAll(): void
    {
        $this->model->generateHmacToken($this->user, 'hmac-1', ['read'], null, null);
        $this->model->generateHmacToken($this->user, 'hmac-2', ['write'], null, null);

        $this->model->revokeAllHmacTokens($this->user);

        $remaining = $this->model->getAllHmacTokens($this->user);
        $this->assertCount(0, $remaining);
    }

    // -----------------------------------------------------------------
    // Code Identities
    // -----------------------------------------------------------------

    #[Test]
    public function createCodeIdentityStoresHashedCodeAndReturnsRawCode(): void
    {
        $rawCode = $this->model->createCodeIdentity($this->user, [
            'type'    => UserIdentity::TYPE_MAGIC_LINK,
            'name'    => 'magic',
            'expires' => new \DateTimeImmutable('+10 minutes'),
        ], fn() => bin2hex(random_bytes(16)));

        $this->assertNotEmpty($rawCode);

        // Verify the hashed secret is stored
        $identity = $this->model->getIdentityBySecret(UserIdentity::TYPE_MAGIC_LINK, hash('sha256', $rawCode));
        $this->assertInstanceOf(UserIdentity::class, $identity);
        $this->assertSame(hash('sha256', $rawCode), $identity->secret);
    }

    // -----------------------------------------------------------------
    // Generic Identity Methods
    // -----------------------------------------------------------------

    #[Test]
    public function getIdentityByTypeFindsCorrectType(): void
    {
        $this->model->generateAccessToken($this->user, 'token', ['read'], null);

        $identity = $this->model->getIdentityByType($this->user, UserIdentity::TYPE_ACCESS_TOKEN);

        $this->assertInstanceOf(UserIdentity::class, $identity);
        $this->assertSame(UserIdentity::TYPE_ACCESS_TOKEN, $identity->type);
    }

    #[Test]
    public function getIdentityBySecretFindsByTypeAndSecret(): void
    {
        $rawCode = $this->model->createCodeIdentity($this->user, [
            'type'    => UserIdentity::TYPE_EMAIL_2FA,
            'expires' => new \DateTimeImmutable('+5 minutes'),
        ], fn() => '123456');

        $identity = $this->model->getIdentityBySecret(UserIdentity::TYPE_EMAIL_2FA, hash('sha256', $rawCode));

        $this->assertInstanceOf(UserIdentity::class, $identity);
        $this->assertSame(UserIdentity::TYPE_EMAIL_2FA, $identity->type);
    }

    #[Test]
    public function deleteIdentitiesByTypeRemovesAllOfThatType(): void
    {
        $this->model->generateAccessToken($this->user, 'token-x', ['read'], null);
        $this->model->generateAccessToken($this->user, 'token-y', ['read'], null);

        $this->model->deleteIdentitiesByType($this->user, UserIdentity::TYPE_ACCESS_TOKEN);

        $remaining = $this->model->getAllAccessTokens($this->user);
        $this->assertCount(0, $remaining);

        // Email identity should still be present
        $email = $this->model->getEmailIdentity($this->user);
        $this->assertInstanceOf(UserIdentity::class, $email);
    }

    #[Test]
    public function getIdentitiesByUserReturnsAll(): void
    {
        $this->model->generateAccessToken($this->user, 'one', ['read'], null);
        $this->model->generateHmacToken($this->user, 'two', ['read'], null, null);

        // 1 email_password (from createUser) + 1 access_token + 1 hmac = 3
        $identities = $this->model->getIdentitiesByUser($this->user);

        $this->assertCount(3, $identities);
        foreach ($identities as $i) {
            $this->assertInstanceOf(UserIdentity::class, $i);
        }
    }

    // -----------------------------------------------------------------
    // Utility
    // -----------------------------------------------------------------

    #[Test]
    public function touchIdentityUpdatesLastUsedAt(): void
    {
        $identity = $this->model->getEmailIdentity($this->user);
        $this->assertNull($identity->last_used_at);

        $this->model->touchIdentity($identity);

        $this->assertNotNull($identity->last_used_at);

        // Re-fetch from DB to confirm persistence
        $refreshed = $this->model->getEmailIdentity($this->user);
        $this->assertNotNull($refreshed->last_used_at);
    }

    #[Test]
    public function setIdentityExpirationByIdUpdatesExpires(): void
    {
        $identity = $this->model->getEmailIdentity($this->user);
        $expiry   = '2099-12-31 23:59:59';

        $result = $this->model->setIdentityExpirationById($identity->id, $this->user, $expiry);

        $this->assertTrue($result);

        $refreshed = $this->model->getEmailIdentity($this->user);
        $this->assertSame($expiry, $refreshed->expires);
    }

    #[Test]
    public function setIdentityExpirationByIdReturnsFalseForNonExistent(): void
    {
        $result = $this->model->setIdentityExpirationById(99999, $this->user, '2099-01-01 00:00:00');

        $this->assertFalse($result);
    }

    #[Test]
    public function forcePasswordResetSetsForceResetFlag(): void
    {
        $this->model->forcePasswordReset($this->user, true);

        $identity = $this->model->getEmailIdentity($this->user);
        $this->assertTrue((bool) $identity->force_reset);

        $this->model->forcePasswordReset($this->user, false);

        $identity = $this->model->getEmailIdentity($this->user);
        $this->assertFalse((bool) $identity->force_reset);
    }
}
