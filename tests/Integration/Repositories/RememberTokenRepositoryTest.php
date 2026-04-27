<?php

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Integration\Repositories;

use Enlivenapp\FlightShield\Models\RememberToken;
use Enlivenapp\FlightShield\Tests\TestHelper;
use PDO;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(RememberToken::class)]
class RememberTokenRepositoryTest extends TestCase
{
    protected PDO $pdo;
    protected RememberToken $model;
    protected int $userId;

    protected function setUp(): void
    {
        $this->pdo    = TestHelper::createDatabase();
        TestHelper::registerFlightDb($this->pdo);
        $this->model  = new RememberToken($this->pdo);

        $user           = TestHelper::createUser($this->pdo, 'rem@example.com', 'password123', 'remuser');
        $this->userId   = $user->id;
    }

    /**
     * Insert a remember token row directly and return the selector used.
     */
    private function insertToken(int $userId, string $selector, string $validator, string $expires): void
    {
        $now  = (new \DateTimeImmutable())->format('Y-m-d H:i:s');
        $stmt = $this->pdo->prepare(
            'INSERT INTO auth_remember_tokens
             (selector, hashed_validator, user_id, expires, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?)'
        );
        $stmt->execute([$selector, hash('sha256', $validator), $userId, $expires, $now, $now]);
    }

    // -----------------------------------------------------------------
    // findBySelector
    // -----------------------------------------------------------------

    #[Test]
    public function findBySelectorReturnsTokenForExistingSelector(): void
    {
        $this->insertToken($this->userId, 'sel-abc', 'validator-value', '2099-12-31 23:59:59');

        $token = $this->model->findBySelector('sel-abc');

        $this->assertInstanceOf(RememberToken::class, $token);
        $this->assertSame('sel-abc', $token->selector);
        $this->assertSame($this->userId, $token->user_id);
    }

    #[Test]
    public function findBySelectorReturnsNullForNonExistentSelector(): void
    {
        $result = $this->model->findBySelector('does-not-exist');

        $this->assertNull($result);
    }

    // -----------------------------------------------------------------
    // deleteByUser
    // -----------------------------------------------------------------

    #[Test]
    public function deleteByUserRemovesAllTokensForThatUser(): void
    {
        $other = TestHelper::createUser($this->pdo, 'other@example.com', 'password123', 'otherrem');

        $this->insertToken($this->userId, 'sel-u1a', 'val-u1a', '2099-12-31 23:59:59');
        $this->insertToken($this->userId, 'sel-u1b', 'val-u1b', '2099-12-31 23:59:59');
        $this->insertToken($other->id,    'sel-u2a', 'val-u2a', '2099-12-31 23:59:59');

        $this->model->deleteByUser($this->userId);

        $this->assertNull($this->model->findBySelector('sel-u1a'));
        $this->assertNull($this->model->findBySelector('sel-u1b'));

        // Other user's token should remain
        $this->assertInstanceOf(RememberToken::class, $this->model->findBySelector('sel-u2a'));
    }

    // -----------------------------------------------------------------
    // purgeExpired
    // -----------------------------------------------------------------

    #[Test]
    public function purgeExpiredRemovesOnlyExpiredTokensAndKeepsValidOnes(): void
    {
        $past   = (new \DateTimeImmutable('-1 hour'))->format('Y-m-d H:i:s');
        $future = (new \DateTimeImmutable('+1 hour'))->format('Y-m-d H:i:s');

        $this->insertToken($this->userId, 'sel-expired-1', 'val-exp1', $past);
        $this->insertToken($this->userId, 'sel-expired-2', 'val-exp2', $past);
        $this->insertToken($this->userId, 'sel-valid',     'val-valid', $future);

        $this->model->purgeExpired();

        $this->assertNull($this->model->findBySelector('sel-expired-1'));
        $this->assertNull($this->model->findBySelector('sel-expired-2'));
        $this->assertInstanceOf(RememberToken::class, $this->model->findBySelector('sel-valid'));
    }
}
