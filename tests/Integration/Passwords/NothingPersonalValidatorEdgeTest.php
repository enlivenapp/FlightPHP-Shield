<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Integration\Passwords;

use Enlivenapp\FlightShield\Models\User;
use Enlivenapp\FlightShield\Passwords\NothingPersonalValidator;
use Enlivenapp\FlightShield\Tests\TestHelper;
use PDO;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The "nothing personal" checks: username, reversed username, email parts
 * and the similarity threshold.
 */
#[CoversClass(NothingPersonalValidator::class)]
class NothingPersonalValidatorEdgeTest extends TestCase
{
    protected PDO $pdo;
    protected User $user;
    protected NothingPersonalValidator $validator;

    protected function setUp(): void
    {
        $this->pdo = TestHelper::createDatabase();
        TestHelper::resetFlight();
        TestHelper::registerFlightDb($this->pdo);

        $this->user = TestHelper::createUser($this->pdo, 'jonathan@example.com', 'Str0ng!Passw0rd', 'jonathan', true);
        $this->validator = new NothingPersonalValidator(['max_similarity' => 50]);
    }

    protected function tearDown(): void
    {
        TestHelper::resetFlight();
    }

    private function check(string $password, ?array $config = null): bool
    {
        $validator = $config === null
            ? $this->validator
            : new NothingPersonalValidator($config);

        return $validator->check($password, $this->user)->isOK();
    }

    #[Test]
    public function aNullUserAlwaysPasses(): void
    {
        $this->assertTrue((new NothingPersonalValidator([]))->check('jonathan', null)->isOK());
    }

    #[Test]
    public function theUsernameItselfIsRejected(): void
    {
        $this->assertFalse($this->check('jonathan'));
    }

    #[Test]
    public function theReversedUsernameIsRejected(): void
    {
        $this->assertFalse($this->check('nahtanoj'));
    }

    #[Test]
    public function theEmailLocalPartIsRejected(): void
    {
        $this->assertFalse($this->check('jonathan123'));
    }

    #[Test]
    public function theEmailDomainIsRejected(): void
    {
        // The domain needle is the full domain, so the password has to
        // contain 'example.com' to trip it.
        $this->assertFalse($this->check('example.com7'));
    }

    #[Test]
    public function anUnrelatedPasswordPasses(): void
    {
        $this->assertTrue($this->check('Purple!Harbour9'));
    }

    #[Test]
    public function shortFragmentsAreIgnored(): void
    {
        // 'jo' is under the three-character floor, so it is not a needle.
        $this->assertTrue($this->check('jo9!Xyk'));
    }

    #[Test]
    public function aDisabledSimilarityThresholdSkipsTheSimilarityCheck(): void
    {
        $this->assertTrue($this->check('jonath0n', ['max_similarity' => 0]));
    }

    #[Test]
    public function anOverLargeSimilarityThresholdIsClampedTo100(): void
    {
        // The threshold is clamped to 100, so a merely-similar password
        // still passes rather than being rejected outright.
        $this->assertTrue($this->check('jonath0n', ['max_similarity' => 500]));
    }

    #[Test]
    public function aUserWithoutAUsernameOnlyChecksTheEmail(): void
    {
        $this->pdo->exec("UPDATE users SET username = NULL WHERE id = {$this->user->id}");
        $user = (new User($this->pdo))->findById($this->user->id);

        $this->assertTrue($this->validator->check('Purple!Harbour9', $user)->isOK());
        $this->assertFalse($this->validator->check('jonathan99', $user)->isOK());
    }
}
