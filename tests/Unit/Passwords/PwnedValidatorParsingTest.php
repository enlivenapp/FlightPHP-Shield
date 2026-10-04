<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Unit\Passwords;

use Enlivenapp\FlightShield\Passwords\PwnedValidator;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The HIBP response parsing, driven by a canned range body so no network
 * call is needed.
 */
#[CoversClass(PwnedValidator::class)]
class PwnedValidatorParsingTest extends TestCase
{
    /**
     * @param string|null $body The range body to hand back, or null for
     *   an unreachable API.
     */
    private function validator(?string $body): PwnedValidator
    {
        return new class([], $body) extends PwnedValidator {
            public function __construct(array $config, private ?string $body)
            {
                parent::__construct($config);
            }

            protected function fetchRange(string $rangeHash): ?string
            {
                return $this->body;
            }
        };
    }

    /**
     * Build a range body line for the given password.
     */
    private function lineFor(string $password, int $hits, string $ending = "\r\n"): string
    {
        $hash = strtoupper(sha1($password));

        return substr($hash, 5) . ':' . $hits . $ending;
    }

    // -----------------------------------------------------------------
    // The unreachable API
    // -----------------------------------------------------------------

    #[Test]
    public function anUnreachableApiPassesThePassword(): void
    {
        $this->assertTrue($this->validator(null)->check('password')->isOK());
    }

    // -----------------------------------------------------------------
    // A miss
    // -----------------------------------------------------------------

    #[Test]
    public function aHashNotInTheRangePasses(): void
    {
        $body = $this->lineFor('something-else', 42);

        $this->assertTrue($this->validator($body)->check('password')->isOK());
    }

    #[Test]
    public function anEmptyRangeBodyPasses(): void
    {
        $this->assertTrue($this->validator('')->check('password')->isOK());
    }

    // -----------------------------------------------------------------
    // A hit
    // -----------------------------------------------------------------

    #[Test]
    public function aHashInTheRangeFails(): void
    {
        $body = $this->lineFor('password', 42);

        $this->assertFalse($this->validator($body)->check('password')->isOK());
    }

    #[Test]
    public function theHitCountIsReadFromTheLine(): void
    {
        $body = $this->lineFor('password', 12345);

        $result = $this->validator($body)->check('password');

        $this->assertSame(
            'This password has appeared in 12345 data breaches found in databases.',
            $result->reason()
        );
    }

    #[Test]
    public function aSingleHitUsesTheSingularWording(): void
    {
        $body = $this->lineFor('password', 1);

        $result = $this->validator($body)->check('password');

        $this->assertSame(
            'This password has appeared in 1 data breaches found in a database.',
            $result->reason()
        );
    }

    #[Test]
    public function aZeroHitCountUsesTheSingularWording(): void
    {
        $body = $this->lineFor('password', 0);

        $result = $this->validator($body)->check('password');

        $this->assertStringContainsString('a database', (string) $result->reason());
    }

    #[Test]
    public function theFailureCarriesTheExtraInfo(): void
    {
        $body = $this->lineFor('password', 42);

        $result = $this->validator($body)->check('password');

        $this->assertSame(
            'Choose a password that has not been exposed in a data breach.',
            $result->extraInfo()
        );
    }

    // -----------------------------------------------------------------
    // The line ending
    // -----------------------------------------------------------------

    #[Test]
    public function aLineWithoutATrailingCrlfIsStillRead(): void
    {
        $body = $this->lineFor('password', 42, '');

        $result = $this->validator($body)->check('password');

        $this->assertFalse($result->isOK());
        $this->assertStringContainsString('42 data breaches', (string) $result->reason());
    }

    #[Test]
    public function theHitIsFoundAmongOtherLines(): void
    {
        $body = $this->lineFor('other-one', 7)
            . $this->lineFor('password', 99)
            . $this->lineFor('other-two', 3);

        $result = $this->validator($body)->check('password');

        $this->assertStringContainsString('99 data breaches', (string) $result->reason());
    }

    #[Test]
    public function theHitIsFoundOnTheLastLine(): void
    {
        $body = $this->lineFor('other-one', 7) . $this->lineFor('password', 5, '');

        $result = $this->validator($body)->check('password');

        $this->assertStringContainsString('5 data breaches', (string) $result->reason());
    }

    #[Test]
    public function aPartialHashMatchIsNotAHit(): void
    {
        // The search hash is 35 chars; a 34-char prefix must not match.
        $hash = strtoupper(sha1('password'));
        $body = substr($hash, 5, 34) . ':42' . "\r\n";

        $this->assertTrue($this->validator($body)->check('password')->isOK());
    }

    #[Test]
    public function theSearchUsesTheHashAfterThePrefix(): void
    {
        $hash = strtoupper(sha1('password'));
        // Put the full hash in the body; the search starts after the prefix.
        $body = $hash . ':42' . "\r\n";

        $this->assertFalse($this->validator($body)->check('password')->isOK());
    }
}
