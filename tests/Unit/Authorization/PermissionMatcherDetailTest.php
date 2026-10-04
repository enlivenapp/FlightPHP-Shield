<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Unit\Authorization;

use Enlivenapp\FlightShield\Authorization\PermissionMatcher;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * The matcher's edge cases: the trailing-wildcard prefix rule, the
 * continue-vs-break behaviour across grants, and the literal guard.
 */
#[CoversClass(PermissionMatcher::class)]
class PermissionMatcherDetailTest extends TestCase
{
    /**
     * @return iterable<string, array{string, list<string>, bool}>
     */
    public static function trailingWildcardProvider(): iterable
    {
        // A grant of the form 'prefix.*' matches descendants only.
        yield 'prefix wildcard matches a child' => ['users.create', ['users.*'], true];
        yield 'prefix wildcard matches a grandchild' => ['users.create.team', ['users.*'], true];
        yield 'prefix wildcard does not match the prefix itself' => ['users', ['users.*'], false];
        yield 'prefix wildcard does not match a longer sibling' => ['usersx.create', ['users.*'], false];
        yield 'prefix wildcard with a dotted prefix' => ['a.b.c', ['a.b.*'], true];
        yield 'prefix wildcard with a dotted prefix parent' => ['a.b', ['a.b.*'], false];
    }

    #[Test]
    #[DataProvider('trailingWildcardProvider')]
    public function trailingWildcardMatchesDescendantsOnly(string $permission, array $grants, bool $expected): void
    {
        $this->assertSame($expected, PermissionMatcher::matches($permission, $grants));
    }

    /**
     * @return iterable<string, array{string, list<string>, bool}>
     */
    public static function grantOrderProvider(): iterable
    {
        // A non-matching grant before a matching one must not stop the scan.
        yield 'invalid grant before a valid one' => ['users.edit', ['*', 'users.edit'], true];
        yield 'invalid grant before a wildcard' => ['users.create', ['*', 'users.*'], true];
        yield 'empty-segment grant before a valid one' => ['users.edit', ['users..edit', 'users.edit'], true];
        yield 'partial wildcard grant before a valid one' => ['users.edit', ['users.e*', 'users.edit'], true];
        yield 'leading wildcard grant before a valid one' => ['users.edit', ['*.edit', 'users.edit'], true];
        yield 'unrelated grant before a valid one' => ['users.edit', ['roles.create', 'users.edit'], true];
        yield 'valid grant after several invalid ones' => ['a.b', ['*', 'x..y', 'a.*'], true];
    }

    #[Test]
    #[DataProvider('grantOrderProvider')]
    public function anInvalidGrantDoesNotStopTheScan(string $permission, array $grants, bool $expected): void
    {
        $this->assertSame($expected, PermissionMatcher::matches($permission, $grants));
    }

    /**
     * @return iterable<string, array{string, list<string>, bool}>
     */
    public static function literalGuardProvider(): iterable
    {
        // The 'prefix.*' fast path only applies to a literal prefix.
        yield 'literal prefix with a wildcard' => ['users.create', ['users.*'], true];
        yield 'prefix containing a wildcard is not literal' => ['users.create', ['us*ers.*'], false];
        yield 'prefix with a double dot is not literal' => ['users.create', ['users..*'], false];
        yield 'prefix starting with a dot is not literal' => ['users.create', ['.users.*'], false];
        yield 'prefix ending with a dot is not literal' => ['users.create', ['users..*'], false];
    }

    #[Test]
    #[DataProvider('literalGuardProvider')]
    public function thePrefixFastPathRequiresALiteral(string $permission, array $grants, bool $expected): void
    {
        $this->assertSame($expected, PermissionMatcher::matches($permission, $grants));
    }

    /**
     * @return iterable<string, array{string, list<string>, bool}>
     */
    public static function segmentValidationProvider(): iterable
    {
        yield 'a bare star segment is allowed' => ['a.b.c', ['a.*.c'], true];
        yield 'a star with text is rejected' => ['a.b.c', ['a.b*.c'], false];
        yield 'an empty segment is rejected' => ['a.b.c', ['a..c'], false];
        yield 'a leading star segment is rejected' => ['a.b.c', ['*.b.c'], false];
        yield 'a trailing star segment is allowed' => ['a.b.c', ['a.b.*'], true];
        yield 'two star segments are allowed' => ['a.b.c.d', ['a.*.*.d'], true];
    }

    #[Test]
    #[DataProvider('segmentValidationProvider')]
    public function segmentValidationIsExact(string $permission, array $grants, bool $expected): void
    {
        $this->assertSame($expected, PermissionMatcher::matches($permission, $grants));
    }

    /**
     * @return iterable<string, array{string, list<string>, bool}>
     */
    public static function segmentCountProvider(): iterable
    {
        // A middle wildcard matches exactly one segment.
        yield 'middle wildcard matches one segment' => ['a.b.c', ['a.*.c'], true];
        yield 'middle wildcard rejects a shorter permission' => ['a.c', ['a.*.c'], false];
        yield 'middle wildcard rejects a longer permission' => ['a.b.x.c', ['a.*.c'], false];
        yield 'exact segment count required without a trailing star' => ['a.b.c', ['a.b.c'], true];
        yield 'one extra segment rejected without a trailing star' => ['a.b.c.d', ['a.b.c'], false];
    }

    #[Test]
    #[DataProvider('segmentCountProvider')]
    public function theSegmentCountIsEnforced(string $permission, array $grants, bool $expected): void
    {
        $this->assertSame($expected, PermissionMatcher::matches($permission, $grants));
    }

    #[Test]
    public function aSingleSegmentPermissionMatchesAnExactGrant(): void
    {
        $this->assertTrue(PermissionMatcher::matches('users', ['users']));
    }

    #[Test]
    public function aSingleSegmentPermissionDoesNotMatchAWildcard(): void
    {
        $this->assertFalse(PermissionMatcher::matches('users', ['*']));
    }

    #[Test]
    public function aTrailingStarGrantWithOneSegmentMatchesADeeperPermission(): void
    {
        $this->assertTrue(PermissionMatcher::matches('a.b', ['a.*']));
    }

    #[Test]
    public function aTrailingStarGrantWithOneSegmentRejectsTheSameSegment(): void
    {
        $this->assertFalse(PermissionMatcher::matches('a', ['a.*']));
    }

    #[Test]
    public function anEmptyGrantListReturnsFalse(): void
    {
        $this->assertFalse(PermissionMatcher::matches('a.b', []));
    }

    #[Test]
    public function anEmptyPermissionReturnsFalse(): void
    {
        $this->assertFalse(PermissionMatcher::matches('', ['a.b']));
    }

    #[Test]
    public function aPermissionWithAWildcardReturnsFalse(): void
    {
        $this->assertFalse(PermissionMatcher::matches('a.*', ['a.b']));
    }

    #[Test]
    public function aPermissionWithAnEmptySegmentReturnsFalse(): void
    {
        $this->assertFalse(PermissionMatcher::matches('a..b', ['a.*']));
    }

    /**
     * @return iterable<string, array{string, list<string>, bool}>
     */
    public static function wildcardPositionProvider(): iterable
    {
        // A wildcard that is not the last character of the grant.
        yield 'wildcard in the middle of a segment' => ['a.b.c', ['a.b*.c'], false];
        yield 'wildcard at the start of a segment' => ['a.b.c', ['a.*b.c'], false];
        yield 'wildcard as the whole middle segment' => ['a.b.c', ['a.*.c'], true];
        yield 'wildcard at the end of a multi-segment grant' => ['a.b.c', ['a.b.*'], true];
        yield 'wildcard alone' => ['a.b', ['*'], false];
        yield 'wildcard after a dot at the end' => ['a.b.c', ['a.b.*'], true];
        yield 'wildcard before a dot' => ['a.b.c', ['a.*.c'], true];
    }

    #[Test]
    #[DataProvider('wildcardPositionProvider')]
    public function theWildcardPositionIsChecked(string $permission, array $grants, bool $expected): void
    {
        $this->assertSame($expected, PermissionMatcher::matches($permission, $grants));
    }

    /**
     * @return iterable<string, array{string, list<string>, bool}>
     */
    public static function continueProvider(): iterable
    {
        // A grant that reaches the 'continue' paths must not stop the scan.
        yield 'a prefix wildcard that does not match, then a valid grant' => ['x.y', ['a.*', 'x.y'], true];
        yield 'a prefix wildcard that does not match, then a wildcard' => ['x.y.z', ['a.*', 'x.*'], true];
        yield 'an invalid grant, then a prefix wildcard' => ['a.b', ['*', 'a.*'], true];
        yield 'a prefix wildcard miss, then an exact match' => ['a.b', ['c.*', 'a.b'], true];
        yield 'two prefix wildcard misses, then a match' => ['a.b', ['c.*', 'd.*', 'a.b'], true];
    }

    #[Test]
    #[DataProvider('continueProvider')]
    public function aNonMatchingGrantContinuesTheScan(string $permission, array $grants, bool $expected): void
    {
        $this->assertSame($expected, PermissionMatcher::matches($permission, $grants));
    }

    #[Test]
    public function aPrefixWildcardMissDoesNotMatch(): void
    {
        $this->assertFalse(PermissionMatcher::matches('a.b', ['c.*']));
    }

    #[Test]
    public function aPrefixWildcardMatchesOnlyItsOwnPrefix(): void
    {
        $this->assertTrue(PermissionMatcher::matches('a.b', ['a.*']));
        $this->assertFalse(PermissionMatcher::matches('ab.b', ['a.*']));
    }

    #[Test]
    public function aPrefixWildcardRequiresTheDotBoundary(): void
    {
        // 'ab' must not match the 'a.*' prefix.
        $this->assertFalse(PermissionMatcher::matches('ab', ['a.*']));
    }

    #[Test]
    public function aPrefixWildcardMatchesADeeperDescendant(): void
    {
        $this->assertTrue(PermissionMatcher::matches('a.b.c.d', ['a.*']));
    }

    #[Test]
    public function aPrefixWildcardDoesNotMatchThePrefixAlone(): void
    {
        $this->assertFalse(PermissionMatcher::matches('a', ['a.*']));
    }
}
