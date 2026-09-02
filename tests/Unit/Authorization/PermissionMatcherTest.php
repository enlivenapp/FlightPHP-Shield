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

#[CoversClass(PermissionMatcher::class)]
class PermissionMatcherTest extends TestCase
{
    /**
     * @return iterable<string, array{string, list<string>, bool}>
     */
    public static function matchProvider(): iterable
    {
        // Exact matches
        yield 'exact' => ['users.edit', ['users.edit'], true];
        yield 'exact among many grants' => ['users.edit', ['roles.delete', 'users.edit'], true];

        // Trailing wildcard — descendants only
        yield 'trailing wildcard descendant' => ['users.create', ['users.*'], true];
        yield 'trailing wildcard deeper descendant' => ['users.create.team', ['users.*'], true];
        yield 'trailing wildcard does not match parent node' => ['users', ['users.*'], false];
        yield 'trailing wildcard does not match sibling root' => ['user', ['users.*'], false];
        yield 'trailing wildcard nested prefix' => ['a.b.c', ['a.b.*'], true];
        yield 'trailing wildcard nested prefix parent' => ['a.b', ['a.b.*'], false];

        // Middle wildcards — exactly one segment
        yield 'middle wildcard single segment' => ['admin.access.post', ['admin.*.post'], true];
        yield 'middle wildcard one-too-few segments' => ['admin.post', ['admin.*.post'], false];
        yield 'middle wildcard mismatch' => ['admin.access.edit', ['admin.*.post'], false];
        yield 'middle wildcard with deep permission' => ['a.b.c.d', ['a.*.c'], false];
        yield 'two middle wildcards' => ['a.b.c.d', ['a.*.*.d'], true];

        // Exact match wins over wildcard interpretation
        yield 'exact match of grant root beats trailing wildcard' => ['users', ['users', 'users.*'], true];

        // Invalid / non-matching
        yield 'standalone star grant matches nothing' => ['users.edit', ['*'], false];
        yield 'leading wildcard segment rejected' => ['users.edit', ['*.edit'], false];
        yield 'partial segment wildcard rejected' => ['users.edit', ['users.e*'], false];
        yield 'wildcard in permission rejected' => ['users.*', ['users'], false];
        yield 'empty permission rejected' => ['', ['users'], false];
        yield 'empty grant segment skipped' => ['users.edit', ['users..edit'], false];
        yield 'empty segments in permission rejected' => ['users..edit', ['users.*'], false];
        yield 'unrelated grants' => ['users.edit', ['roles.create', 'billing.view'], false];
    }

    #[Test]
    #[DataProvider('matchProvider')]
    public function matchesReturnsExpected(string $permission, array $grants, bool $expected): void
    {
        $this->assertSame($expected, PermissionMatcher::matches($permission, $grants));
    }

    #[Test]
    public function emptyGrantListNeverMatches(): void
    {
        $this->assertFalse(PermissionMatcher::matches('users.edit', []));
    }

    #[Test]
    public function caseSensitiveMatching(): void
    {
        $this->assertFalse(PermissionMatcher::matches('users.EDIT', ['users.edit']));
        $this->assertTrue(PermissionMatcher::matches('users.EDIT', ['users.EDIT']));
        $this->assertFalse(PermissionMatcher::matches('Users.create', ['users.*']));
    }
}