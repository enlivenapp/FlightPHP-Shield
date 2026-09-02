<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Authorization;

/**
 * Matches permission grants against requested permission names for
 * Flight Shield authorization internals.
 *
 * Ported from CodeIgniter Shield's PermissionMatcher
 * (original PR by memleakd — @see https://github.com/codeigniter4/shield/pull/1327).
 *
 * Supported wildcards:
 *   - trailing wildcard matches the named node and all of its descendants
 *     (e.g. grant "users.*" matches "users.create", but NOT "users")
 *   - middle wildcard matches exactly one segment
 *     (e.g. grant "admin.*.post" matches "admin.access.post", but NOT
 *     "admin.foo.bar.post")
 *
 * Not allowed: "*" alone, multiple wildcards in one segment, wildcards in
 * the first position, empty segments, or partial segment wildcards.
 */
final class PermissionMatcher
{
    /**
     * @param list<string> $grants
     */
    public static function matches(string $permission, array $grants): bool
    {
        $permissionSegments = self::splitIfValid($permission);

        if ($permissionSegments === null) {
            return false;
        }

        $permissionSegmentCount = count($permissionSegments);

        foreach ($grants as $grant) {
            if ($grant === $permission) {
                return true;
            }

            $wildcardPosition = strpos($grant, '*');

            if ($wildcardPosition === false) {
                continue;
            }

            if (
                $wildcardPosition > 0
                && $wildcardPosition === strlen($grant) - 1
                && $grant[$wildcardPosition - 1] === '.'
            ) {
                $prefix = substr($grant, 0, $wildcardPosition - 1);

                if (self::isLiteral($prefix) && str_starts_with($permission, $prefix . '.')) {
                    return true;
                }

                continue;
            }

            $grantSegments = self::splitIfValid($grant);

            if ($grantSegments === null) {
                continue;
            }

            if (self::matchesWildcardGrant($grantSegments, $permissionSegments, $permissionSegmentCount)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param list<string> $grantSegments
     * @param list<string> $permissionSegments
     */
    private static function matchesWildcardGrant(array $grantSegments, array $permissionSegments, int $permissionSegmentCount): bool
    {
        $grantSegmentCount = count($grantSegments);

        if ($grantSegments[$grantSegmentCount - 1] === '*') {
            $grantSegmentCount--;

            return $permissionSegmentCount > $grantSegmentCount
                && self::segmentsMatch($grantSegments, $permissionSegments, $grantSegmentCount);
        }

        return $permissionSegmentCount === $grantSegmentCount
            && self::segmentsMatch($grantSegments, $permissionSegments, $grantSegmentCount);
    }

    /**
     * @param list<string> $grantSegments
     * @param list<string> $permissionSegments
     */
    private static function segmentsMatch(array $grantSegments, array $permissionSegments, int $segmentCount): bool
    {
        for ($index = 0; $index < $segmentCount; $index++) {
            if ($grantSegments[$index] !== '*' && $grantSegments[$index] !== $permissionSegments[$index]) {
                return false;
            }
        }

        return true;
    }

    /**
     * @return list<string>|null
     */
    private static function splitIfValid(string $permission): ?array
    {
        if ($permission === '' || str_starts_with($permission, '*')) {
            return null;
        }

        $segments = explode('.', $permission);

        foreach ($segments as $segment) {
            if ($segment === '' || ($segment !== '*' && str_contains($segment, '*'))) {
                return null;
            }
        }

        return $segments;
    }

    private static function isLiteral(string $permission): bool
    {
        return $permission !== ''
            && ! str_contains($permission, '*')
            && ! str_contains($permission, '..')
            && ! str_starts_with($permission, '.')
            && ! str_ends_with($permission, '.');
    }
}