<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Support;

/**
 * Detects crawlers/robots from a User-Agent string so magic-link and
 * action verification endpoints can return 404 instead of burning tokens
 * and emailing codes.
 *
 * The keyword set mirrors CodeIgniter's default robot list
 * (original PRs by michalsn — @see https://github.com/codeigniter4/shield/pull/1294
 * and https://github.com/codeigniter4/shield/pull/1295).
 */
class RobotDetector
{
    /**
     * Robot keywords, matched case-insensitively against the User-Agent.
     */
    public const DEFAULT_ROBOT_KEYWORDS = [
        'googlebot',
        'google-pagerenderer',
        'google-read-aloud',
        'google-safety',
        'msnbot',
        'baiduspider',
        'bingbot',
        'bingpreview',
        'slurp',
        'yahoo',
        'ask jeeves',
        'fastcrawler',
        'infoseek',
        'lycos',
        'yandex',
        'mediapartners-google',
        'crazywebcrawler',
        'adsbot-google',
        'feedfetcher-google',
        'curious george',
        'ia_archiver',
        'mj12bot',
        'uptimebot',
        'duckduckbot',
        'sogou',
        'exabot',
        'bot',
        'crawler',
        'spider',
    ];

    /**
     * @param list<string> $keywords Extra keywords to match against
     * @param array        $config   'bot_detection' config: 'enabled' and 'user_agents'
     */
    public static function isBot(
        ?string $userAgent = null,
        array $config = [],
        array $keywords = []
    ): bool {
        if (! ($config['enabled'] ?? true)) {
            return false;
        }

        $userAgent = $userAgent ?? $_SERVER['HTTP_USER_AGENT'] ?? '';

        if ($userAgent === '') {
            return false;
        }

        $needles = array_merge($keywords, $config['user_agents'] ?? [], self::DEFAULT_ROBOT_KEYWORDS);
        $needle  = strtolower(implode('|', array_map('preg_quote', $needles)));

        return (bool) preg_match('/' . $needle . '/i', $userAgent);
    }
}