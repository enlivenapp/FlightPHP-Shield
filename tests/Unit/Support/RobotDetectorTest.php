<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Unit\Support;

use Enlivenapp\FlightShield\Support\RobotDetector;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(RobotDetector::class)]
class RobotDetectorTest extends TestCase
{
    /**
     * @return iterable<string, array{string|null, bool}>
     */
    public static function userAgentProvider(): iterable
    {
        yield 'googlebot' => ['Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)', true];
        yield 'bingbot lowercase' => ['Mozilla/5.0 (compatible; bingbot/2.0)', true];
        yield 'bingpreview' => ['Mozilla/5.0 (compatible; BingPreview/1.0b)', true];
        yield 'duckduckbot' => ['DuckDuckBot/1.0; (+http://duckduckgo.com/duckduckbot.html)', true];
        yield 'mj12bot' => ['Mozilla/5.0 (compatible; MJ12bot/v1.4.8)', true];
        yield 'generic bot substring' => ['Discordbot/2.0', true];
        yield 'yahoo slurp' => ['Mozilla/5.0 (compatible; Yahoo! Slurp/3.0)', true];
        yield 'legit firefox' => ['Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0', false];
        yield 'legit chrome' => ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36', false];
        yield 'curl' => ['curl/8.1.2', false];
        yield 'wget' => ['Wget/1.21.4', false];
        yield 'empty string' => ['', false];
    }

    #[Test]
    #[DataProvider('userAgentProvider')]
    public function detectsRobotsByDefault(?string $userAgent, bool $expected): void
    {
        $this->assertSame($expected, RobotDetector::isBot($userAgent));
    }

    #[Test]
    public function nullUserAgentFallsBackToServer(): void
    {
        $_SERVER['HTTP_USER_AGENT'] = 'Googlebot/2.1';
        $this->assertTrue(RobotDetector::isBot());
        unset($_SERVER['HTTP_USER_AGENT']);
    }

    #[Test]
    public function missingUserAgentIsNotABot(): void
    {
        unset($_SERVER['HTTP_USER_AGENT']);
        $this->assertFalse(RobotDetector::isBot());
    }

    #[Test]
    public function disabledConfigNeverDetects(): void
    {
        $this->assertFalse(RobotDetector::isBot('Googlebot/2.1', ['enabled' => false]));
    }

    #[Test]
    public function extraUserAgentsAreMatched(): void
    {
        $config = ['enabled' => true, 'user_agents' => ['MyCustomCrawler', 'acme-checker']];
        $this->assertTrue(RobotDetector::isBot('MyCustomCrawler/1.0', $config));
        $this->assertTrue(RobotDetector::isBot('ACME-Checker (+https://example.com)', $config));
        $this->assertFalse(RobotDetector::isBot('Mozilla/5.0 Firefox/126.0', $config));
    }
}