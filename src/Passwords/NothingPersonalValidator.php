<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Passwords;

use Enlivenapp\FlightShield\Entities\User;
use Enlivenapp\FlightShield\Result;

/**
 * Checks that the password doesn't contain personal information
 * (username, email, or other personal fields).
 */
class NothingPersonalValidator extends BaseValidator implements ValidatorInterface
{
    public function check(string $password, ?User $user = null): Result
    {
        if ($user === null) {
            return (new Result())->setSuccess(true);
        }

        $password = strtolower($password);

        if (! $this->isNotPersonal($password, $user)) {
            return (new Result())
                ->setSuccess(false)
                ->setReason('Password should not contain personal information.')
                ->setExtraInfo('Do not use your name, email, or username in your password.');
        }

        if (! $this->isNotSimilar($password, $user)) {
            return (new Result())
                ->setSuccess(false)
                ->setReason('Password is too similar to your username.')
                ->setExtraInfo('Choose a password that is different from your username.');
        }

        return (new Result())->setSuccess(true);
    }

    protected function isNotPersonal(string $password, User $user): bool
    {
        $userName = strtolower($user->username ?? '');

        // Get email from identities if loaded
        $email = '';
        foreach ($user->identities as $identity) {
            if ($identity->type === 'email_password') {
                $email = strtolower($identity->secret);
                break;
            }
        }

        if ($password === $userName || $password === $email || $password === strrev($userName)) {
            return false;
        }

        $needles = $this->stripExplode($userName);

        if (! empty($email) && str_contains($email, '@')) {
            [$localPart, $domain] = explode('@', $email) + [1 => null];
            $emailParts = $this->stripExplode($localPart);
            if ($domain !== null && $domain !== '') {
                $emailParts[] = $domain;
            }
            $needles = array_merge($needles, $emailParts);
        }

        $haystacks = $this->stripExplode($password);

        foreach ($haystacks as $haystack) {
            if (empty($haystack) || mb_strlen($haystack, 'UTF-8') < 3) {
                continue;
            }

            foreach ($needles as $needle) {
                if (empty($needle) || mb_strlen($needle, 'UTF-8') < 3) {
                    continue;
                }

                if (str_contains($haystack, $needle) || str_contains($needle, $haystack)) {
                    return false;
                }
            }
        }

        return true;
    }

    protected function isNotSimilar(string $password, User $user): bool
    {
        if ($user->username === null) {
            return true;
        }

        $maxSimilarity = (float) ($this->config['max_similarity'] ?? 50);

        if ($maxSimilarity < 1) {
            return true;
        }

        if ($maxSimilarity > 100) {
            $maxSimilarity = 100;
        }

        similar_text($password, strtolower($user->username), $similarity);

        return $similarity < $maxSimilarity;
    }

    protected function stripExplode(string $str): array
    {
        $stripped = preg_replace('/[\W_]+/', ' ', $str);
        $parts = explode(' ', trim((string) $stripped));

        if (! in_array($str, $parts, true)) {
            array_unshift($parts, $str);
        }

        return $parts;
    }
}
