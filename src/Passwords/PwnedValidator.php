<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Passwords;

use Enlivenapp\FlightShield\Models\User;
use Enlivenapp\FlightShield\Result;

/**
 * Checks password against the Have I Been Pwned database
 * of over 500 million stolen passwords.
 *
 * @see https://haveibeenpwned.com/API/v3#PwnedPasswords
 */
class PwnedValidator extends BaseValidator implements ValidatorInterface
{
    public function check(string $password, ?User $user = null): Result
    {
        $hashedPassword = strtoupper(sha1($password));
        $rangeHash  = substr($hashedPassword, 0, 5);
        $searchHash = substr($hashedPassword, 5);

        $ch = curl_init("https://api.pwnedpasswords.com/range/{$rangeHash}");
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER     => ['Accept: text/plain'],
            CURLOPT_TIMEOUT        => 10,
            CURLOPT_CONNECTTIMEOUT => 5,
        ]);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        // If the API is unreachable, let the password through
        if ($response === false || $httpCode !== 200) {
            return (new Result())->setSuccess(true);
        }

        $startPos = strpos($response, $searchHash);
        if ($startPos === false) {
            return (new Result())->setSuccess(true);
        }

        $startPos += 36; // past the delimiter (:)
        $endPos = strpos($response, "\r\n", $startPos);
        $hits = $endPos !== false
            ? (int) substr($response, $startPos, $endPos - $startPos)
            : (int) substr($response, $startPos);

        $wording = $hits > 1 ? 'databases' : 'a database';

        return (new Result())
            ->setSuccess(false)
            ->setReason("This password has appeared in {$hits} data breaches found in {$wording}.")
            ->setExtraInfo('Choose a password that has not been exposed in a data breach.');
    }
}
