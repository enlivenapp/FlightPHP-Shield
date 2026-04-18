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
 * Checks password against a dictionary of 65k commonly used passwords.
 */
class DictionaryValidator extends BaseValidator implements ValidatorInterface
{
    public function check(string $password, ?User $user = null): Result
    {
        $dictionaryFile = __DIR__ . '/_dictionary.txt';

        if (! file_exists($dictionaryFile)) {
            // No dictionary file — pass
            return (new Result())->setSuccess(true);
        }

        $fp = fopen($dictionaryFile, 'rb');
        if ($fp) {
            while (($line = fgets($fp, 4096)) !== false) {
                if (strtolower($password) === strtolower(trim($line))) {
                    fclose($fp);

                    return (new Result())
                        ->setSuccess(false)
                        ->setReason('This password is too common.')
                        ->setExtraInfo('Choose a less common password.');
                }
            }
            fclose($fp);
        }

        return (new Result())->setSuccess(true);
    }
}
