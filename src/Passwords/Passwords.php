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
 * Central location for password hashing, verifying, and validating.
 * Ported from CodeIgniter Shield.
 */
class Passwords
{
    protected array $config;

    public function __construct(array $config = [])
    {
        $this->config = array_merge([
            'algorithm'    => PASSWORD_DEFAULT,
            'cost'         => 12,
            'memory_cost'  => 65536,
            'time_cost'    => 4,
            'threads'      => 1,
            'min_length'   => 8,
            'max_similarity' => 50,
            'validators'   => [
                CompositionValidator::class,
                NothingPersonalValidator::class,
                DictionaryValidator::class,
            ],
        ], $config);
    }

    public function hash(string $password): string|false
    {
        return password_hash($password, $this->config['algorithm'], $this->getHashOptions());
    }

    public function verify(string $password, string $hash): bool
    {
        return password_verify($password, $hash);
    }

    public function needsRehash(string $hashedPassword): bool
    {
        return password_needs_rehash($hashedPassword, $this->config['algorithm'], $this->getHashOptions());
    }

    /**
     * Run the password through all configured validators.
     */
    public function check(string $password, ?User $user = null): Result
    {
        if ($password === '') {
            return (new Result())
                ->setSuccess(false)
                ->setReason('Password cannot be empty.');
        }

        foreach ($this->config['validators'] as $className) {
            /** @var ValidatorInterface $validator */
            $validator = new $className($this->config);
            $result = $validator->check($password, $user);

            if (! $result->isOK()) {
                return $result;
            }
        }

        return (new Result())->setSuccess(true);
    }

    protected function getHashOptions(): array
    {
        $algo = $this->config['algorithm'];

        if (
            (defined('PASSWORD_ARGON2I') && $algo === PASSWORD_ARGON2I)
            || (defined('PASSWORD_ARGON2ID') && $algo === PASSWORD_ARGON2ID)
        ) {
            return [
                'memory_cost' => $this->config['memory_cost'],
                'time_cost'   => $this->config['time_cost'],
                'threads'     => $this->config['threads'],
            ];
        }

        return [
            'cost' => $this->config['cost'],
        ];
    }
}
