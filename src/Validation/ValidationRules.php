<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Validation;

use Enlivenapp\FlightShield\Passwords\Passwords;

/**
 * Provides validation rule sets for registration, login, and password fields.
 */
class ValidationRules
{
    protected array $config;

    public function __construct(array $config = [])
    {
        $this->config = $config;
    }

    /**
     * Returns validation rules for registration.
     */
    public function getRegistrationRules(): array
    {
        return [
            'username' => [
                'required'  => true,
                'min_length' => 3,
                'max_length' => 30,
                'pattern'    => '/^[a-zA-Z0-9.]+$/',
            ],
            'email' => [
                'required' => true,
                'email'    => true,
                'max_length' => 254,
            ],
            'password' => [
                'required'   => true,
                'min_length' => $this->config['min_length'] ?? 8,
            ],
            'password_confirm' => [
                'required' => true,
                'matches'  => 'password',
            ],
        ];
    }

    /**
     * Returns validation rules for login.
     */
    public function getLoginRules(): array
    {
        return [
            'email' => [
                'required' => true,
                'email'    => true,
                'max_length' => 254,
            ],
            'password' => [
                'required' => true,
            ],
        ];
    }

    /**
     * Returns validation rules for the password field.
     */
    public function getPasswordRules(): array
    {
        return [
            'required'   => true,
            'min_length' => $this->config['min_length'] ?? 8,
        ];
    }

    /**
     * Returns validation rules for the password confirmation field.
     */
    public function getPasswordConfirmRules(): array
    {
        return [
            'required' => true,
            'matches'  => 'password',
        ];
    }

    /**
     * Validate data against a rule set. Returns array of errors (empty = valid).
     */
    public function validate(array $data, array $rules): array
    {
        $errors = [];

        foreach ($rules as $field => $fieldRules) {
            $value = $data[$field] ?? null;

            if (! empty($fieldRules['required']) && (is_null($value) || $value === '')) {
                $errors[$field] = ucfirst($field) . ' is required.';
                continue;
            }

            if ($value === null || $value === '') {
                continue;
            }

            if (! empty($fieldRules['email']) && ! filter_var($value, FILTER_VALIDATE_EMAIL)) {
                $errors[$field] = 'Invalid email address.';
            }

            if (! empty($fieldRules['min_length']) && mb_strlen($value, 'UTF-8') < $fieldRules['min_length']) {
                $errors[$field] = ucfirst($field) . " must be at least {$fieldRules['min_length']} characters.";
            }

            if (! empty($fieldRules['max_length']) && mb_strlen($value, 'UTF-8') > $fieldRules['max_length']) {
                $errors[$field] = ucfirst($field) . " must be no more than {$fieldRules['max_length']} characters.";
            }

            if (! empty($fieldRules['pattern']) && ! preg_match($fieldRules['pattern'], $value)) {
                $errors[$field] = ucfirst($field) . ' contains invalid characters.';
            }

            if (! empty($fieldRules['matches'])) {
                $matchField = $fieldRules['matches'];
                if (($data[$matchField] ?? null) !== $value) {
                    $errors[$field] = ucfirst($field) . ' does not match ' . $matchField . '.';
                }
            }
        }

        return $errors;
    }
}
