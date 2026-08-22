<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Commands;

use Enlivenapp\FlightShield\Authentication\HMAC\HmacEncrypter;
use Enlivenapp\FlightShield\Models\UserIdentity;
use Enlivenapp\FlightShield\Exceptions\RuntimeException;
use flight\commands\AbstractBaseCommand;

class ShieldHmacCommand extends AbstractBaseCommand
{
    public function __construct(array $config)
    {
        parent::__construct('shield:hmac', 'HMAC API Authentication — Key & Token Management', $config);

        $this
            ->argument('[action]', 'Action: init, listkeys, addkey, removekey, encrypt, decrypt, reencrypt, invalidateAll')
            ->option('-k --key', 'Key ID (for removekey)')
            ->usage(
                '<comment>HMAC lets API clients authenticate by signing requests with a shared</end><eol/>' .
                '<comment>secret instead of session cookies or bearer tokens. Each client\'s</end><eol/>' .
                '<comment>secret is stored in the database. These commands manage the encryption</end><eol/>' .
                '<comment>keys that protect those secrets at rest, and control token lifecycle.</end><eol/>' .
                '<eol/>' .
                '<bold>Setup:</end><eol/>' .
                '<bold>  shield:hmac init</end>           <comment>Set up encryption to protect API secrets in the database</end><eol/>' .
                '<bold>  shield:hmac listkeys</end>       <comment>Show all encryption keys and which one is active</end><eol/>' .
                '<bold>  shield:hmac addkey</end>         <comment>Add a new encryption key and set it as active (for key rotation)</end><eol/>' .
                '<bold>  shield:hmac removekey</end>      <comment>Remove an old key after migrating secrets with reencrypt</end> <eol/>' .
                '<eol/>' .
                '<bold>Database:</end><eol/>' .
                '<bold>  shield:hmac encrypt</end>        <comment>Protect any unencrypted API secrets in the database</end><eol/>' .
                '<bold>  shield:hmac decrypt</end>        <comment>Remove encryption from API secrets in the database</end><eol/>' .
                '<bold>  shield:hmac reencrypt</end>      <comment>Migrate all API secrets to use the active encryption key</end><eol/>' .
                '<eol/>' .
                '<bold>Tokens:</end><eol/>' .
                '<bold>  shield:hmac invalidateAll</end>  <comment>Revoke all API tokens immediately (clients must request new ones)</end><eol/>' .
                '<eol/>' .
                '<comment>Key rotation workflow: listkeys → addkey → reencrypt → removekey</end>'
            );
    }

    public function execute(?string $action = null, ?string $key = null): void
    {
        $io = $this->app()->io();

        if ($action === null) {
            $this->showHelp();
            return;
        }

        $config = $this->getShieldConfig();

        try {
            match ($action) {
                'init'          => $this->init($config, $io),
                'listkeys'      => $this->listKeys($config, $io),
                'addkey'        => $this->addKey($config, $io),
                'removekey'     => $this->removeKey($config, $io, $key),
                'encrypt'       => $this->encryptAll($config, $io),
                'decrypt'       => $this->decryptAll($config, $io),
                'reencrypt'     => $this->reEncryptAll($config, $io),
                'invalidateAll' => $this->invalidateAll($io),
                default         => $io->error("Unknown action: {$action}", true),
            };
        } catch (RuntimeException $e) {
            $io->error($e->getMessage(), true);
            $io->write('Run "php runway shield:hmac init" to set up HMAC encryption.', true);
        }
    }

    protected function init(array $config, $io): void
    {
        $hmac = $config['hmac'] ?? [];

        if (!empty($hmac['encryption_current_key']) && !empty($hmac['encryption_keys'][$hmac['encryption_current_key']])) {
            $io->write('HMAC encryption keys are already configured.', true);
            return;
        }

        $keyId = 'k1';
        $secret = base64_encode(random_bytes(32));

        $configFile = $this->getConfigFilePath();
        $contents = $this->readConfigFile($configFile, $io);
        if ($contents === null) {
            return;
        }

        // Replace the empty encryption_keys array
        $contents = preg_replace(
            "/('encryption_keys'\s*=>\s*\[)\s*(\],)/s",
            "$1\n\t\t\t\t\t'{$keyId}' => '{$secret}',\n\t\t\t\t$2",
            $contents
        );

        // Set the current key
        $contents = preg_replace(
            "/'encryption_current_key'\s*=>\s*''/",
            "'encryption_current_key' => '{$keyId}'",
            $contents
        );

        if (!$this->writeConfigFile($configFile, $contents, $io)) {
            return;
        }

        $io->info("HMAC encryption key '{$keyId}' generated and written to config.", true);
    }

    protected function listKeys(array $config, $io): void
    {
        $hmac = $config['hmac'] ?? [];
        $keys = $hmac['encryption_keys'] ?? [];
        $currentKey = $hmac['encryption_current_key'] ?? '';

        if (empty($keys)) {
            $io->write('No encryption keys configured. Run "php runway shield:hmac init" to get started.', true);
            return;
        }

        $io->bold('Key ID          Status', true);
        foreach ($keys as $keyId => $secret) {
            $status = ($keyId === $currentKey) ? 'active' : 'inactive';
            $io->write("  {$keyId}              {$status}", true);
        }
    }

    protected function addKey(array $config, $io): void
    {
        $hmac = $config['hmac'] ?? [];
        $keys = $hmac['encryption_keys'] ?? [];

        if (empty($keys)) {
            $io->error('No keys configured yet. Run "php runway shield:hmac init" first.', true);
            return;
        }

        // Determine next key ID (k1 → k2 → k3...)
        $maxNum = 0;
        foreach (array_keys($keys) as $existingId) {
            if (preg_match('/^k(\d+)$/', $existingId, $m)) {
                $maxNum = max($maxNum, (int) $m[1]);
            }
        }
        $newKeyId = 'k' . ($maxNum + 1);
        $newSecret = base64_encode(random_bytes(32));

        $configFile = $this->getConfigFilePath();
        $contents = $this->readConfigFile($configFile, $io);
        if ($contents === null) {
            return;
        }

        // Add new key after last existing key in the encryption_keys array
        $contents = preg_replace(
            "/(encryption_keys.*?\n)((\s*'k\d+'\s*=>.*?\n)*?)(\s*\],)/s",
            "$1$2\t\t\t\t\t'{$newKeyId}' => '{$newSecret}',\n$4",
            $contents
        );

        // Update current key
        $contents = preg_replace(
            "/'encryption_current_key'\s*=>\s*'[^']*'/",
            "'encryption_current_key' => '{$newKeyId}'",
            $contents
        );

        if (!$this->writeConfigFile($configFile, $contents, $io)) {
            return;
        }

        $io->info("Encryption key '{$newKeyId}' added and set as active.", true);
        $io->write('Run "php runway shield:hmac reencrypt" to migrate existing secrets to the new key.', true);
    }

    protected function removeKey(array $config, $io, ?string $keyId): void
    {
        if ($keyId === null) {
            $io->error('Key ID is required (-k keyid).', true);
            return;
        }

        $hmac = $config['hmac'] ?? [];
        $keys = $hmac['encryption_keys'] ?? [];
        $currentKey = $hmac['encryption_current_key'] ?? '';

        if (!isset($keys[$keyId])) {
            $io->error("Key '{$keyId}' not found.", true);
            return;
        }

        if ($keyId === $currentKey) {
            $io->error("Cannot remove the active key '{$keyId}'. Add a new key first.", true);
            return;
        }

        $configFile = $this->getConfigFilePath();
        $contents = $this->readConfigFile($configFile, $io);
        if ($contents === null) {
            return;
        }

        // Remove the key line
        $contents = preg_replace(
            "/\s*'" . preg_quote($keyId, '/') . "'\s*=>.*?,?\n/",
            "\n",
            $contents
        );

        if (!$this->writeConfigFile($configFile, $contents, $io)) {
            return;
        }

        $io->info("Encryption key '{$keyId}' removed.", true);
    }

    protected function getConfigFilePath(): string
    {
        $projectRoot = defined('PROJECT_ROOT') ? PROJECT_ROOT : dirname(__DIR__, 5);
        return $projectRoot . '/app/config/config.php';
    }

    protected function readConfigFile(string $configFile, $io): ?string
    {
        $contents = file_get_contents($configFile);
        if ($contents === false) {
            $io->error("Unable to read config file: {$configFile}", true);
            return null;
        }
        return $contents;
    }

    protected function writeConfigFile(string $configFile, string $contents, $io): bool
    {
        if (file_put_contents($configFile, $contents) === false) {
            $io->error("Unable to write config file: {$configFile}", true);
            return false;
        }
        return true;
    }

    protected function encryptAll(array $config, $io): void
    {
        $encrypter  = new HmacEncrypter($config);
        $identities = (new UserIdentity(\Flight::db()))->eq('type', UserIdentity::TYPE_HMAC_TOKEN)->findAll();

        foreach ($identities as $identity) {
            if ($encrypter->isEncrypted($identity->secret2)) {
                $io->write("id: {$identity->id}, already encrypted, skipped.", true);
                continue;
            }

            $identity->secret2 = $encrypter->encrypt($identity->secret2);
            $identity->save();
            $io->info("id: {$identity->id}, encrypted.", true);
        }
    }

    protected function decryptAll(array $config, $io): void
    {
        $encrypter  = new HmacEncrypter($config);
        $identities = (new UserIdentity(\Flight::db()))->eq('type', UserIdentity::TYPE_HMAC_TOKEN)->findAll();

        foreach ($identities as $identity) {
            if (! $encrypter->isEncrypted($identity->secret2)) {
                $io->write("id: {$identity->id}, not encrypted, skipped.", true);
                continue;
            }

            $identity->secret2 = $encrypter->decrypt($identity->secret2);
            $identity->save();
            $io->info("id: {$identity->id}, decrypted.", true);
        }
    }

    protected function reEncryptAll(array $config, $io): void
    {
        $encrypter  = new HmacEncrypter($config);
        $identities = (new UserIdentity(\Flight::db()))->eq('type', UserIdentity::TYPE_HMAC_TOKEN)->findAll();

        foreach ($identities as $identity) {
            if ($encrypter->isEncryptedWithCurrentKey($identity->secret2)) {
                $io->write("id: {$identity->id}, already on current key, skipped.", true);
                continue;
            }

            $identity->secret2 = $encrypter->encrypt(
                $encrypter->decrypt($identity->secret2)
            );
            $identity->save();
            $io->info("id: {$identity->id}, re-encrypted.", true);
        }
    }

    protected function invalidateAll($io): void
    {
        $identities = (new UserIdentity(\Flight::db()))->eq('type', UserIdentity::TYPE_HMAC_TOKEN)->findAll();

        $now = (new \DateTimeImmutable())->format('Y-m-d H:i:s');

        foreach ($identities as $identity) {
            if ($identity->expires !== null && $identity->expires < $now) {
                $io->write("id: {$identity->id}, already expired, skipped.", true);
                continue;
            }

            $identity->expires = $now;
            $identity->save();
            $io->info("id: {$identity->id}, set as expired.", true);
        }
    }

    protected function getShieldConfig(): array
    {
        return \Flight::app()->get('enlivenapp.flight-shield') ?? [];
    }
}
