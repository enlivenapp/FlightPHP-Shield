<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Commands;

use flight\commands\AbstractBaseCommand;

class ShieldCommand extends AbstractBaseCommand
{
    public function __construct(array $config)
    {
        parent::__construct('shield', 'Flight Shield — authentication & authorization CLI', $config);

        $this->usage(
            '<bold>Available commands:</end><eol/>' .
            '<eol/>' .
            '<bold>  shield:user</end>         <comment>Manage users (create, activate, delete, password, groups)</end><eol/>' .
            '<bold>  shield:group</end>        <comment>Manage groups (list, create, update, delete, permissions)</end><eol/>' .
            '<bold>  shield:permission</end>   <comment>Manage permissions (list, create, update, delete)</end><eol/>' .
            '<bold>  shield:hmac</end>         <comment>HMAC API Authentication — Key & Token Management</end><eol/>' .
            '<eol/>' .
            '<comment>Run any command without arguments to see its help.</end>'
        );
    }

    public function execute(): void
    {
        $this->showHelp();
    }
}
