<?php

declare(strict_types=1);

// Support both standalone (own vendor/) and project-level autoload
$autoload = __DIR__ . '/../vendor/autoload.php';
if (! file_exists($autoload)) {
    $autoload = __DIR__ . '/../../../autoload.php';
}
require_once $autoload;

spl_autoload_register(function (string $class) {
    $prefix = 'Enlivenapp\\FlightShield\\Tests\\';
    if (str_starts_with($class, $prefix)) {
        $file = __DIR__ . '/' . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
        if (file_exists($file)) {
            require_once $file;
        }
    }
});
