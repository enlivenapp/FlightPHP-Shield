<?php

/**
 * @package   Enlivenapp\FlightShield
 * @copyright 2026 enlivenapp
 * @license   MIT
 */ $shieldLogo = 'data:image/png;base64,' . base64_encode(file_get_contents(dirname(__DIR__, 2) . '/flight-shield.png')); ?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Activate Account - Flight Shield</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 2rem;
        }
        .shield-card {
            background: #fff;
            border-radius: 12px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            width: 100%;
            max-width: 420px;
            padding: 2.5rem;
        }
        .shield-header { text-align: center; margin-bottom: 2rem; }
        .shield-logo { width: 100px; height: auto; margin-bottom: 0.5rem; }
        .shield-title { font-size: 1.5rem; font-weight: 700; color: #1a1a2e; margin-bottom: 0.25rem; }
        .shield-subtitle { font-size: 0.875rem; color: #888; }
        .shield-error {
            background: #fee; border: 1px solid #fcc; border-radius: 6px;
            color: #c33; padding: 0.75rem 1rem; margin-bottom: 1.5rem; font-size: 0.875rem;
        }
        .shield-message {
            background: #f0f7f0; border: 1px solid #c3e6c3; border-radius: 6px;
            color: #2d6a2d; padding: 1rem; font-size: 0.875rem;
            text-align: center;
        }
        .shield-links { margin-top: 1.5rem; text-align: center; font-size: 0.875rem; }
        .shield-links a { color: #0f3460; text-decoration: none; }
        .shield-links a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="shield-card">
        <div class="shield-header">
            <img src="<?= $shieldLogo ?>" alt="Flight Shield" class="shield-logo">
            <div class="shield-title">Flight Shield</div>
            <div class="shield-subtitle">Activate Your Account</div>
        </div>

        <?php if (!empty($error)): ?>
            <div class="shield-error"><?= htmlspecialchars($error) ?></div>
        <?php endif; ?>

        <div class="shield-message">
            We've sent an activation link to your email address. Please check your inbox and click the link to activate your account.
        </div>

        <div class="shield-links">
            <p><a href="/auth/login">Back to sign in</a></p>
        </div>
    </div>
</body>
</html>
