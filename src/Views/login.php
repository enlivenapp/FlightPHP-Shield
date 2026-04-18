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
    <title>Login - Flight Shield</title>
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
        .shield-header {
            text-align: center;
            margin-bottom: 2rem;
        }
        .shield-logo {
            width: 100px;
            height: auto;
            margin-bottom: 0.5rem;
        }
        .shield-title {
            font-size: 1.5rem;
            font-weight: 700;
            color: #1a1a2e;
            margin-bottom: 0.25rem;
        }
        .shield-subtitle {
            font-size: 0.875rem;
            color: #888;
        }
        .shield-error {
            background: #fee;
            border: 1px solid #fcc;
            border-radius: 6px;
            color: #c33;
            padding: 0.75rem 1rem;
            margin-bottom: 1.5rem;
            font-size: 0.875rem;
        }
        .shield-field {
            margin-bottom: 1.25rem;
        }
        .shield-field label {
            display: block;
            font-size: 0.875rem;
            font-weight: 600;
            color: #333;
            margin-bottom: 0.375rem;
        }
        .shield-field input[type="text"],
        .shield-field input[type="email"],
        .shield-field input[type="password"] {
            width: 100%;
            padding: 0.75rem 1rem;
            border: 1px solid #ddd;
            border-radius: 6px;
            font-size: 1rem;
            transition: border-color 0.2s;
            outline: none;
        }
        .shield-field input:focus {
            border-color: #0f3460;
            box-shadow: 0 0 0 3px rgba(15,52,96,0.1);
        }
        .shield-remember {
            margin-bottom: 1.5rem;
        }
        .shield-remember label {
            font-size: 0.875rem;
            color: #555;
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        .shield-btn {
            width: 100%;
            padding: 0.75rem;
            background: linear-gradient(135deg, #0f3460, #1a1a2e);
            color: #fff;
            border: none;
            border-radius: 6px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: opacity 0.2s;
        }
        .shield-btn:hover {
            opacity: 0.9;
        }
        .shield-links {
            margin-top: 1.5rem;
            text-align: center;
            font-size: 0.875rem;
        }
        .shield-links a {
            color: #0f3460;
            text-decoration: none;
        }
        .shield-links a:hover {
            text-decoration: underline;
        }
        .shield-links p {
            margin-top: 0.5rem;
        }
    </style>
</head>
<body>
    <div class="shield-card">
        <div class="shield-header">
            <img src="<?= $shieldLogo ?>" alt="Flight Shield" class="shield-logo">
            <div class="shield-title">Flight Shield</div>
            <div class="shield-subtitle">Sign in to your account</div>
        </div>

        <?php if (!empty($error)): ?>
            <div class="shield-error"><?= htmlspecialchars($error) ?></div>
        <?php endif; ?>

        <form method="post" action="/auth/login">
            <?= csrf_field() ?>

            <?php if (in_array('username', $config['valid_login_fields'] ?? [])): ?>
                <div class="shield-field">
                    <label for="username">Username</label>
                    <input type="text" id="username" name="username" required>
                </div>
            <?php endif; ?>

            <div class="shield-field">
                <label for="email">Email</label>
                <input type="email" id="email" name="email" required>
            </div>

            <div class="shield-field">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required>
            </div>

            <?php if ($config['session']['allow_remembering'] ?? true): ?>
                <div class="shield-remember">
                    <label>
                        <input type="checkbox" name="remember" value="1"> Remember me
                    </label>
                </div>
            <?php endif; ?>

            <button type="submit" class="shield-btn">Sign In</button>
        </form>

        <div class="shield-links">
            <?php if ($config['allow_magic_link'] ?? false): ?>
                <p><a href="/auth/magic-link">Sign in with Magic Link</a></p>
            <?php endif; ?>
            <?php if ($config['allow_registration'] ?? true): ?>
                <p><a href="/auth/register">Create an account</a></p>
            <?php endif; ?>
        </div>
    </div>
</body>
</html>
