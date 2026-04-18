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
    <title>Two-Factor Authentication - Flight Shield</title>
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
        .shield-info { font-size: 0.875rem; color: #555; margin-bottom: 1.5rem; text-align: center; }
        .shield-error {
            background: #fee; border: 1px solid #fcc; border-radius: 6px;
            color: #c33; padding: 0.75rem 1rem; margin-bottom: 1.5rem; font-size: 0.875rem;
        }
        .shield-success {
            background: #f0f7f0; border: 1px solid #c3e6c3; border-radius: 6px;
            color: #2d6a2d; padding: 0.75rem 1rem; margin-bottom: 1.5rem; font-size: 0.875rem;
        }
        .shield-field { margin-bottom: 1.25rem; }
        .shield-field label { display: block; font-size: 0.875rem; font-weight: 600; color: #333; margin-bottom: 0.375rem; }
        .shield-field input[type="text"] {
            width: 100%; padding: 0.75rem 1rem; border: 1px solid #ddd;
            border-radius: 6px; font-size: 1.5rem; text-align: center; letter-spacing: 0.5rem;
            transition: border-color 0.2s; outline: none;
        }
        .shield-field input:focus { border-color: #0f3460; box-shadow: 0 0 0 3px rgba(15,52,96,0.1); }
        .shield-btn {
            width: 100%; padding: 0.75rem;
            background: linear-gradient(135deg, #0f3460, #1a1a2e);
            color: #fff; border: none; border-radius: 6px;
            font-size: 1rem; font-weight: 600; cursor: pointer; transition: opacity 0.2s;
        }
        .shield-btn:hover { opacity: 0.9; }
        .shield-resend { margin-top: 1.5rem; text-align: center; }
        .shield-resend-btn {
            background: none; border: none; color: #0f3460; font-size: 0.875rem;
            cursor: pointer; text-decoration: underline; padding: 0;
        }
        .shield-resend-btn:disabled {
            color: #aaa; cursor: default; text-decoration: none;
        }
    </style>
</head>
<body>
    <div class="shield-card">
        <div class="shield-header">
            <img src="<?= $shieldLogo ?>" alt="Flight Shield" class="shield-logo">
            <div class="shield-title">Flight Shield</div>
            <div class="shield-subtitle">Two-Factor Authentication</div>
        </div>

        <?php if (!empty($error)): ?>
            <div class="shield-error"><?= htmlspecialchars($error) ?></div>
        <?php endif; ?>

        <?php if (!empty($message)): ?>
            <div class="shield-success"><?= htmlspecialchars($message) ?></div>
        <?php endif; ?>

        <p class="shield-info">A verification code has been sent to your email. Enter it below.</p>

        <form method="post" action="/auth/2fa/verify">
            <?= csrf_field() ?>

            <div class="shield-field">
                <label for="token">Verification Code</label>
                <input type="text" id="token" name="token" maxlength="6" required autofocus>
            </div>

            <button type="submit" class="shield-btn">Verify</button>
        </form>

        <div class="shield-resend">
            <form method="post" action="/auth/2fa/resend">
                <?= csrf_field() ?>
                <button type="submit" class="shield-resend-btn" id="resendBtn" disabled>
                    Resend code (<span id="countdown">5:00</span>)
                </button>
            </form>
        </div>
    </div>

    <script>
        (function() {
            var seconds = 300;
            var btn = document.getElementById('resendBtn');
            var span = document.getElementById('countdown');
            var timer = setInterval(function() {
                seconds--;
                var m = Math.floor(seconds / 60);
                var s = seconds % 60;
                span.textContent = m + ':' + (s < 10 ? '0' : '') + s;
                if (seconds <= 0) {
                    clearInterval(timer);
                    btn.disabled = false;
                    btn.textContent = 'Resend code';
                }
            }, 1000);
        })();
    </script>
</body>
</html>
