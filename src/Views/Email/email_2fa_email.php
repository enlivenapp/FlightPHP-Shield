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
</head>
<body style="margin: 0; padding: 0; background: #f4f4f7; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;">
    <table width="100%" cellpadding="0" cellspacing="0" style="background: #f4f4f7; padding: 40px 20px;">
        <tr>
            <td align="center">
                <table width="420" cellpadding="0" cellspacing="0" style="background: #fff; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.08); overflow: hidden;">
                    <tr>
                        <td style="background: linear-gradient(135deg, #1a1a2e, #0f3460); padding: 30px; text-align: center;">
                            <img src="<?= $shieldLogo ?>" alt="Flight Shield" width="60" style="margin-bottom: 8px;">
                            <div style="color: #fff; font-size: 20px; font-weight: 700;">Flight Shield</div>
                        </td>
                    </tr>
                    <tr>
                        <td style="padding: 30px;">
                            <h2 style="margin: 0 0 10px; color: #1a1a2e; font-size: 18px;">Your Verification Code</h2>
                            <p style="color: #555; font-size: 14px; line-height: 1.6; margin: 0 0 20px;">Your two-factor authentication code is:</p>
                            <div style="background: #f4f4f7; border-radius: 8px; padding: 20px; text-align: center; margin-bottom: 20px;">
                                <span style="font-size: 32px; font-weight: 700; letter-spacing: 8px; color: #1a1a2e;"><?= htmlspecialchars($code) ?></span>
                            </div>
                            <p style="color: #555; font-size: 14px; line-height: 1.6; margin: 0 0 20px;">This code will expire in 10 minutes. If you did not request this code, please ignore this email.</p>
                        </td>
                    </tr>
                    <tr>
                        <td style="padding: 0 30px 20px; border-top: 1px solid #eee;">
                            <p style="color: #999; font-size: 11px; margin: 15px 0 0;">
                                IP: <?= htmlspecialchars($ipAddress ?? '') ?> |
                                Date: <?= htmlspecialchars($date ?? '') ?>
                            </p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>
