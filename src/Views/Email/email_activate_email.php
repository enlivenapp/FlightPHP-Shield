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
                            <h2 style="margin: 0 0 10px; color: #1a1a2e; font-size: 18px;">Activate Your Account</h2>
                            <p style="color: #555; font-size: 14px; line-height: 1.6; margin: 0 0 20px;">Click the button below to activate your account:</p>
                            <div style="text-align: center; margin-bottom: 20px;">
                                <a href="<?= htmlspecialchars($activationUrl ?? '') ?>" style="display: inline-block; padding: 12px 30px; background: linear-gradient(135deg, #0f3460, #1a1a2e); color: #fff; text-decoration: none; border-radius: 6px; font-size: 16px; font-weight: 600;">Activate Account</a>
                            </div>
                            <p style="color: #555; font-size: 14px; line-height: 1.6; margin: 0 0 10px;">Or copy this link into your browser:</p>
                            <p style="color: #0f3460; font-size: 12px; word-break: break-all; margin: 0 0 20px;"><?= htmlspecialchars($activationUrl ?? '') ?></p>
                            <p style="color: #555; font-size: 14px; line-height: 1.6; margin: 0;">This link will expire in 24 hours. If you did not create an account, please ignore this email.</p>
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
