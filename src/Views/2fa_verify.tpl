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
        .shield-resend-btn:disabled { color: #aaa; cursor: default; text-decoration: none; }
    </style>
</head>
<body>
    <div class="shield-card">
        <div class="shield-header">
            <img src="data:image/png;base64,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" alt="Flight Shield" class="shield-logo">
            <div class="shield-title">Flight Shield</div>
            <div class="shield-subtitle">Two-Factor Authentication</div>
        </div>

        {% if error %}
            <div class="shield-error">{{ error }}</div>
        {% endif %}

        {% if message %}
            <div class="shield-success">{{ message }}</div>
        {% endif %}

        <p class="shield-info">A verification code has been sent to your email. Enter it below.</p>

        <form method="post" action="/auth/2fa/verify">
            {% csrf_field %}

            <div class="shield-field">
                <label for="token">Verification Code</label>
                <input type="text" id="token" name="token" maxlength="6" required autofocus>
            </div>

            <button type="submit" class="shield-btn">Verify</button>
        </form>

        <div class="shield-resend">
            <form method="post" action="/auth/2fa/resend">
                {% csrf_field %}
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
