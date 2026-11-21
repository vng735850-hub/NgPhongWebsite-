
import os
import re
import time
import secrets
from collections import defaultdict
from datetime import datetime
from flask import (
    Flask, request, session, redirect,
    url_for, render_template_string, abort
)

# ==========================================
# PHONG FF CHECKER V1.0
# FREE FIRE UID CHECKER
# WHITE EDITION
# ==========================================

app = Flask(__name__)

app.secret_key = os.environ.get(
    "SECRET_KEY",
    secrets.token_hex(32)
)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
    MAX_CONTENT_LENGTH=16 * 1024
)

APP_NAME = "PHONG FF CHECKER"
VERSION = "1.0"

# Rate limit: số lần gửi tối đa trong một phút
REQUEST_LIMIT = 15
REQUEST_WINDOW = 60

requests_log = defaultdict(list)


# ==========================================
# SECURITY
# ==========================================

@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    return response


def check_rate_limit():
    ip = request.remote_addr or "unknown"
    now = time.time()

    requests_log[ip] = [
        t for t in requests_log[ip]
        if now - t < REQUEST_WINDOW
    ]

    if len(requests_log[ip]) >= REQUEST_LIMIT:
        return False

    requests_log[ip].append(now)
    return True


def get_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)

    return session["csrf_token"]


def validate_csrf():
    token = request.form.get("csrf_token", "")

    if not secrets.compare_digest(
        token,
        session.get("csrf_token", "")
    ):
        abort(400, description="Yêu cầu không hợp lệ.")


# ==========================================
# UID VALIDATION
# ==========================================

def validate_uid(uid):
    if not uid:
        return False, "Vui lòng nhập UID Free Fire."

    uid = uid.strip()

    if not re.fullmatch(r"[0-9]{5,20}", uid):
        return False, "UID phải gồm 5 đến 20 chữ số."

    return True, "UID có định dạng hợp lệ."


# ==========================================
# HTML TEMPLATE
# ==========================================

HTML = """
<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">

<title>{{ title }} - PHONG FF CHECKER</title>

<style>
* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: Arial, sans-serif;
    background: #f5f7fa;
    color: #202938;
}

.navbar {
    background: white;
    padding: 17px 7%;
    display: flex;
    align-items: center;
    justify-content: space-between;
    border-bottom: 1px solid #e9edf2;
}

.logo {
    font-size: 21px;
    font-weight: 800;
    color: #16a34a;
}

.nav-links a {
    text-decoration: none;
    color: #475569;
    margin-left: 20px;
    font-size: 14px;
}

.container {
    max-width: 850px;
    margin: 55px auto;
    padding: 0 18px;
}

.hero {
    text-align: center;
    margin-bottom: 32px;
}

.hero h1 {
    font-size: 34px;
    font-weight: 800;
    margin-bottom: 12px;
}

.hero h1 span {
    color: #16a34a;
}

.hero p {
    color: #64748b;
    font-size: 15px;
    line-height: 1.6;
}

.card {
    background: white;
    padding: 30px;
    border-radius: 15px;
    border: 1px solid #e8edf2;
    box-shadow: 0 8px 30px rgba(15,23,42,0.04);
    margin-bottom: 22px;
}

.card h2 {
    font-size: 20px;
    margin-bottom: 20px;
}

.input-label {
    display: block;
    font-weight: 700;
    font-size: 14px;
    margin-bottom: 10px;
}

input {
    width: 100%;
    padding: 15px;
    border: 1px solid #dce3eb;
    border-radius: 9px;
    outline: none;
    font-size: 16px;
    background: #fff;
}

input:focus {
    border-color: #16a34a;
    box-shadow: 0 0 0 3px rgba(22,163,74,.1);
}

button {
    width: 100%;
    border: none;
    background: #16a34a;
    color: white;
    padding: 15px;
    border-radius: 9px;
    margin-top: 16px;
    font-size: 15px;
    font-weight: 700;
    cursor: pointer;
}

button:hover {
    background: #15803d;
}

.result {
    padding: 18px;
    background: #f0fdf4;
    border: 1px solid #bbf7d0;
    border-radius: 10px;
    margin-top: 20px;
    line-height: 1.8;
}

.error {
    background: #fef2f2;
    border: 1px solid #fecaca;
    color: #b91c1c;
    padding: 15px;
    border-radius: 9px;
    margin-top: 18px;
}

.status {
    display: inline-block;
    padding: 5px 10px;
    border-radius: 30px;
    background: #dcfce7;
    color: #15803d;
    font-size: 12px;
    font-weight: bold;
}

.features {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 14px;
}

.feature {
    background: white;
    padding: 20px 12px;
    border: 1px solid #e8edf2;
    border-radius: 12px;
    text-align: center;
}

.feature .icon {
    font-size: 25px;
    margin-bottom: 10px;
}

.feature strong {
    display: block;
    font-size: 13px;
}

.feature small {
    color: #64748b;
    display: block;
    margin-top: 7px;
    font-size: 11px;
}

.history-item {
    padding: 13px;
    border-bottom: 1px solid #edf0f4;
    display: flex;
    justify-content: space-between;
    gap: 10px;
}

.history-item:last-child {
    border-bottom: none;
}

.footer {
    text-align: center;
    color: #94a3b8;
    font-size: 12px;
    padding: 30px 10px;
}

.small-button {
    background: #64748b;
    padding: 10px;
    font-size: 13px;
}

@media(max-width:600px) {
    .navbar {
        padding: 16px;
    }

    .logo {
        font-size: 16px;
    }

    .nav-links a {
        margin-left: 10px;
        font-size: 12px;
    }

    .container {
        margin-top: 35px;
    }

    .hero h1 {
        font-size: 26px;
    }

    .card {
        padding: 20px;
    }

    .features {
        grid-template-columns: 1fr;
    }
}
</style>
</head>

<body>

<div class="navbar">
    <div class="logo">⚡ PHONG FF</div>

    <div class="nav-links">
        <a href="/">Trang chủ</a>
        <a href="/history">Lịch sử</a>
        <a href="/health">System</a>
    </div>
</div>

<div class="container">

{% if page == "home" %}

<div class="hero">
    <h1>FREE FIRE <span>CHECKER</span></h1>
    <p>
        Hệ thống kiểm tra định dạng UID Free Fire.<br>
        Nhanh chóng, đơn giản và an toàn.
    </p>
</div>

<div class="card">
    <h2>🔍 Kiểm tra UID</h2>

    <form method="POST" action="/check">
        <input type="hidden" name="csrf_token" value="{{ csrf }}">

        <label class="input-label">Nhập UID Free Fire</label>

        <input
            type="text"
            name="uid"
            placeholder="Ví dụ: 123456789"
            maxlength="20"
            inputmode="numeric"
            autocomplete="off"
            required
        >

        <button type="submit">CHECK UID NGAY</button>
    </form>

    {% if result %}
        <div class="{{ result_type }}">
            <strong>{{ result_title }}</strong><br>
            {{ result }}
            {% if checked_uid %}
                <br>UID: <strong>{{ checked_uid }}</strong>
            {% endif %}
        </div>
    {% endif %}
</div>

<div class="features">

    <div class="feature">
        <div class="icon">🔎</div>
        <strong>UID Checker</strong>
        <small>Kiểm tra định dạng UID</small>
    </div>

    <div class="feature">
        <div class="icon">🛡️</div>
        <strong>Safe System</strong>
        <small>Không lấy mật khẩu</small>
    </div>

    <div class="feature">
        <div class="icon">⚡</div>
        <strong>Fast Response</strong>
        <small>Phản hồi nhanh</small>
    </div>

</div>

{% elif page == "history" %}

<div class="hero">
    <h1>UID <span>HISTORY</span></h1>
    <p>Lịch sử kiểm tra trên trình duyệt hiện tại.</p>
</div>

<div class="card">
    <h2>📋 Lịch sử UID</h2>

    {% if history %}
        {% for item in history %}
        <div class="history-item">
            <strong>{{ item.uid }}</strong>
            <small>{{ item.time }}</small>
        </div>
        {% endfor %}

        <form method="POST" action="/history/clear">
            <input type="hidden" name="csrf_token" value="{{ csrf }}">
            <button class="small-button" type="submit">
                Xóa lịch sử
            </button>
        </form>
    {% else %}
        <p style="color:#94a3b8">Chưa có UID nào được kiểm tra.</p>
    {% endif %}
</div>

{% elif page == "health" %}

<div class="hero">
    <h1>SYSTEM <span>STATUS</span></h1>
    <p>Trạng thái hoạt động của PHONG FF CHECKER.</p>
</div>

<div class="card">
    <h2>⚙️ System Information</h2>
    <p>Website: <strong>Online</strong></p>
    <p>Version: <strong>{{ version }}</strong></p>
    <p>Framework: <strong>Python Flask</strong></p>
    <p>UID Validation: <strong>Enabled</strong></p>
    <p>External API: <strong>Not configured</strong></p>
    <p>Account Login: <strong>Disabled</strong></p>
</div>

{% endif %}

</div>

<div class="footer">
    PHONG FF CHECKER V1.0<br>
    Independent UID format checker. Not affiliated with Garena.
</div>

</body>
</html>
"""


# ==========================================
# HOME
# ==========================================

@app.route("/", methods=["GET"])
def home():
    return render_template_string(
        HTML,
        title="Trang chủ",
        page="home",
        csrf=get_csrf_token(),
        result=None,
        result_type="result",
        result_title="",
        checked_uid=None
    )


# ==========================================
# CHECK UID
# ==========================================

@app.route("/check", methods=["POST"])
def check_uid():

    validate_csrf()

    if not check_rate_limit():
        return render_template_string(
            HTML,
            title="Trang chủ",
            page="home",
            csrf=get_csrf_token(),
            result="Bạn đã gửi quá nhiều yêu cầu. Vui lòng thử lại sau.",
            result_type="error",
            result_title="Giới hạn yêu cầu",
            checked_uid=None
        ), 429

    uid = request.form.get("uid", "").strip()

    valid, message = validate_uid(uid)

    result_type = "result" if valid else "error"

    if valid:
        history = session.get("history", [])

        history.insert(0, {
            "uid": uid,
            "time": datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        })

        session["history"] = history[:20]

        result_title = "✓ Định dạng UID hợp lệ"
        result = (
            "UID đã vượt qua bước kiểm tra định dạng. "
            "Chưa có API Garena để xác minh tài khoản thực tế."
        )

    else:
        result_title = "✕ UID không hợp lệ"
        result = message

    return render_template_string(
        HTML,
        title="Kết quả",
        page="home",
        csrf=get_csrf_token(),
        result=result,
        result_type=result_type,
        result_title=result_title,
        checked_uid=uid if valid else None
    )


# ==========================================
# HISTORY
# ==========================================

@app.route("/history", methods=["GET"])
def history():

    return render_template_string(
        HTML,
        title="Lịch sử",
        page="history",
        csrf=get_csrf_token(),
        history=session.get("history", [])
    )


@app.route("/history/clear", methods=["POST"])
def clear_history():

    validate_csrf()

    session["history"] = []

    return redirect(url_for("history"))


# ==========================================
# SYSTEM STATUS
# ==========================================

@app.route("/health", methods=["GET"])
def health():

    return render_template_string(
        HTML,
        title="System",
        page="health",
        version=VERSION
    )


# ==========================================
# ERROR HANDLERS
# ==========================================

@app.errorhandler(400)
def bad_request(error):
    return "400 - Yêu cầu không hợp lệ.", 400


@app.errorhandler(404)
def not_found(error):
    return "404 - Không tìm thấy trang.", 404


@app.errorhandler(413)
def too_large(error):
    return "413 - Dữ liệu gửi lên quá lớn.", 413


@app.errorhandler(429)
def too_many(error):
    return "429 - Quá nhiều yêu cầu.", 429


# ==========================================
# START SERVER
# ==========================================

if __name__ == "__main__":

    port = int(os.environ.get("PORT", 5000))

    app.run(
        host="0.0.0.0",
        port=port,
        debug=False
    )
