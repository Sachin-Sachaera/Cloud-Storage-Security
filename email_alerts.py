"""
email_alerts.py
------------------
Sends real login-alert emails via SMTP ("Was this you?" security notice),
the same pattern Google/Microsoft/banking apps use for new-device logins.

SMTP credentials are read from environment variables so secrets never sit
in source code:

    SMTP_HOST       e.g. smtp.gmail.com
    SMTP_PORT       e.g. 587
    SMTP_USERNAME   the sending account, e.g. your gmail address
    SMTP_PASSWORD   an APP PASSWORD (not your normal Gmail password —
                    generate one at https://myaccount.google.com/apppasswords,
                    requires 2-Step Verification to be turned on)
    SMTP_FROM       optional, defaults to SMTP_USERNAME

Set them before running, e.g. (Linux/Mac):
    export SMTP_HOST=smtp.gmail.com
    export SMTP_PORT=587
    export SMTP_USERNAME=youraddress@gmail.com
    export SMTP_PASSWORD=your16charapppassword

If SMTP is not configured (or sending fails, e.g. no internet in a sandbox),
the alert is NOT lost — it's recorded in the in-app "Security Alerts" log
(see app.py: ALERT_LOG) so the feature is still fully demoable offline.
"""

import os
import smtplib
import ssl
from datetime import datetime
from email.mime.text import MIMEText

SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USERNAME = os.environ.get("SMTP_USERNAME", "YOUR_MAILID")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "GMAIL SMPT PASSWORD")
SMTP_FROM = os.environ.get("SMTP_FROM", SMTP_USERNAME)


def smtp_configured() -> bool:
    return bool(SMTP_HOST and SMTP_USERNAME and SMTP_PASSWORD)


def build_login_alert_email(
    full_name: str,
    username: str,
    ip_address: str,
    timestamp: str,
) -> MIMEText:
    body = f"""Hi {full_name},

A login to your CloudGuard family account was just detected.

    Account:    {username}
    Time:       {timestamp}
    IP Address: {ip_address}

If this was you, no action is needed.

If this was NOT you, please change your password immediately from the
CloudGuard dashboard and review the Security Alerts log for other
suspicious activity.

— CloudGuard Integrated Cloud Security Framework
"""

    msg = MIMEText(body)
    msg["Subject"] = f"[CloudGuard] New login to {username} — was this you?"
    msg["From"] = SMTP_FROM
    return msg


def send_login_alert(
    to_email: str,
    full_name: str,
    username: str,
    ip_address: str,
) -> dict:
    """Send a login alert email; never raise (always returns an outcome dict)."""

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    result = {
        "to": to_email,
        "username": username,
        "timestamp": timestamp,
        "ip_address": ip_address,
        "delivered": False,
        "detail": "",
    }

    if not smtp_configured():
        result["detail"] = "SMTP not configured. Alert recorded locally instead."
        return result

    try:
        msg = build_login_alert_email(
            full_name, username, ip_address, timestamp
        )
        msg["To"] = to_email

        context = ssl.create_default_context()

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
            server.starttls(context=context)
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.sendmail(SMTP_FROM, [to_email], msg.as_string())

        result["delivered"] = True
        result["detail"] = f"Email sent via {SMTP_HOST}."
    except Exception as e:
        result["detail"] = (
            f"Send failed ({type(e).__name__}: {e}). "
            "Alert recorded locally instead."

        )

    return result

