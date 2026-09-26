"""
admin.py — SHFSL 2.0 alerting.

Fixes vs. original prototype:
  - No credentials in source. Everything comes from core.config.settings,
    which reads environment variables only.
  - In demo mode (or if credentials are simply absent), sending is a
    logged no-op — it never raises and never blocks the caller.
  - SMTP failures are caught individually (auth, connect, generic) and
    logged without ever printing the password.
"""
import smtplib
import threading
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

from core.config import settings


def send_alert_email(subject, body):
    if not settings.email_enabled():
        print(f"[EMAIL] Skipped (disabled or unconfigured): {subject[:60]}")
        return

    def _send():
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = settings.SENDER_EMAIL
            msg["To"] = settings.RECEIVER_EMAIL
            msg.attach(MIMEText(body, "plain"))

            with smtplib.SMTP(settings.SMTP_SERVER, settings.SMTP_PORT, timeout=10) as server:
                server.starttls()
                server.login(settings.SENDER_EMAIL, settings.SENDER_PASSWORD)
                server.sendmail(settings.SENDER_EMAIL, settings.RECEIVER_EMAIL, msg.as_string())
            print(f"[EMAIL] Alert sent: {subject[:60]}")
        except smtplib.SMTPAuthenticationError:
            print("[EMAIL] Authentication failed — check SHFSL_SENDER_PASSWORD.")
        except smtplib.SMTPConnectError:
            print("[EMAIL] Cannot connect to SMTP server.")
        except Exception as e:
            print(f"[EMAIL] Failed to send alert: {type(e).__name__}")

    threading.Thread(target=_send, daemon=True).start()
