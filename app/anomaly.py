# app/anomaly.py
from datetime import datetime, timedelta
from .models import db, Attempt
from flask import current_app
import smtplib
from email.mime.text import MIMEText

def log_attempt(ip, email, success):
    attempt = Attempt(ip=ip, email=email, timestamp=datetime.utcnow(), success=success)
    db.session.add(attempt)
    db.session.commit()

def check_anomaly(ip, threshold=10, window_hours=1):
    window_start = datetime.utcnow() - timedelta(hours=window_hours)
    failed_attempts = Attempt.query.filter(
        Attempt.ip == ip,
        Attempt.success == False,
        Attempt.timestamp >= window_start
    ).count()
    if failed_attempts > threshold:
        current_app.logger.warning(f"Anomaly detected: {failed_attempts} failed attempts from IP {ip}")
        send_alert_email(ip, failed_attempts)
        return True
    return False

def send_alert_email(ip, count):
    msg = MIMEText(f"Anomaly: {count} failed logins from {ip}")
    msg['Subject'] = 'Security Alert'
    msg['From'] = current_app.config['SMTP_USER']
    msg['To'] = 'admin@example.com'
    with smtplib.SMTP(current_app.config['SMTP_HOST'], current_app.config['SMTP_PORT']) as server:
        server.starttls()
        server.login(current_app.config['SMTP_USER'], current_app.config['SMTP_PASS'])
        server.send_message(msg)