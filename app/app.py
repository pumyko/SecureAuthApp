import os
import sys
import time
import random
import hashlib
import requests
import pyotp
import logging
import uuid
import smtplib
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from argon2 import PasswordHasher
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from authlib.integrations.flask_client import OAuth

load_dotenv()

app = Flask(__name__)

# Загрузка конфигов
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'default-key-for-dev')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Инициализация расширений
db = SQLAlchemy(app)
ph = PasswordHasher()

# Проверка ENCRYPTION_KEY
enc_key = os.getenv('ENCRYPTION_KEY')
if not enc_key:
    print("Critical error: ENCRYPTION_KEY not found in environment!", file=sys.stderr)
    sys.exit(1)

try:
    cipher = Fernet(enc_key.encode())
except Exception as e:
    print(f"Critical error: key encryption: {e}", file=sys.stderr)
    sys.exit(1)

# Настройка OAuth
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.getenv('GOOGLE_CLIENT_ID'),
    client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)

# Модель БД
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    mfa_secret_encrypted = db.Column(db.String(255), nullable=True)
    mfa_enabled = db.Column(db.Boolean, default=False)
    oauth_provider = db.Column(db.String(50), nullable=True)
    oauth_id = db.Column(db.String(100), unique=True, nullable=True)

logging.basicConfig(level=logging.INFO)
limiter = Limiter(get_remote_address, app=app, storage_uri="memory://")

def is_password_pwned(password):
    if not password: return False
    sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]
    try:
        response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=1.5)
        if response.status_code == 200:
            return suffix in response.text
    except Exception as e:
        app.logger.error(f"HIBP API unreachable: {e}")
    return False

# Эндпоинт инициации входа
@app.route('/oauth-login')
@limiter.limit("5 per minute") # Критерий: Rate limit
def oauth_login():
    redirect_uri = "https://localhost/oauth-callback"
    # Authlib автоматически генерирует и проверяет 'state' для защиты от CSRF
    app.logger.info(f"OAuth login attempt from {request.user_agent}")
    return google.authorize_redirect(redirect_uri)

# Callback эндпоинт
@app.route('/oauth-callback')
def oauth_callback():
    try:
        token = google.authorize_access_token()
        user_info = token.get('userinfo')
    except Exception as e:
        app.logger.error(f"OAuth error: {e}")
        return jsonify({"error": "OAuth validation failed"}), 400

    # Поиск или создание пользователя (интеграция с существующим flow)
    user = User.query.filter_by(oauth_id=user_info['sub']).first()
    
    if not user:
        # Если email уже есть в базе, привязываем OAuth к нему
        user = User.query.filter_by(email=user_info['email']).first()
        if user:
            user.oauth_id = user_info['sub']
            user.oauth_provider = 'google'
        else:
            # Создаем нового пользователя (без пароля, вход только через Google)
            user = User(
                email=user_info['email'],
                oauth_id=user_info['sub'],
                oauth_provider='google',
                password_hash='OAUTH_USER' 
            )
            db.session.add(user)
        db.session.commit()

    # Критерий: MFA triggers post-OAuth if enabled
    if user.mfa_enabled:
        return jsonify({
            "status": "mfa_required", 
            "message": "OAuth success, please provide MFA code",
            "email": user.email 
        }), 202

    return jsonify({"status": "success", "message": "Logged in via Google!"}), 200

# Добавляем в модель БД таблицу для токенов
class ResetToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token_hash = db.Column(db.String(128), index=True) # Хэшируем токен для защиты при утечке БД
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    expiry = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)

# Эндпоинт запроса сброса пароля
@app.route('/password-reset', methods=['POST'])
@limiter.limit("3 per hour") # Критерий: Ограничение попыток
def request_reset():
    data = request.json or {}
    email = data.get('email')
    user = User.query.filter_by(email=email).first()
    
    # Даже если пользователя нет, возвращаем успех (предотвращение перебора email)
    if user:
        token = str(uuid.uuid4())
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        
        # Храним с TTL 10 минут
        new_token = ResetToken(
            token_hash=token_hash, 
            user_id=user.id, 
            expiry=datetime.utcnow() + timedelta(minutes=10)
        )
        db.session.add(new_token)
        db.session.commit()
        
        # Демо-отправка email (SMTP настройки из .env)
        send_reset_email(email, token)
        app.logger.info(f"Password reset requested for: {email}")

    return jsonify({"message": "If this email exists, a reset link has been sent."}), 200

# Эндпоинт установки нового пароля
@app.route('/password-confirm', methods=['POST'])
def confirm_reset():
    data = request.json or {}
    token = data.get('token')
    new_password = data.get('new_password')
    mfa_code = data.get('mfa_code')
    
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    reset_record = ResetToken.query.filter_by(token_hash=token_hash, used=False).first()
    
    # Проверка TTL и использования (Критерий: single-use, short TTL)
    if not reset_record or reset_record.expiry < datetime.utcnow():
        return jsonify({"error": "Invalid or expired token"}), 400
    
    user = User.query.get(reset_record.user_id)
    
    # Интеграция с MFA (Критерий: Require MFA if enabled)
    if user.mfa_enabled:
        if not mfa_code:
            return jsonify({"status": "mfa_required", "message": "MFA code needed for reset"}), 202
        secret = cipher.decrypt(user.mfa_secret_encrypted.encode()).decode()
        if not pyotp.totp.TOTP(secret).verify(mfa_code):
            return jsonify({"error": "Invalid MFA code"}), 401

    # Проверка нового пароля на утечки (HIBP)
    if is_password_pwned(new_password):
        return jsonify({"error": "This password is compromised, choose another"}), 403

    # Атомарное обновление (Критерий: Atomic transactions)
    user.password_hash = ph.hash(new_password)
    reset_record.used = True
    db.session.commit()
    
    return jsonify({"status": "success", "message": "Password updated"}), 200

def send_reset_email(email, token):
    # Заглушка для демо. В реальности берем SMTP_HOST, SMTP_PORT из .env
    print(f"DEBUG MAIL: Sending token {token} to {email}")

@app.route('/mfa-setup', methods=['POST'])
def mfa_setup():
    data = request.json or {}
    user = User.query.filter_by(email=data.get('email')).first()
    if not user: return jsonify({"error": "User not found"}), 404
    
    secret = pyotp.random_base32()
    user.mfa_secret_encrypted = cipher.encrypt(secret.encode()).decode()
    db.session.commit()
    
    otp_uri = pyotp.totp.TOTP(secret).provisioning_uri(name=user.email, issuer_name="SecureAuthApp")
    return jsonify({"secret": secret, "qr_uri": otp_uri}), 200

@app.route('/mfa-verify', methods=['POST'])
@limiter.limit("3 per minute")
def mfa_verify():
    data = request.json or {}
    user = User.query.filter_by(email=data.get('email')).first()
    if not user or not user.mfa_secret_encrypted:
        return jsonify({"error": "MFA not set up"}), 400
    
    try:
        secret = cipher.decrypt(user.mfa_secret_encrypted.encode()).decode()
        totp = pyotp.totp.TOTP(secret)
        if totp.verify(data.get('code')):
            user.mfa_enabled = True
            db.session.commit()
            return jsonify({"status": "success", "message": "MFA enabled"}), 200
    except Exception:
        return jsonify({"error": "Decryption failed"}), 500
        
    return jsonify({"error": "Invalid code"}), 401

@app.route('/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    start_time = time.perf_counter()
    data = request.json or {}
    email = data.get('email', '')
    password = data.get('password', '')
    mfa_code = data.get('mfa_code')

    user = User.query.filter_by(email=email).first()
    valid_password = False
    
    if user:
        try:
            ph.verify(user.password_hash, password)
            valid_password = True
        except Exception: pass
    else:
        ph.hash("dummy_password_for_timing")

    # Constant time delay (Stage 3)
    elapsed = time.perf_counter() - start_time
    time.sleep(max(0, 1.2 + random.uniform(-0.05, 0.05) - elapsed))

    if not valid_password:
        return jsonify({"error": "Invalid credentials"}), 401

    if is_password_pwned(password):
        return jsonify({"status": "error", "message": "Password compromised!"}), 403

    # MFA Check
    if user.mfa_enabled:
        if not mfa_code:
            return jsonify({"status": "mfa_required", "message": "Please provide MFA code"}), 202
        
        secret = cipher.decrypt(user.mfa_secret_encrypted.encode()).decode()
        if not pyotp.totp.TOTP(secret).verify(mfa_code):
            return jsonify({"error": "Invalid MFA code"}), 401

    return jsonify({"status": "success", "message": "Logged in!"}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)