# app/auth.py
import time
import random
import pyotp
import logging
import uuid
import smtplib
from datetime import datetime, timedelta, UTC
from email.mime.text import MIMEText
from flask import Blueprint, request, jsonify, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from authlib.integrations.flask_client import OAuth
from flask_jwt_extended import create_access_token, get_jwt_identity, jwt_required, JWTManager
from .models import db, User, ResetToken, ApiKey
from .security import ph, cipher, is_password_pwned, validate_email
from .anomaly import log_attempt, check_anomaly
import hashlib

auth_bp = Blueprint('auth', __name__)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
handler = logging.handlers.SocketHandler('logstash', 5000)
handler.setFormatter(logging.Formatter('%(message)s'))
logger.addHandler(handler)

limiter = Limiter(get_remote_address, storage_uri=os.getenv("REDIS_URL", "redis://localhost:6379"))

jwt = JWTManager()

oauth = OAuth()
google = oauth.register(
    name='google',
    client_id=os.getenv('GOOGLE_CLIENT_ID'),
    client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)

@auth_bp.route('/oauth-login')
@limiter.limit("5 per minute")
def oauth_login():
    redirect_uri = "https://localhost/oauth-callback"
    return google.authorize_redirect(redirect_uri)

@auth_bp.route('/oauth-callback')
def oauth_callback():
    try:
        token = google.authorize_access_token()
        user_info = token.get('userinfo')
    except Exception as e:
        logger.error(f"OAuth error: {e}")
        return jsonify({"error": "OAuth validation failed"}), 400

    user = User.query.filter_by(oauth_id=user_info['sub']).first()

    if not user:
        if not validate_email(user_info['email']):
            return jsonify({"error": "Invalid email format"}), 400
        user = User.query.filter_by(email=user_info['email']).first()
        if user:
            user.oauth_id = user_info['sub']
            user.oauth_provider = 'google'
        else:
            user = User(
                email=user_info['email'],
                oauth_id=user_info['sub'],
                oauth_provider='google',
                password_hash=None
            )
            db.session.add(user)
        db.session.commit()

    if user.mfa_enabled:
        session['mfa_pending_email'] = user.email
        return jsonify({
            "status": "mfa_required",
            "message": "OAuth success, please provide MFA code",
            "email": user.email
        }), 202

    return jsonify({"status": "success", "message": "Logged in via Google!"}), 200

@auth_bp.route('/password-reset', methods=['POST'])
@limiter.limit("3 per hour")
def request_reset():
    data = request.json or {}
    email = data.get('email')
    if not validate_email(email):
        return jsonify({"error": "Invalid email format"}), 400

    user = User.query.filter_by(email=email).first()

    token = str(uuid.uuid4())
    token_hash = hashlib.sha256(token.encode()).hexdigest()

    if user:
        new_token = ResetToken(
            token_hash=token_hash,
            user_id=user.id,
            expiry=datetime.now(UTC) + timedelta(minutes=10)
        )
        db.session.add(new_token)
        send_reset_email(email, token)
    else:
        dummy_token = ResetToken(
            token_hash=token_hash,
            user_id=-1,
            expiry=datetime.now(UTC) + timedelta(minutes=10)
        )
        db.session.add(dummy_token)

    db.session.commit()
    db.session.query(ResetToken).filter_by(user_id=-1).delete()
    db.session.commit()

    return jsonify({"message": "If this email exists, a reset link has been sent."}), 200

@auth_bp.route('/password-confirm', methods=['POST'])
def confirm_reset():
    data = request.json or {}
    token = data.get('token')
    new_password = data.get('new_password')
    mfa_code = data.get('mfa_code')

    token_hash = hashlib.sha256(token.encode()).hexdigest()
    reset_record = ResetToken.query.filter_by(token_hash=token_hash, used=False).first()

    if not reset_record or reset_record.expiry < datetime.now(UTC):
        return jsonify({"error": "Invalid or expired token"}), 400

    user = User.query.get(reset_record.user_id)

    if user.mfa_enabled:
        if not mfa_code:
            return jsonify({"status": "mfa_required", "message": "MFA code needed for reset"}), 202
        secret = cipher.decrypt(user.mfa_secret_encrypted.encode()).decode()
        if not pyotp.TOTP(secret).verify(mfa_code):
            return jsonify({"error": "Invalid MFA code"}), 401

    if is_password_pwned(new_password):
        return jsonify({"error": "This password is compromised, choose another"}), 403

    user.password_hash = ph.hash(new_password)
    reset_record.used = True
    db.session.commit()

    return jsonify({"status": "success", "message": "Password updated"}), 200

def send_reset_email(email, token):
    logger.info(f"{{'event': 'reset_email_sent', 'email': '{email}', 'token': '{token}'}}")

@auth_bp.route('/mfa-setup', methods=['POST'])
def mfa_setup():
    data = request.json or {}
    email = data.get('email')
    if 'mfa_pending_email' not in session or session['mfa_pending_email'] != email:
        return jsonify({"error": "Unauthorized MFA setup"}), 403

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "User not found"}), 404

    secret = pyotp.random_base32()
    user.mfa_secret_encrypted = cipher.encrypt(secret.encode()).decode()
    db.session.commit()

    otp_uri = pyotp.TOTP(secret).provisioning_uri(name=user.email, issuer_name="SecureAuthApp")
    return jsonify({"secret": secret, "qr_uri": otp_uri}), 200

@auth_bp.route('/mfa-verify', methods=['POST'])
@limiter.limit("3 per minute")
def mfa_verify():
    data = request.json or {}
    email = data.get('email')
    if 'mfa_pending_email' not in session or session['mfa_pending_email'] != email:
        return jsonify({"error": "Unauthorized MFA verification"}), 403

    user = User.query.filter_by(email=email).first()
    if not user or not user.mfa_secret_encrypted:
        return jsonify({"error": "MFA not set up"}), 400

    try:
        secret = cipher.decrypt(user.mfa_secret_encrypted.encode()).decode()
        totp = pyotp.TOTP(secret)
        if totp.verify(data.get('code')):
            user.mfa_enabled = True
            db.session.commit()
            session.pop('mfa_pending_email', None)
            return jsonify({"status": "success", "message": "MFA enabled"}), 200
    except Exception:
        return jsonify({"error": "Decryption failed"}), 500

    return jsonify({"error": "Invalid code"}), 401

@auth_bp.route('/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    start_time = time.perf_counter()
    data = request.json or {}
    email = data.get('email', '')
    password = data.get('password', '')
    mfa_code = data.get('mfa_code')
    ip = request.remote_addr
    behavior_score = request.headers.get('X-Behavior-Score')

    if behavior_score is None or float(behavior_score) < 0.5:
        log_attempt(ip, email, False)
        logger.warning(f"{{'event': 'suspicious_behavior', 'ip': '{ip}', 'score': '{behavior_score}'}}")
        elapsed = time.perf_counter() - start_time
        time.sleep(max(0, 0.6 + random.uniform(-0.05, 0.05) - elapsed))
        return jsonify({"error": "Suspicious activity detected"}), 403

    if check_anomaly(ip):
        elapsed = time.perf_counter() - start_time
        time.sleep(max(0, 0.6 + random.uniform(-0.05, 0.05) - elapsed))
        return jsonify({"error": "Anomaly detected"}), 429

    if not validate_email(email):
        ph.hash("dummy")
        log_attempt(ip, email, False)
        elapsed = time.perf_counter() - start_time
        time.sleep(max(0, 0.6 + random.uniform(-0.05, 0.05) - elapsed))
        return jsonify({"error": "Invalid email format"}), 400

    user = User.query.filter_by(email=email).first()
    valid_password = False

    if user:
        if user.password_hash is None:
            log_attempt(ip, email, False)
            elapsed = time.perf_counter() - start_time
            time.sleep(max(0, 0.6 + random.uniform(-0.05, 0.05) - elapsed))
            return jsonify({"error": "This account uses OAuth only"}), 403
        try:
            ph.verify(user.password_hash, password)
            valid_password = True
        except Exception:
            pass
    else:
        ph.hash("dummy_password_for_timing")

    if not valid_password:
        log_attempt(ip, email, False)
        elapsed = time.perf_counter() - start_time
        time.sleep(max(0, 0.6 + random.uniform(-0.05, 0.05) - elapsed))
        return jsonify({"error": "Invalid credentials"}), 401

    if is_password_pwned(password):
        log_attempt(ip, email, False)
        elapsed = time.perf_counter() - start_time
        time.sleep(max(0, 0.6 + random.uniform(-0.05, 0.05) - elapsed))
        return jsonify({"status": "error", "message": "Password compromised!"}), 403

    if user.mfa_enabled:
        if not mfa_code:
            session['mfa_pending_email'] = email
            elapsed = time.perf_counter() - start_time
            time.sleep(max(0, 0.6 + random.uniform(-0.05, 0.05) - elapsed))
            return jsonify({"status": "mfa_required", "message": "Please provide MFA code"}), 202

        secret = cipher.decrypt(user.mfa_secret_encrypted.encode()).decode()
        if not pyotp.TOTP(secret).verify(mfa_code):
            log_attempt(ip, email, False)
            elapsed = time.perf_counter() - start_time
            time.sleep(max(0, 0.6 + random.uniform(-0.05, 0.05) - elapsed))
            return jsonify({"error": "Invalid MFA code"}), 401

    log_attempt(ip, email, True)
    elapsed = time.perf_counter() - start_time
    time.sleep(max(0, 0.6 + random.uniform(-0.05, 0.05) - elapsed))
    return jsonify({"status": "success", "message": "Logged in!"}), 200

@auth_bp.route('/api-key', methods=['POST'])
@jwt_required()
@limiter.limit("5 per day")
def generate_api_key():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user.mfa_enabled:
        return jsonify({"error": "MFA required for API key generation"}), 403

    # Behavioral check if needed
    behavior_score = request.headers.get('X-Behavior-Score')
    if behavior_score is None or float(behavior_score) < 0.5:
        logger.warning(f"{{'event': 'suspicious_api_key', 'user_id': '{user_id}'}}")
        return jsonify({"error": "Suspicious activity detected"}), 403

    key = create_access_token(identity=user_id, expires_delta=timedelta(days=7))
    key_hash = hashlib.sha256(key.encode()).hexdigest()
    api_key = ApiKey(key_hash=key_hash, user_id=user_id, expiry=datetime.now(UTC) + timedelta(days=7))
    db.session.add(api_key)
    db.session.commit()

    logger.info(f"{{'event': 'api_key_generated', 'user_id': '{user_id}', 'token': '{key}'}}")
    return jsonify({"api_key": key}), 200

@auth_bp.route('/api-key/rotate', methods=['POST'])
@jwt_required()
@limiter.limit("5 per day")
def rotate_api_key():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user.mfa_enabled:
        return jsonify({"error": "MFA required for API key rotation"}), 403

    old_key = request.json.get('old_key')
    old_hash = hashlib.sha256(old_key.encode()).hexdigest()
    existing = ApiKey.query.filter_by(key_hash=old_hash, user_id=user_id).first()
    if not existing:
        return jsonify({"error": "Invalid old key"}), 400

    new_key = create_access_token(identity=user_id, expires_delta=timedelta(days=7))
    new_hash = hashlib.sha256(new_key.encode()).hexdigest()
    existing.key_hash = new_hash
    existing.expiry = datetime.now(UTC) + timedelta(days=7)
    db.session.commit()

    logger.info(f"{{'event': 'api_key_rotated', 'user_id': '{user_id}', 'token': '{new_key}'}}")
    return jsonify({"api_key": new_key}), 200