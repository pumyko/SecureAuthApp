import pytest
import pyotp
from app.app import app, db
from app.models import User, ResetToken
from app.security import ph, cipher

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    with app.app_context():
        db.drop_all()
        db.create_all()
        # Create test user with MFA
        secret = pyotp.random_base32()
        user = User(
            email="test@secure.com",
            password_hash=ph.hash("VeryUniquePassword2025!@#"),
            mfa_secret_encrypted=cipher.encrypt(secret.encode()).decode(),
            mfa_enabled=False
        )
        db.session.add(user)
        # OAuth user
        oauth_user = User(
            email="oauth@secure.com",
            oauth_id="123",
            oauth_provider="google",
            password_hash=None
        )
        db.session.add(oauth_user)
        db.session.commit()
    yield app.test_client()
    with app.app_context():
        db.drop_all()

def test_mfa_success(client):
    with app.app_context():
        user = User.query.filter_by(email="test@secure.com").first()
        secret = cipher.decrypt(user.mfa_secret_encrypted.encode()).decode()
        code = pyotp.TOTP(secret).now()

    with client.session_transaction() as sess:
        sess['mfa_pending_email'] = "test@secure.com"

    response = client.post('/mfa-verify', json={"email": "test@secure.com", "code": code})
    assert response.status_code == 200
    assert response.json['status'] == 'success'

def test_mfa_fail(client):
    with client.session_transaction() as sess:
        sess['mfa_pending_email'] = "test@secure.com"

    response = client.post('/mfa-verify', json={"email": "test@secure.com", "code": "invalid"})
    assert response.status_code == 401
    assert response.json['error'] == 'Invalid code'

def test_reset_token_creation(client):
    response = client.post('/password-reset', json={"email": "test@secure.com"})
    assert response.status_code == 200

    with app.app_context():
        token = ResetToken.query.filter_by(user_id=1).first()
        assert token is not None
        assert not token.used

def test_oauth_user_login_attempt(client):
    response = client.post('/login', json={
        "email": "oauth@secure.com",
        "password": "any"
    })
    assert response.status_code == 403
    assert response.json['error'] == 'This account uses OAuth only'

def test_behavioral_block(client):
    response = client.post('/login', json={
        "email": "test@secure.com",
        "password": "VeryUniquePassword2025!@#"
    }, headers={'X-Behavior-Score': '0.3'})
    assert response.status_code == 403
    assert response.json['error'] == 'Suspicious activity detected'