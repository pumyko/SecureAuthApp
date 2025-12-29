import pytest
from app import app, db, User, ph

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:' # БД в памяти для тестов
    with app.app_context():
        db.create_all()
        # Создаем тестового пользователя с безопасным (не pwned) паролем
        user = User(email="test@secure.com", password_hash=ph.hash("VeryUniquePassword2025!@#"))
        db.session.add(user)
        db.session.commit()
    return app.test_client()

def test_login_success(client):
    """Проверка успешного входа"""
    response = client.post('/login', json={
        "email": "test@secure.com",
        "password": "VeryUniquePassword2025!@#"
    })
    assert response.status_code == 200
    assert response.json['status'] == 'success'

def test_login_invalid_credentials(client):
    """Проверка неверных данных (должна быть задержка и 401)"""
    response = client.post('/login', json={
        "email": "wrong@ex.com",
        "password": "wrongpassword"
    })
    assert response.status_code == 401
    assert response.json['status'] == 'error'