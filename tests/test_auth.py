import pytest
from app.app import app

@pytest.fixture
def client():
    with app.test_client() as client:
        yield client

def test_login_fail(client):
    """Проверка, что неверный пароль возвращает 401"""
    response = client.post('/login', json={
        'email': 'admin@example.com',
        'password': 'wrongpassword'
    })
    assert response.status_code == 401
    assert b"Invalid email or password" in response.data