import pytest
from app import app, db, User

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    with app.app_context():
        db.create_all()
        yield app.test_client()
        db.drop_all()

def test_login_fail(client):
    response = client.post('/login', json={
        'email': 'admin@example.com',
        'password': 'wrongpassword'
    })
    assert response.status_code == 401
    assert response.json['error'] == "Invalid credentials"