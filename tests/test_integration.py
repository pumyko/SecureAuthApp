def test_rate_limiting(client):
    # Отправляем 6 запросов при лимите 5 в минуту
    for _ in range(5):
        client.post('/login', json={"email": "test@ex.com", "password": "123"})
    response = client.post('/login', json={"email": "test@ex.com", "password": "123"})
    assert response.status_code == 429
    assert b"Too many requests" in response.data

def test_db_integrity(app):
    with app.app_context():
        user = User(email="new@ex.com", password_hash="hash")
        db.session.add(user)
        db.session.commit()
        assert User.query.filter_by(email="new@ex.com").first() is not None