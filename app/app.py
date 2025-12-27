import time
import random
from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# Инициализируем лимитер: 5 попыток в минуту для одного IP на эндпоинт /login
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

# Имитация базы данных (в продакшене пароли уже должны быть в Argon2/PBKDF2)
users = {
    "admin@example.com": generate_password_hash("strongpass", method='scrypt')
}

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute") # Жесткий лимит на попытки входа
def login():
    start_time = time.perf_counter()
    target_duration = 0.5  # Целевое время ответа: 500мс
    
    data = request.get_json()
    email = data.get('email', '')
    password = data.get('password', '')

    # 1. Поиск пользователя
    user_hash = users.get(email)

    # 2. Проверка пароля
    # Если пользователя нет, проверяем "пустой" хэш, чтобы потратить столько же времени CPU
    if user_hash:
        is_valid = check_password_hash(user_hash, password)
    else:
        # Dummy check для предотвращения side-channel атак по времени
        check_password_hash(generate_password_hash("dummy"), "password")
        is_valid = False

    # 3. Выравнивание времени ответа
    execution_time = time.perf_counter() - start_time
    sleep_time = target_duration - execution_time
    if sleep_time > 0:
        # Добавляем небольшой джиттер (шум), чтобы запутать автоматику
        time.sleep(sleep_time + random.uniform(-0.02, 0.02))

    # 4. Унифицированный ответ (Всегда одна и та же ошибка)
    if is_valid:
        return jsonify({"status": "success", "message": "Welcome!"}), 200
    
    return jsonify({"status": "error", "message": "Invalid email or password"}), 401

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({"error": "Too many requests. Please try again later."}), 429

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)