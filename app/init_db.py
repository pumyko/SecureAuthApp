import os
from app import app, db, User, ph
from cryptography.fernet import Fernet
from dotenv import load_dotenv

load_dotenv()

with app.app_context():
    # Удаляем старые таблицы и создаем новые (с полями mfa)
    print("Database resetting...")
    db.drop_all()
    db.create_all()
    
    # Создаем тестового админа
    admin_email = 'admin@example.com'
    admin_pass = 'strongpass'
    
    admin = User(
        email=admin_email, 
        password_hash=ph.hash(admin_pass),
        mfa_enabled=False
    )
    
    db.session.add(admin)
    db.session.commit()
    print(f"Database updated. Created user: {admin_email}")