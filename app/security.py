import os
import sys
import hashlib
import requests
import re
from argon2 import PasswordHasher
from cryptography.fernet import Fernet
from dotenv import load_dotenv

load_dotenv()

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

def is_password_pwned(password):
    if not password:
        return False
    sha1_hash = hashlib.sha1(password.encode('utf-8'), usedforsecurity=False).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]
    try:
        response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=1.5)
        if response.status_code == 200:
            return suffix in response.text
    except Exception as e:
        print(f"HIBP API unreachable: {e}", file=sys.stderr)
    return False

def validate_email(email):
    regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(regex, email) is not None