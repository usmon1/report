import bcrypt

def hash_password(password: str) -> str:
    """
    Хэширует пароль с помощью bcrypt
    Возвращает строку с хэшем
    """
    # Генерируем соль и хэшируем пароль
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Проверяет пароль против хэша
    Возвращает True если пароль верный
    """
    try:
        return bcrypt.checkpw(
            plain_password.encode('utf-8'),
            hashed_password.encode('utf-8')
        )
    except Exception:
        return False
