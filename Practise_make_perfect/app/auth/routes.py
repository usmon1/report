from app.database import get_users_db_connection
from app.auth.utils import hash_password, verify_password


def check_user_login(login: str, password: str) -> dict:
    """
    Проверяет логин и пароль пользователя с ВЕРИФИКАЦИЕЙ ХЭША
    И обновляет время последнего входа при успешной аутентификации
    """
    print(f"🔐 Проверяем вход для логина: {login}")

    conn = get_users_db_connection()
    if conn is None:
        print("❌ Не удалось подключиться к БД пользователей")
        return {"success": False, "error": "Ошибка подключения к базе данных"}

    try:
        cur = conn.cursor()

        # Ищем пользователя по логину (теперь нам нужен хэш пароля)
        cur.execute(
            'SELECT "логин", "пароль_хэш", "статус", "роль" FROM users WHERE "логин" = %s',
            (login,)
        )

        user = cur.fetchone()

        if user is None:
            print(f"❌ Пользователь с логином '{login}' не найден")
            return {"success": False, "error": "Пользователь не найден"}

        print(f"📋 Найден пользователь: логин={user[0]}, статус={user[2]}, роль={user[3]}")

        if user[2] != 'active':
            print(f"❌ Пользователь '{login}' заблокирован")
            return {"success": False, "error": "Пользователь заблокирован"}

        # ВЕРИФИЦИРУЕМ пароль с помощью bcrypt
        if verify_password(password, user[1]):
            print(f"✅ Пользователь '{login}' успешно вошел, роль: {user[3]}")

            # ОБНОВЛЯЕМ время последнего входа
            try:
                cur.execute(
                    'UPDATE users SET "Последний_вход" = CURRENT_TIMESTAMP WHERE "логин" = %s',
                    (login,)
                )
                conn.commit()
                print(f"🕒 Обновлено время последнего входа для пользователя: {login}")
            except Exception as e:
                print(f"⚠️ Не удалось обновить время последнего входа: {e}")
                # Не прерываем вход из-за этой ошибки

            return {
                "success": True,
                "user_login": user[0],
                "user_role": user[3],
            }
        else:
            print(f"❌ Неверный пароль для пользователя '{login}'")
            return {"success": False, "error": "Неверный пароль"}

    except Exception as e:
        print(f"❌ Ошибка при проверке пользователя: {e}")
        return {"success": False, "error": "Ошибка при проверке пользователя"}
    finally:
        conn.close()

def check_login_unique(login: str) -> bool:
    """
    Проверяет, уникален ли логин
    Возвращает True если логин свободен, False если занят
    """
    conn = get_users_db_connection()
    if conn is None:
        print("❌ Не удалось подключиться к БД пользователей")
        return False

    try:
        cur = conn.cursor()

        # Проверяем есть ли пользователь с таким логином
        cur.execute(
            'SELECT "логин" FROM users WHERE "логин" = %s',
            (login,)
        )

        user = cur.fetchone()

        if user is None:
            print(f"✅ Логин '{login}' свободен")
            return True
        else:
            print(f"❌ Логин '{login}' уже занят")
            return False

    except Exception as e:
        print(f"❌ Ошибка при проверке логина: {e}")
        return False
    finally:
        conn.close()


def check_email_unique(email: str) -> bool:
    """
    Проверяет, уникален ли email
    Возвращает True если email свободен, False если занят
    """
    conn = get_users_db_connection()
    if conn is None:
        print("❌ Не удалось подключиться к БД пользователей")
        return False

    try:
        cur = conn.cursor()

        # Проверяем есть ли пользователь с таким email
        cur.execute(
            'SELECT "email" FROM users WHERE "email" = %s',
            (email,)
        )

        user = cur.fetchone()

        if user is None:
            print(f"✅ Email '{email}' свободен")
            return True
        else:
            print(f"❌ Email '{email}' уже занят")
            return False

    except Exception as e:
        print(f"❌ Ошибка при проверке email: {e}")
        return False
    finally:
        conn.close()


def create_user(full_name: str, email: str, login: str, password: str) -> dict:
    """
    Создает нового пользователя в БД с хэшированным паролем
    """
    conn = get_users_db_connection()
    if conn is None:
        return {"success": False, "error": "Ошибка подключения к базе данных"}

    try:
        cur = conn.cursor()

        # ХЭШИРУЕМ пароль перед сохранением
        hashed_password = hash_password(password)

        # Вставляем нового пользователя с ХЭШИРОВАННЫМ паролем
        cur.execute(
            '''
            INSERT INTO users ("ФИО", "email", "логин", "пароль_хэш", "роль", "статус", "Дата_регистрации", "Последний_вход")
            VALUES (%s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP, NULL)
            ''',
            (full_name, email, login, hashed_password, "user", "active")
        )

        conn.commit()

        print(f"✅ Пользователь '{login}' успешно создан (пароль захэширован)")
        return {"success": True, "user_login": login}

    except Exception as e:
        conn.rollback()
        print(f"❌ Ошибка при создании пользователя: {e}")
        return {"success": False, "error": f"Ошибка при создании пользователя: {e}"}
    finally:
        conn.close()

