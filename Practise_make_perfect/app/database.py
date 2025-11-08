import psycopg2
from psycopg2.extras import RealDictCursor

# Настройки подключения к ОСНОВНОЙ базе данных
MAIN_DB_CONFIG = {
    "host": "localhost",
    "database": "laba",  # замени на имя своей основной БД
    "user": "usmon",  # замени на своего пользователя PostgreSQL
    "password": "12345",  # замени на свой пароль
    "port": "5432"
}

# Настройки подключения к базе пользователей
USERS_DB_CONFIG = {
    "host": "localhost",
    "database": "user_laba2",  # замени на имя БД users
    "user": "usmon",  # обычно тот же пользователь
    "password": "12345",  # тот же пароль
    "port": "5432"
}


def get_main_db_connection():
    """Подключение к основной базе данных"""
    try:
        connection = psycopg2.connect(**MAIN_DB_CONFIG)
        return connection
    except Exception as error:
        print(f"Ошибка подключения к основной БД: {error}")
        return None


def get_users_db_connection():
    """Подключение к базе пользователей"""
    try:
        connection = psycopg2.connect(**USERS_DB_CONFIG)
        return connection
    except Exception as error:
        print(f"Ошибка подключения к БД пользователей: {error}")
        return None


def test_connections():
    print("🔍 Тестируем подключения к базам данных...")

    # Тест основной БД
    main_conn = get_main_db_connection()
    if main_conn:
        print("✅ Подключение к основной БД успешно")
        main_conn.close()
    else:
        print("❌ Ошибка подключения к основной БД")

    # Тест БД пользователей
    users_conn = get_users_db_connection()
    if users_conn:
        print("✅ Подключение к БД пользователей успешно")
        users_conn.close()
    else:
        print("❌ Ошибка подключения к БД пользователей")