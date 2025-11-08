import time
from typing import Dict, Tuple
import hashlib

# In-memory хранилище для неудачных попыток входа
# В реальном проекте лучше использовать Redis или БД
failed_attempts: Dict[str, Tuple[int, float]] = {}

# Настройки безопасности
MAX_ATTEMPTS = 5
LOCKOUT_TIME = 900  # 15 минут в секундах
ATTEMPT_WINDOW = 3600  # 1 час - окно для подсчета попыток


def get_client_identifier(login: str, ip: str) -> str:
    """Создает уникальный идентификатор для комбинации логин+IP"""
    return hashlib.md5(f"{login}:{ip}".encode()).hexdigest()


def record_failed_attempt(login: str, ip: str):
    """Записывает неудачную попытку входа"""
    identifier = get_client_identifier(login, ip)
    now = time.time()

    if identifier in failed_attempts:
        count, first_attempt = failed_attempts[identifier]

        # Сбрасываем счетчик если прошло больше часа с первой попытки
        if now - first_attempt > ATTEMPT_WINDOW:
            failed_attempts[identifier] = (1, now)
        else:
            failed_attempts[identifier] = (count + 1, first_attempt)
    else:
        failed_attempts[identifier] = (1, now)

    print(f"🔐 Неудачная попытка входа: {login} с IP {ip}. Попыток: {failed_attempts[identifier][0]}")


def record_successful_attempt(login: str, ip: str):
    """Удаляет записи о неудачных попытках при успешном входе"""
    identifier = get_client_identifier(login, ip)
    if identifier in failed_attempts:
        del failed_attempts[identifier]
        print(f"🔐 Сброс счетчика попыток для: {login}")


def is_blocked(login: str, ip: str) -> Tuple[bool, int]:
    """
    Проверяет, заблокирован ли логин/IP.
    Возвращает (заблокирован, оставшееся время в секундах)
    """
    identifier = get_client_identifier(login, ip)

    if identifier not in failed_attempts:
        return False, 0

    count, first_attempt = failed_attempts[identifier]
    now = time.time()

    # Сбрасываем счетчик если прошло больше часа
    if now - first_attempt > ATTEMPT_WINDOW:
        del failed_attempts[identifier]
        return False, 0

    if count >= MAX_ATTEMPTS:
        time_since_first = now - first_attempt
        if time_since_first < LOCKOUT_TIME:
            remaining = LOCKOUT_TIME - time_since_first
            return True, int(remaining)
        else:
            # Время блокировки истекло, сбрасываем счетчик
            del failed_attempts[identifier]
            return False, 0

    return False, 0


def get_remaining_attempts(login: str, ip: str) -> int:
    """Возвращает количество оставшихся попыток"""
    identifier = get_client_identifier(login, ip)

    if identifier not in failed_attempts:
        return MAX_ATTEMPTS

    count, first_attempt = failed_attempts[identifier]

    # Сбрасываем счетчик если прошло больше часа
    if time.time() - first_attempt > ATTEMPT_WINDOW:
        del failed_attempts[identifier]
        return MAX_ATTEMPTS

    return MAX_ATTEMPTS - count