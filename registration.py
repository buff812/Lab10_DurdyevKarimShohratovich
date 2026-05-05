import re
import logging
import hashlib
from datetime import datetime
from typing import Tuple

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('registration_log.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)

# Список зарезервированных логинов
RESERVED_LOGINS = {
    'admin', 'root', 'system', 'test', 'user', 'guest', 'administrator',
    'moderator', 'support', 'help', 'info', 'noreply'
}

def mask_password(password: str) -> str:
    """
    Маскирует пароль для логирования.
    Использует хеш для одинакового результата для совпадающих паролей.
    """
    if not password:
        return "***EMPTY***"
    
    # Хеш пароля для одинакового результата
    hash_obj = hashlib.md5(password.encode())
    hash_hex = hash_obj.hexdigest()[:8]
    return f"***{hash_hex}***"


def validate_login(login: str) -> Tuple[bool, str]:
    """Валидирует логин (телефон, email или строка)"""
    
    if not login:
        return False, "Логин не может быть пустым"
    
    # Проверка телефона: +x-xxx-xxx-xxxx
    if login.startswith('+'):
        phone_pattern = r'^\+\d{1,3}-\d{3}-\d{3}-\d{4}$'
        if not re.match(phone_pattern, login):
            return False, "Телефон должен быть в формате +x-xxx-xxx-xxxx"
        return True, ""
    
    # Проверка email: xxx@xxx.xxx
    if '@' in login:
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, login):
            return False, "Email некорректен (формат: xxx@xxx.xxx)"
        return True, ""
    
    # Проверка строки: минимум 5 символов, латиница, цифры, подчеркивание
    if len(login) < 5:
        return False, "Логин должен содержать минимум 5 символов"
    
    if not re.match(r'^[a-zA-Z0-9_]+$', login):
        return False, "Логин может содержать только латиницу, цифры и подчеркивание"
    
    # Проверка против зарезервированных логинов
    if login.lower() in RESERVED_LOGINS:
        return False, f"Логин '{login}' зарезервирован и недоступен"
    
    return True, ""


def validate_password(password: str, confirm_password: str) -> Tuple[bool, str]:
    """Валидирует пароль и его подтверждение"""
    
    if not password:
        return False, "Пароль не может быть пустым"
    
    if not confirm_password:
        return False, "Подтверждение пароля не может быть пустым"
    
    if len(password) < 7:
        return False, "Пароль должен содержать минимум 7 символов"
    
    # Проверка на кириллицу, цифры и спецсимволы
    if not re.search(r'[а-яёА-ЯЁ]', password):
        return False, "Пароль должен содержать минимум одну букву кириллицы"
    
    if not re.search(r'[0-9]', password):
        return False, "Пароль должен содержать минимум одну цифру"
    
    if not re.search(r'[!@#$%^&*()_\-+=\[\]{};:\'",.<>?/\\|`~]', password):
        return False, "Пароль должен содержать минимум один спецсимвол (!@#$%^&* и т.д.)"
    
    if not re.search(r'[a-z]', password):
        return False, "Пароль должен содержать минимум одну букву в нижнем регистре (а-я)"
    
    if not re.search(r'[A-Z]', password):
        return False, "Пароль должен содержать минимум одну букву в верхнем регистре (А-Я)"
    
    # Проверка кириллицы (не допускать латиницу)
    if re.search(r'[a-zA-Z]', password):
        return False, "Пароль может содержать только кириллицу, не латиницу"
    
    if password != confirm_password:
        return False, "Пароль и его подтверждение не совпадают"
    
    return True, ""


def validate_registration(login: str, password: str, confirm_password: str) -> Tuple[bool, str]:
    """
    Основная функция валидации регистрации.
    
    Args:
        login: логин (телефон, email или строка)
        password: пароль
        confirm_password: подтверждение пароля
    
    Returns:
        Кортеж (успех, сообщение об ошибке)
    """
    
    masked_pwd = mask_password(password)
    masked_confirm = mask_password(confirm_password)
    
    try:
        # Валидация логина
        login_valid, login_error = validate_login(login)
        if not login_valid:
            logging.warning(
                f"FAILED REGISTRATION | Login={login} | Password={masked_pwd} | "
                f"ConfirmPassword={masked_confirm} | Error: {login_error}"
            )
            return False, login_error
        
        # Валидация пароля
        password_valid, password_error = validate_password(password, confirm_password)
        if not password_valid:
            logging.warning(
                f"FAILED REGISTRATION | Login={login} | Password={masked_pwd} | "
                f"ConfirmPassword={masked_confirm} | Error: {password_error}"
            )
            return False, password_error
        
        # Успешная регистрация
        logging.info(
            f"SUCCESS REGISTRATION | Login={login} | Password={masked_pwd} | "
            f"ConfirmPassword={masked_confirm} | Успешная регистрация"
        )
        return True, ""
    
    except Exception as e:
        logging.error(
            f"REGISTRATION ERROR | Login={login} | Password={masked_pwd} | "
            f"ConfirmPassword={masked_confirm} | Exception: {str(e)}", exc_info=True
        )
        return False, f"Ошибка сервера: {str(e)}"


# Тестирование
if __name__ == "__main__":
    print("=== ТЕСТИРОВАНИЕ ФУНКЦИИ РЕГИСТРАЦИИ ===\n")
    
    # Тест 1: Успешная регистрация с email
    print("Тест 1: Успешная регистрация с email")
    result, message = validate_registration(
        "user@example.com",
        "Пароль123!",
        "Пароль123!"
    )
    print(f"Результат: {result}, Сообщение: {message}\n")
    
    # Тест 2: Успешная регистрация с логином
    print("Тест 2: Успешная регистрация с логином (строка)")
    result, message = validate_registration(
        "john_doe",
        "Пароль123!",
        "Пароль123!"
    )
    print(f"Результат: {result}, Сообщение: {message}\n")
    
    # Тест 3: Успешная регистрация с телефоном
    print("Тест 3: Успешная регистрация с телефоном")
    result, message = validate_registration(
        "+7-123-456-7890",
        "Пароль123!",
        "Пароль123!"
    )
    print(f"Результат: {result}, Сообщение: {message}\n")
    
    # Тест 4: Пароли не совпадают
    print("Тест 4: Пароли не совпадают")
    result, message = validate_registration(
        "user@example.com",
        "Пароль123!",
        "Пароль456!"
    )
    print(f"Результат: {result}, Сообщение: {message}\n")
    
    # Тест 5: Короткий логин
    print("Тест 5: Короткий логин (менее 5 символов)")
    result, message = validate_registration(
        "usr",
        "Пароль123!",
        "Пароль123!"
    )
    print(f"Результат: {result}, Сообщение: {message}\n")
    
    # Тест 6: Зарезервированный логин
    print("Тест 6: Зарезервированный логин")
    result, message = validate_registration(
        "admin",
        "Пароль123!",
        "Пароль123!"
    )
    print(f"Результат: {result}, Сообщение: {message}\n")
    
    # Тест 7: Короткий пароль
    print("Тест 7: Короткий пароль (менее 7 символов)")
    result, message = validate_registration(
        "user@example.com",
        "Па123!",
        "Па123!"
    )
    print(f"Результат: {result}, Сообщение: {message}\n")
    
    # Тест 8: Пароль без кириллицы
    print("Тест 8: Пароль без кириллицы")
    result, message = validate_registration(
        "user@example.com",
        "Password123!",
        "Password123!"
    )
    print(f"Результат: {result}, Сообщение: {message}\n")
    
    # Тест 9: Пароль без цифр
    print("Тест 9: Пароль без цифр")
    result, message = validate_registration(
        "user@example.com",
        "Пароль!!!",
        "Пароль!!!"
    )
    print(f"Результат: {result}, Сообщение: {message}\n")
    
    # Тест 10: Неправильный формат email
    print("Тест 10: Неправильный формат email")
    result, message = validate_registration(
        "user.example.com",  # Без @
        "Пароль123!",
        "Пароль123!"
    )
    print(f"Результат: {result}, Сообщение: {message}\n")
    
    # Тест 11: Неправильный формат телефона
    print("Тест 11: Неправильный формат телефона")
    result, message = validate_registration(
        "+712345678",  # Неправильный формат
        "Пароль123!",
        "Пароль123!"
    )
    print(f"Результат: {result}, Сообщение: {message}\n")
    
    # Тест 12: Логин с недопустимыми символами
    print("Тест 12: Логин с недопустимыми символами")
    result, message = validate_registration(
        "user@name",  # @ в логине (строка)
        "Пароль123!",
        "Пароль123!"
    )
    print(f"Результат: {result}, Сообщение: {message}\n")
    
    # Тест 13: Пустой логин
    print("Тест 13: Пустой логин")
    result, message = validate_registration(
        "",
        "Пароль123!",
        "Пароль123!"
    )
    print(f"Результат: {result}, Сообщение: {message}\n")
    
    # Тест 14: Пустой пароль
    print("Тест 14: Пустой пароль")
    result, message = validate_registration(
        "user@example.com",
        "",
        ""
    )
    print(f"Результат: {result}, Сообщение: {message}\n")