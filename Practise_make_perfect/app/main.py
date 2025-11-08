from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from app.database import test_connections, get_main_db_connection, get_users_db_connection
from app.auth.routes import check_user_login, check_login_unique, check_email_unique, create_user
from app.auth.security import record_failed_attempt, record_successful_attempt, is_blocked, get_remaining_attempts
from datetime import datetime
app = FastAPI(title="Enterprise Reporting System")
templates = Jinja2Templates(directory="app/templates")


# Тестируем подключение к БД при старте
@app.on_event("startup")
async def startup_event():
    test_connections()


# Главная страница выбора режима
@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


# Страница входа
@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("auth/login.html", {"request": request, "is_admin": False})


# Страница регистрации
@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    return templates.TemplateResponse("auth/register.html", {"request": request})


# Страница входа для администратора
@app.get("/admin_login", response_class=HTMLResponse)
async def admin_login_page(request: Request):
    return templates.TemplateResponse("auth/login.html", {"request": request, "is_admin": True})


# ... существующий код ...

# Обновляем обработчики входа с защитой от брут-форса
@app.post("/api/login")
async def api_login(request: Request, username: str = Form(...), password: str = Form(...)):
    client_ip = request.client.host

    # Проверяем не заблокирован ли пользователь
    blocked, remaining_time = is_blocked(username, client_ip)
    if blocked:
        minutes = remaining_time // 60
        seconds = remaining_time % 60
        return JSONResponse(content={
            "success": False,
            "error": f"Слишком много неудачных попыток. Попробуйте через {minutes} мин {seconds} сек."
        })

    result = check_user_login(username, password)

    if result["success"]:
        # Успешный вход - сбрасываем счетчик
        record_successful_attempt(username, client_ip)
        result["login_type"] = "user"
        result["redirect_url"] = "/dashboard"
    else:
        # Неудачная попытка - записываем
        record_failed_attempt(username, client_ip)
        remaining_attempts = get_remaining_attempts(username, client_ip)

        # Добавляем информацию о remaining_attempts
        result["remaining_attempts"] = remaining_attempts

        # Проверяем не заблокировался ли пользователь после этой попытки
        blocked, remaining_time = is_blocked(username, client_ip)
        if blocked:
            minutes = remaining_time // 60
            seconds = remaining_time % 60
            result["error"] = f"Слишком много неудачных попыток. Попробуйте через {minutes} мин {seconds} сек."
        elif remaining_attempts <= 2:  # Предупреждение при малом количестве попыток
            result["error"] = f"{result['error']} (осталось попыток: {remaining_attempts})"

    return JSONResponse(content=result)


@app.post("/api/admin_login")
async def api_admin_login(request: Request, username: str = Form(...), password: str = Form(...)):
    client_ip = request.client.host

    # Проверяем не заблокирован ли пользователь
    blocked, remaining_time = is_blocked(username, client_ip)
    if blocked:
        minutes = remaining_time // 60
        seconds = remaining_time % 60
        return JSONResponse(content={
            "success": False,
            "error": f"Слишком много неудачных попыток. Попробуйте через {minutes} мин {seconds} сек."
        })

    result = check_user_login(username, password)

    if result["success"] and result["user_role"] == "admin":
        record_successful_attempt(username, client_ip)
        result["login_type"] = "admin"
        result["redirect_url"] = "/dashboard"
    else:
        record_failed_attempt(username, client_ip)
        remaining_attempts = get_remaining_attempts(username, client_ip)

        result["remaining_attempts"] = remaining_attempts

        if result["success"] and result["user_role"] != "admin":
            result = {"success": False, "error": "Недостаточно прав для входа в панель администратора"}
            result["remaining_attempts"] = remaining_attempts

        blocked, remaining_time = is_blocked(username, client_ip)
        if blocked:
            minutes = remaining_time // 60
            seconds = remaining_time % 60
            result["error"] = f"Слишком много неудачных попыток. Попробуйте через {minutes} мин {seconds} сек."
        elif remaining_attempts <= 2:
            result["error"] = f"{result['error']} (осталось попыток: {remaining_attempts})"

    return JSONResponse(content=result)


# Страница личного кабинета
# Страница личного кабинета
@app.get("/dashboard")
async def dashboard(request: Request):
    # Получаем параметры из query string (передаются из check_auth.html)
    user_login = request.query_params.get("user_login")
    user_role = request.query_params.get("user_role")
    login_type = request.query_params.get("login_type")

    print(f"🔍 Dashboard: user_login={user_login}, user_role={user_role}, login_type={login_type}")

    if not user_login or not user_role:
        # Если нет параметров, проверяем аутентификацию
        return templates.TemplateResponse("auth/check_auth.html", {"request": request})

    # Определяем какой интерфейс показывать
    if login_type == "admin" and user_role == "admin":
        print("🔍 Показываем админ-панель")
        return templates.TemplateResponse(
            "admin/dashboard.html",
            {"request": request, "username": user_login, "user_role": user_role}  # ДОБАВЬ user_role
        )
    else:
        print("🔍 Показываем пользовательскую панель")
        return templates.TemplateResponse(
            "user/dashboard.html",
            {"request": request, "username": user_login, "user_role": user_role}  # ДОБАВЬ user_role
        )


# Выход из системы
@app.get("/logout")
async def logout():
    # Возвращаем страницу, которая очистит localStorage
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Выход из системы</title>
        <script>
            // Очищаем localStorage
            localStorage.removeItem('user_login');
            localStorage.removeItem('user_role');
            localStorage.removeItem('login_type');
            localStorage.removeItem('is_logged_in');

            // Перенаправляем на главную
            setTimeout(function() {
                window.location.href = '/';
            }, 1000);
        </script>
    </head>
    <body>
        <div style="text-align: center; margin-top: 100px;">
            <h1>🚪 Выход из системы...</h1>
            <p>Вы будете перенаправлены на главную страницу</p>
        </div>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)




# API для регистрации нового пользователя
@app.post("/api/register")
async def api_register(
        full_name: str = Form(...),
        email: str = Form(...),
        username: str = Form(...),
        password: str = Form(...),
        password_confirm: str = Form(...)
):
    print(f"📨 Получен запрос на регистрацию: {username}, {email}")

    # 1. Проверяем что пароли совпадают
    if password != password_confirm:
        return JSONResponse(content={
            "success": False,
            "error": "Пароли не совпадают"
        })

    # 2. Проверяем длину пароля
    if len(password) < 6:
        return JSONResponse(content={
            "success": False,
            "error": "Пароль должен содержать минимум 6 символов"
        })

    # 3. Проверяем уникальность логина
    if not check_login_unique(username):
        return JSONResponse(content={
            "success": False,
            "error": "Логин уже занят"
        })

    # 4. Проверяем уникальность email
    if not check_email_unique(email):
        return JSONResponse(content={
            "success": False,
            "error": "Email уже занят"
        })

    # 5. Создаем пользователя
    result = create_user(full_name, email, username, password)

    if result["success"]:
        return JSONResponse(content={
            "success": True,
            "message": "Регистрация успешна! Теперь вы можете войти в систему.",
            "redirect_url": "/login"
        })
    else:
        return JSONResponse(content={
            "success": False,
            "error": result.get("error", "Неизвестная ошибка при регистрации")
        })

# API для проверки уникальности логина
@app.get("/api/check_login")
async def api_check_login(login: str):
    is_unique = check_login_unique(login)
    return JSONResponse(content={"available": is_unique})

# API для проверки уникальности email
@app.get("/api/check_email")
async def api_check_email(email: str):
    is_unique = check_email_unique(email)
    return JSONResponse(content={"available": is_unique})
#------------------------------------------------------------------------

# API для главной страницы - общая статистика
# API для главной страницы - общая статистика
@app.get("/api/main/statistics")
async def get_main_statistics():
    """Возвращает общую статистику для главной страницы"""
    conn = get_main_db_connection()
    if conn:
        try:
            cur = conn.cursor()

            # 1. Общее количество предприятий
            cur.execute("SELECT COUNT(*) FROM enterprises")
            total_enterprises = cur.fetchone()[0]

            # 2. Суммарные показатели по всем услугам (общие)
            cur.execute("""
                SELECT 
                    COALESCE(SUM(s."План_всего"), 0) as total_plan,
                    COALESCE(SUM(s."Фактически_выполнено_всего"), 0) as total_fact
                FROM services s
            """)
            totals = cur.fetchone()

            # Преобразуем в числа
            total_plan = float(totals[0]) if totals[0] else 0.0
            total_fact = float(totals[1]) if totals[1] else 0.0

            # 3. Расчет процента выполнения (общего)
            total_percentage = (total_fact / total_plan * 100) if total_plan > 0 else 0.0

            # 4. Статистика по сельской местности - только для соответствующих категорий
            rural_categories = [
                "Услуги транспорта, в т.ч. в сельской местности",
                "Услуги связи, в т.ч. в сельской местности",
                "Услуги жилищного хозяйства, в т.ч. в сельской местности",
                "Услуги культуры, в т.ч. в сельской местности",
                "Прочие услуги, в т.ч. в сельской местности"
            ]

            # Суммируем только сельские категории
            cur.execute("""
                SELECT 
                    COALESCE(SUM(s."План_всего"), 0) as rural_plan,
                    COALESCE(SUM(s."Фактически_выполнено_всего"), 0) as rural_fact
                FROM services s
                WHERE s."Наименование_вида_услуг" IN %s
            """, (tuple(rural_categories),))

            rural_totals = cur.fetchone()
            rural_plan = float(rural_totals[0]) if rural_totals[0] else 0.0
            rural_fact = float(rural_totals[1]) if rural_totals[1] else 0.0
            rural_percentage = (rural_fact / rural_plan * 100) if rural_plan > 0 else 0.0

            return JSONResponse(content={
                "success": True,
                "total_enterprises": total_enterprises,
                "total_plan": total_plan,
                "total_fact": total_fact,
                "total_percentage": total_percentage,
                "rural_plan": rural_plan,
                "rural_fact": rural_fact,
                "rural_percentage": rural_percentage
            })

        except Exception as e:
            print(f"❌ Ошибка в get_main_statistics: {e}")
            return JSONResponse(content={"success": False, "error": str(e)})
        finally:
            conn.close()
    else:
        return JSONResponse(content={"success": False, "error": "Ошибка подключения к БД"})


# API для детальной информации по услугам
@app.get("/api/main/services-detailed")
async def get_services_detailed():
    """Возвращает детальную информацию по всем видам услуг"""
    conn = get_main_db_connection()
    if conn:
        try:
            cur = conn.cursor()

            # Получаем все виды услуг (даже если по ним нет данных)
            cur.execute("""
                SELECT st."Наименование_вида_услуг",
                       COALESCE(SUM(s."План_всего"), 0) as plan_total,
                       COALESCE(SUM(s."Фактически_выполнено_всего"), 0) as fact_total
                FROM service_types st
                LEFT JOIN services s ON st."Наименование_вида_услуг" = s."Наименование_вида_услуг"
                GROUP BY st."Наименование_вида_услуг"
                ORDER BY st."Наименование_вида_услуг"
            """)

            services_data = []
            for row in cur.fetchall():
                service_name = row[0]
                plan = float(row[1]) if row[1] else 0.0
                fact = float(row[2]) if row[2] else 0.0
                percentage = (fact / plan * 100) if plan > 0 else 0.0

                services_data.append({
                    "service_name": service_name,
                    "plan_total": plan,
                    "fact_total": fact,
                    "percentage": percentage
                })

            return JSONResponse(content={
                "success": True,
                "services": services_data
            })

        except Exception as e:
            print(f"❌ Ошибка в get_services_detailed: {e}")
            return JSONResponse(content={"success": False, "error": str(e)})
        finally:
            conn.close()
    else:
        return JSONResponse(content={"success": False, "error": "Ошибка подключения к БД"})
#--------------------------------------------------------------------------------------------

# ДОБАВЬ ПОСЛЕ СУЩЕСТВУЮЩИХ МАРШРУТОВ:

# Раздел "Отчёты"
# Основная страница выбора типа отчетов
@app.get("/reports")
async def reports_main(request: Request):
    user_login = request.query_params.get("user_login")
    user_role = request.query_params.get("user_role")

    if not user_login or not user_role:
        return templates.TemplateResponse("auth/check_auth.html", {"request": request})

    return templates.TemplateResponse("user/reports_main.html", {
        "request": request,
        "username": user_login,
        "user_role": user_role
    })


# Раздел "Справочники"
@app.get("/catalogs")
async def catalogs_page(request: Request):
    user_login = request.query_params.get("user_login")
    user_role = request.query_params.get("user_role")

    if not user_login or not user_role:
        return templates.TemplateResponse("auth/check_auth.html", {"request": request})

    return templates.TemplateResponse("user/catalogs.html", {
        "request": request,
        "username": user_login,
        "user_role": user_role
    })

#----------------------------------------------------------------------------

# API для получения списка предприятий с статистикой
# API для получения списка предприятий с статистикой (ОБНОВЛЕННАЯ ВЕРСИЯ)
@app.get("/api/reports/enterprises")
async def get_enterprises_with_stats():
    """Возвращает список всех предприятий с агрегированной статистикой"""
    conn = get_main_db_connection()
    if conn:
        try:
            cur = conn.cursor()

            # Получаем предприятия с общей статистикой (БЕЗ Выполнено_за_прошлый_год)
            cur.execute("""
                SELECT 
                    e."Регистрационный_номер",
                    e."Наименование_предприятия",
                    e."Код_министерства",
                    e."Код_отрасли", 
                    e."Код_области",
                    COALESCE(SUM(s."План_всего"), 0) as total_plan,
                    COALESCE(SUM(s."Фактически_выполнено_всего"), 0) as total_fact
                FROM enterprises e
                LEFT JOIN services s ON e."Регистрационный_номер" = s."Регистрационный_номер"
                GROUP BY e."Регистрационный_номер", e."Наименование_предприятия", 
                         e."Код_министерства", e."Код_отрасли", e."Код_области"
                ORDER BY e."Наименование_предприятия"
            """)

            enterprises = []
            for row in cur.fetchall():
                reg_number = row[0]
                name = row[1]
                # Исправленные индексы - теперь только 7 полей вместо 8
                total_plan = float(row[5]) if row[5] else 0.0
                total_fact = float(row[6]) if row[6] else 0.0

                # Расчет процентов
                total_percentage = (total_fact / total_plan * 100) if total_plan > 0 else 0.0

                # Статистика по сельской местности
                rural_categories = [
                    "Услуги транспорта, в т.ч. в сельской местности",
                    "Услуги связи, в т.ч. в сельской местности",
                    "Услуги жилищного хозяйства, в т.ч. в сельской местности",
                    "Услуги культуры, в т.ч. в сельской местности",
                    "Прочие услуги, в т.ч. в сельской местности"
                ]

                cur.execute("""
                    SELECT 
                        COALESCE(SUM("План_всего"), 0) as rural_plan,
                        COALESCE(SUM("Фактически_выполнено_всего"), 0) as rural_fact
                    FROM services 
                    WHERE "Регистрационный_номер" = %s 
                    AND "Наименование_вида_услуг" IN %s
                """, (reg_number, tuple(rural_categories)))

                rural_stats = cur.fetchone()
                rural_plan = float(rural_stats[0]) if rural_stats[0] else 0.0
                rural_fact = float(rural_stats[1]) if rural_stats[1] else 0.0
                rural_percentage = (rural_fact / rural_plan * 100) if rural_plan > 0 else 0.0

                enterprises.append({
                    "reg_number": reg_number,
                    "name": name,
                    "total_plan": total_plan,
                    "total_fact": total_fact,
                    "total_percentage": total_percentage,
                    "rural_plan": rural_plan,
                    "rural_fact": rural_fact,
                    "rural_percentage": rural_percentage
                })

            return JSONResponse(content={"success": True, "enterprises": enterprises})

        except Exception as e:
            print(f"❌ Ошибка в get_enterprises_with_stats: {e}")
            return JSONResponse(content={"success": False, "error": str(e)})
        finally:
            conn.close()
    else:
        return JSONResponse(content={"success": False, "error": "Ошибка подключения к БД"})

# API для детальной статистики по услугам предприятия
# API для детальной статистики по услугам предприятия за конкретный год
# API для детальной статистики по услугам предприятия за конкретный год (ОБНОВЛЕННАЯ ВЕРСИЯ)
# API для детальной статистики по услугам предприятия за конкретный год с динамикой
@app.get("/api/reports/enterprise/{reg_number}/services")
async def get_enterprise_services_detail(reg_number: int, year: int = None):
    """Возвращает детальную статистику по услугам для конкретного предприятия и года с динамикой"""
    conn = get_main_db_connection()
    if conn:
        try:
            cur = conn.cursor()

            # Получаем данные за текущий год
            current_year = year
            previous_year = year - 1 if year else None

            # Базовый запрос для текущего года
            query_current = """
                SELECT 
                    st."Наименование_вида_услуг",
                    COALESCE(SUM(s."План_всего"), 0) as plan_total,
                    COALESCE(SUM(s."Фактически_выполнено_всего"), 0) as fact_total
                FROM service_types st
                LEFT JOIN services s ON st."Наименование_вида_услуг" = s."Наименование_вида_услуг" 
                    AND s."Регистрационный_номер" = %s
            """
            params_current = [reg_number]

            if current_year:
                query_current += " AND s.\"Отчетный_период\" = %s"
                params_current.append(current_year)

            query_current += " GROUP BY st.\"Наименование_вида_услуг\" ORDER BY st.\"Наименование_вида_услуг\""

            cur.execute(query_current, params_current)
            current_year_data = cur.fetchall()

            # Получаем данные за предыдущий год для расчета динамики
            previous_year_data = {}
            if previous_year:
                query_previous = """
                    SELECT 
                        st."Наименование_вида_услуг",
                        COALESCE(SUM(s."Фактически_выполнено_всего"), 0) as previous_fact
                    FROM service_types st
                    LEFT JOIN services s ON st."Наименование_вида_услуг" = s."Наименование_вида_услуг" 
                        AND s."Регистрационный_номер" = %s AND s."Отчетный_период" = %s
                    GROUP BY st."Наименование_вида_услуг"
                """
                cur.execute(query_previous, (reg_number, previous_year))
                for row in cur.fetchall():
                    service_name = row[0]
                    previous_fact = float(row[1]) if row[1] else 0.0
                    previous_year_data[service_name] = previous_fact

            # Формируем ответ с динамикой (по вашей формуле: текущий/прошлый * 100)
            services_data = []
            for row in current_year_data:
                service_name = row[0]
                plan = float(row[1]) if row[1] else 0.0
                fact = float(row[2]) if row[2] else 0.0
                percentage = (fact / plan * 100) if plan > 0 else 0.0

                # Расчет динамики относительно прошлого года (ваша формула)
                previous_fact = previous_year_data.get(service_name, 0.0)
                # Формула: (текущий год / прошлый год) * 100
                dynamics = (fact / previous_fact * 100) if previous_fact > 0 else None

                services_data.append({
                    "service_name": service_name,
                    "plan_total": plan,
                    "fact_total": fact,
                    "percentage": percentage,
                    "dynamics": dynamics
                })

            return JSONResponse(content={
                "success": True,
                "services": services_data,
                "current_year": current_year,
                "previous_year": previous_year
            })

        except Exception as e:
            print(f"❌ Ошибка в get_enterprise_services_detail: {e}")
            return JSONResponse(content={"success": False, "error": str(e)})
        finally:
            conn.close()
    else:
        return JSONResponse(content={"success": False, "error": "Ошибка подключения к БД"})
#-----------------------------------------------------------------------------------------------

# Основная страница отчетов по предприятию
@app.get("/reports/enterprise")
async def enterprise_reports_main(request: Request):
    user_login = request.query_params.get("user_login")
    user_role = request.query_params.get("user_role")

    if not user_login or not user_role:
        return templates.TemplateResponse("auth/check_auth.html", {"request": request})

    return templates.TemplateResponse("reports/enterprise/step1_enterprises.html", {
        "request": request,
        "username": user_login,
        "user_role": user_role
    })


# Шаг 2: Выбор периода (будет реализован позже)
@app.get("/reports/enterprise/{reg_number}/periods")
async def enterprise_periods(request: Request, reg_number: int):
    user_login = request.query_params.get("user_login")
    user_role = request.query_params.get("user_role")

    if not user_login or not user_role:
        return templates.TemplateResponse("auth/check_auth.html", {"request": request})

    return templates.TemplateResponse("reports/enterprise/step2_periods.html", {
        "request": request,
        "username": user_login,
        "user_role": user_role,
        "reg_number": reg_number
    })
#------------------------------------------------------------------------------------------

# API для получения отчетных периодов предприятия с статистикой
# API для получения отчетных периодов предприятия с статистикой (ОБНОВЛЕННАЯ ВЕРСИЯ)
@app.get("/api/reports/enterprise/{reg_number}/periods")
async def get_enterprise_periods(reg_number: int):
    """Возвращает список отчетных периодов для предприятия с агрегированной статистикой"""
    conn = get_main_db_connection()
    if conn:
        try:
            cur = conn.cursor()

            # Получаем уникальные отчетные периоды для предприятия
            cur.execute("""
                SELECT DISTINCT s."Отчетный_период"
                FROM services s
                WHERE s."Регистрационный_номер" = %s
                ORDER BY s."Отчетный_период" DESC
            """, (reg_number,))

            periods = []
            for row in cur.fetchall():
                year = row[0]

                # Статистика за текущий год (БЕЗ Выполнено_за_прошлый_год)
                cur.execute("""
                    SELECT 
                        COALESCE(SUM("План_всего"), 0) as total_plan,
                        COALESCE(SUM("Фактически_выполнено_всего"), 0) as total_fact   
                    FROM services 
                    WHERE "Регистрационный_номер" = %s AND "Отчетный_период" = %s
                """, (reg_number, year))

                current_stats = cur.fetchone()
                current_plan = float(current_stats[0]) if current_stats[0] else 0.0
                current_fact = float(current_stats[1]) if current_stats[1] else 0.0
                current_percentage = (current_fact / current_plan * 100) if current_plan > 0 else 0.0

                # Статистика по сельской местности за текущий год
                rural_categories = [
                    "Услуги транспорта, в т.ч. в сельской местности",
                    "Услуги связи, в т.ч. в сельской местности",
                    "Услуги жилищного хозяйства, в т.ч. в сельской местности",
                    "Услуги культуры, в т.ч. в сельской местности",
                    "Прочие услуги, в т.ч. в сельской местности"
                ]

                cur.execute("""
                    SELECT 
                        COALESCE(SUM("План_всего"), 0) as rural_plan,
                        COALESCE(SUM("Фактически_выполнено_всего"), 0) as rural_fact
                    FROM services 
                    WHERE "Регистрационный_номер" = %s 
                    AND "Отчетный_период" = %s
                    AND "Наименование_вида_услуг" IN %s
                """, (reg_number, year, tuple(rural_categories)))

                rural_stats = cur.fetchone()
                rural_plan = float(rural_stats[0]) if rural_stats[0] else 0.0
                rural_fact = float(rural_stats[1]) if rural_stats[1] else 0.0
                rural_percentage = (rural_fact / rural_plan * 100) if rural_plan > 0 else 0.0

                # Статистика за предыдущий год для динамики (используем фактические данные)
                previous_year = year - 1
                cur.execute("""
                    SELECT 
                        COALESCE(SUM("Фактически_выполнено_всего"), 0) as previous_fact
                    FROM services 
                    WHERE "Регистрационный_номер" = %s AND "Отчетный_период" = %s
                """, (reg_number, previous_year))

                previous_stats = cur.fetchone()
                previous_fact = float(previous_stats[0]) if previous_stats[0] else 0.0

                # Расчет динамики - ПРАВИЛЬНАЯ ФОРМУЛА
                # Динамика = (Текущий год - Прошлый год) / Прошлый год * 100
                dynamics_total = (current_fact/ previous_fact * 100) if previous_fact > 0 else 0.0

                # Статистика по сельской местности за предыдущий год для динамики
                cur.execute("""
                    SELECT 
                        COALESCE(SUM("Фактически_выполнено_всего"), 0) as rural_previous_fact
                    FROM services 
                    WHERE "Регистрационный_номер" = %s 
                    AND "Отчетный_период" = %s
                    AND "Наименование_вида_услуг" IN %s
                """, (reg_number, previous_year, tuple(rural_categories)))

                rural_previous_stats = cur.fetchone()
                rural_previous_fact = float(rural_previous_stats[0]) if rural_previous_stats[0] else 0.0

                # Динамика для сельской местности
                dynamics_rural = (rural_fact / rural_previous_fact * 100) if rural_previous_fact > 0 else 0.0

                periods.append({
                    "year": year,
                    "current_plan": current_plan,
                    "current_fact": current_fact,
                    "current_percentage": current_percentage,
                    "rural_plan": rural_plan,
                    "rural_fact": rural_fact,
                    "rural_percentage": rural_percentage,
                    "dynamics_total": dynamics_total,
                    "dynamics_rural": dynamics_rural
                })

            return JSONResponse(content={"success": True, "periods": periods})

        except Exception as e:
            print(f"❌ Ошибка в get_enterprise_periods: {e}")
            return JSONResponse(content={"success": False, "error": str(e)})
        finally:
            conn.close()
    else:
        return JSONResponse(content={"success": False, "error": "Ошибка подключения к БД"})
#-----------------------------------------------------------------------------------------------
## API для получения областей с статистикой для предприятия и периода (ПОЛНОСТЬЮ ПЕРЕПИСАННАЯ ВЕРСИЯ)
@app.get("/api/reports/enterprise/{reg_number}/periods/{year}/regions")
async def get_enterprise_regions(reg_number: int, year: int):
    """Возвращает список областей с агрегированной статистикой для предприятия и периода"""
    conn = get_main_db_connection()
    if conn:
        try:
            cur = conn.cursor()
            print(f"🔍 Поиск областей для предприятия {reg_number} за {year} год")

            # Сначала проверим, есть ли вообще данные для этого предприятия и периода
            check_query = """
            SELECT COUNT(*) FROM services 
            WHERE "Регистрационный_номер" = %s AND "Отчетный_период" = %s
            """
            cur.execute(check_query, (reg_number, year))
            total_services = cur.fetchone()[0]

            if total_services == 0:
                print(f"⚠️ Нет данных для предприятия {reg_number} за {year} год")
                return JSONResponse(content={"success": True, "regions": []})

            # Получаем уникальные области
            regions_query = """
            SELECT DISTINCT 
                r."Код_области",
                r."Наименование_области"
            FROM services s
            JOIN districts d ON s."Код_района" = d."Код_района" 
            JOIN regions r ON d."Код_области" = r."Код_области"
            WHERE s."Регистрационный_номер" = %s AND s."Отчетный_период" = %s
            ORDER BY r."Наименование_области"
            """

            cur.execute(regions_query, (reg_number, year))
            regions_data = cur.fetchall()
            print(f"📊 Найдено областей: {len(regions_data)}")

            regions = []
            for region in regions_data:
                region_code = region[0]
                region_name = region[1]
                print(f"🔍 Обрабатываем область: {region_name} (код: {region_code})")

                try:
                    # Получаем количество районов и услуг
                    count_query = """
                    SELECT 
                        COUNT(DISTINCT d."Код_района") as districts_count,
                        COUNT(DISTINCT s.id) as services_count
                    FROM services s
                    JOIN districts d ON s."Код_района" = d."Код_района"
                    WHERE s."Регистрационный_номер" = %s 
                        AND s."Отчетный_период" = %s 
                        AND d."Код_области" = %s
                    """
                    cur.execute(count_query, (reg_number, year, region_code))
                    count_result = cur.fetchone()

                    districts_count = count_result[0] if count_result else 0
                    services_count = count_result[1] if count_result else 0

                    # Получаем статистику по области
                    stats_query = """
                    SELECT 
                        COALESCE(SUM(s."План_всего"), 0) as total_plan,
                        COALESCE(SUM(s."Фактически_выполнено_всего"), 0) as total_fact,
                        COALESCE(SUM(CASE 
                            WHEN s."Наименование_вида_услуг" LIKE '%%в т.ч. в сельской местности%%' 
                            THEN s."План_всего" ELSE 0 
                        END), 0) as rural_plan,
                        COALESCE(SUM(CASE 
                            WHEN s."Наименование_вида_услуг" LIKE '%%в т.ч. в сельской местности%%' 
                            THEN s."Фактически_выполнено_всего" ELSE 0 
                        END), 0) as rural_fact
                    FROM services s
                    JOIN districts d ON s."Код_района" = d."Код_района"
                    WHERE s."Регистрационный_номер" = %s 
                        AND s."Отчетный_период" = %s 
                        AND d."Код_области" = %s
                    """

                    cur.execute(stats_query, (reg_number, year, region_code))
                    stats_result = cur.fetchone()

                    if stats_result:
                        total_plan = float(stats_result[0]) if stats_result[0] is not None else 0.0
                        total_fact = float(stats_result[1]) if stats_result[1] is not None else 0.0
                        rural_plan = float(stats_result[2]) if stats_result[2] is not None else 0.0
                        rural_fact = float(stats_result[3]) if stats_result[3] is not None else 0.0
                    else:
                        total_plan = total_fact = rural_plan = rural_fact = 0.0

                    # Расчет процентов
                    total_percentage = (total_fact / total_plan * 100) if total_plan > 0 else 0.0
                    rural_percentage = (rural_fact / rural_plan * 100) if rural_plan > 0 else 0.0

                    # Статистика за предыдущий год
                    prev_year = year - 1
                    prev_stats_query = """
                    SELECT 
                        COALESCE(SUM(s."Фактически_выполнено_всего"), 0) as prev_total_fact,
                        COALESCE(SUM(CASE 
                            WHEN s."Наименование_вида_услуг" LIKE '%%в т.ч. в сельской местности%%' 
                            THEN s."Фактически_выполнено_всего" ELSE 0 
                        END), 0) as prev_rural_fact
                    FROM services s
                    JOIN districts d ON s."Код_района" = d."Код_района"
                    WHERE s."Регистрационный_номер" = %s 
                        AND s."Отчетный_период" = %s 
                        AND d."Код_области" = %s
                    """

                    cur.execute(prev_stats_query, (reg_number, prev_year, region_code))
                    prev_stats_result = cur.fetchone()

                    if prev_stats_result:
                        prev_total_fact = float(prev_stats_result[0]) if prev_stats_result[0] is not None else 0.0
                        prev_rural_fact = float(prev_stats_result[1]) if prev_stats_result[1] is not None else 0.0
                    else:
                        prev_total_fact = prev_rural_fact = 0.0

                    # Расчет динамики
                    dynamics_total = (total_fact / prev_total_fact * 100) if prev_total_fact > 0 else 0.0
                    dynamics_rural = (rural_fact / prev_rural_fact * 100) if prev_rural_fact > 0 else 0.0

                    region_data = {
                        "region_code": region_code,
                        "region_name": region_name,
                        "districts_count": districts_count,
                        "services_count": services_count,
                        "total_plan": total_plan,
                        "total_fact": total_fact,
                        "total_percentage": total_percentage,
                        "rural_plan": rural_plan,
                        "rural_fact": rural_fact,
                        "rural_percentage": rural_percentage,
                        "dynamics_total": dynamics_total,
                        "dynamics_rural": dynamics_rural
                    }

                    regions.append(region_data)
                    print(f"✅ Область {region_name} обработана успешно")

                except Exception as region_error:
                    print(f"❌ Ошибка при обработке области {region_name}: {region_error}")
                    continue

            print(f"✅ Всего обработано областей: {len(regions)}")
            return JSONResponse(content={"success": True, "regions": regions})

        except Exception as e:
            print(f"❌ Критическая ошибка в get_enterprise_regions: {e}")
            import traceback
            print(f"🔍 Детальный traceback: {traceback.format_exc()}")
            return JSONResponse(content={"success": False, "error": str(e)})
        finally:
            conn.close()
    else:
        return JSONResponse(content={"success": False, "error": "Ошибка подключения к БД"})
# API для детальной статистики по услугам в области (С ДИНАМИКОЙ)
@app.get("/api/reports/enterprise/{reg_number}/periods/{year}/regions/{region_code}/services")
async def get_region_services_detail(reg_number: int, year: int, region_code: int):
    """Возвращает детальную статистику по услугам для области с динамикой"""
    conn = get_main_db_connection()
    if conn:
        try:
            cur = conn.cursor()
            print(f"🔍 Загрузка услуг для области {region_code}, предприятие {reg_number}, год {year}")

            # Данные за текущий год
            current_year_query = """
            SELECT 
                st."Наименование_вида_услуг",
                COALESCE(SUM(s."План_всего"), 0) as plan_total,
                COALESCE(SUM(s."Фактически_выполнено_всего"), 0) as fact_total
            FROM service_types st
            LEFT JOIN services s ON st."Наименование_вида_услуг" = s."Наименование_вида_услуг"
                AND s."Регистрационный_номер" = %s 
                AND s."Отчетный_период" = %s
                AND EXISTS (
                    SELECT 1 FROM districts d 
                    WHERE d."Код_района" = s."Код_района" AND d."Код_области" = %s
                )
            GROUP BY st."Наименование_вида_услуг"
            ORDER BY st."Наименование_вида_услуг"
            """

            cur.execute(current_year_query, (reg_number, year, region_code))
            current_data = cur.fetchall()

            # Данные за предыдущий год для динамики
            previous_year = year - 1
            previous_year_query = """
            SELECT 
                st."Наименование_вида_услуг",
                COALESCE(SUM(s."Фактически_выполнено_всего"), 0) as previous_fact
            FROM service_types st
            LEFT JOIN services s ON st."Наименование_вида_услуг" = s."Наименование_вида_услуг"
                AND s."Регистрационный_номер" = %s 
                AND s."Отчетный_период" = %s
                AND EXISTS (
                    SELECT 1 FROM districts d 
                    WHERE d."Код_района" = s."Код_района" AND d."Код_области" = %s
                )
            GROUP BY st."Наименование_вида_услуг"
            """

            cur.execute(previous_year_query, (reg_number, previous_year, region_code))
            previous_data = cur.fetchall()

            # Создаем словарь для быстрого доступа к данным предыдущего года
            previous_dict = {}
            for service in previous_data:
                service_name = service[0]
                previous_fact = float(service[1]) if service[1] else 0.0
                previous_dict[service_name] = previous_fact

            services = []
            for service in current_data:
                service_name = service[0]
                plan_total = float(service[1]) if service[1] else 0.0
                fact_total = float(service[2]) if service[2] else 0.0

                # Расчет процента выполнения
                percentage = (fact_total / plan_total * 100) if plan_total > 0 else 0.0

                # Расчет динамики относительно прошлого года
                previous_fact = previous_dict.get(service_name, 0.0)
                dynamics = (fact_total / previous_fact * 100) if previous_fact > 0 else None

                services.append({
                    "service_name": service_name,
                    "plan_total": plan_total,
                    "fact_total": fact_total,
                    "percentage": percentage,
                    "dynamics": dynamics
                })

            print(f"✅ Загружено {len(services)} услуг для области {region_code}")
            return JSONResponse(content={
                "success": True,
                "services": services,
                "current_year": year,
                "previous_year": previous_year
            })

        except Exception as e:
            print(f"❌ Ошибка в get_region_services_detail: {e}")
            import traceback
            print(f"🔍 Детальный traceback: {traceback.format_exc()}")
            return JSONResponse(content={"success": False, "error": str(e)})
        finally:
            conn.close()
    else:
        return JSONResponse(content={"success": False, "error": "Ошибка подключения к БД"})
    # Шаг 2.5: Выбор области


@app.get("/reports/enterprise/{reg_number}/periods/{year}/regions")
async def enterprise_regions(request: Request, reg_number: int, year: int):
    user_login = request.query_params.get("user_login")
    user_role = request.query_params.get("user_role")

    if not user_login or not user_role:
        return templates.TemplateResponse("auth/check_auth.html", {"request": request})

    return templates.TemplateResponse("reports/enterprise/step2.5_regions.html", {
        "request": request,
        "username": user_login,
        "user_role": user_role,
        "reg_number": reg_number,
        "year": year
    })
#-----------------------------------------------------------------------------------------------

# API для получения районов в области с статистикой для предприятия и периода
@app.get("/api/reports/enterprise/{reg_number}/periods/{year}/regions/{region_code}/districts")
async def get_enterprise_districts(reg_number: int, year: int, region_code: int):
    """Возвращает список районов в области с агрегированной статистикой для предприятия и периода"""
    conn = get_main_db_connection()
    if conn:
        try:
            cur = conn.cursor()
            print(f"🔍 Поиск районов для предприятия {reg_number}, область {region_code}, год {year}")

            # Проверяем, есть ли данные
            check_query = """
            SELECT COUNT(*) FROM services s
            JOIN districts d ON s."Код_района" = d."Код_района"
            WHERE s."Регистрационный_номер" = %s 
                AND s."Отчетный_период" = %s 
                AND d."Код_области" = %s
            """
            cur.execute(check_query, (reg_number, year, region_code))
            total_services = cur.fetchone()[0]

            if total_services == 0:
                print(f"⚠️ Нет данных для предприятия {reg_number} в области {region_code} за {year} год")
                return JSONResponse(content={"success": True, "districts": []})

            # Получаем районы
            districts_query = """
            SELECT 
                d."Код_района",
                d."Наименование_района"
            FROM services s
            JOIN districts d ON s."Код_района" = d."Код_района"
            WHERE s."Регистрационный_номер" = %s 
                AND s."Отчетный_период" = %s 
                AND d."Код_области" = %s
            GROUP BY d."Код_района", d."Наименование_района"
            ORDER BY d."Наименование_района"
            """

            cur.execute(districts_query, (reg_number, year, region_code))
            districts_data = cur.fetchall()
            print(f"📊 Найдено районов: {len(districts_data)}")

            districts = []
            for district in districts_data:
                district_code = district[0]
                district_name = district[1]
                print(f"🔍 Обрабатываем район: {district_name} (код: {district_code})")

                try:
                    # Статистика по району
                    stats_query = """
                    SELECT 
                        COALESCE(SUM(s."План_всего"), 0) as total_plan,
                        COALESCE(SUM(s."Фактически_выполнено_всего"), 0) as total_fact,
                        COALESCE(SUM(CASE 
                            WHEN s."Наименование_вида_услуг" LIKE '%%в т.ч. в сельской местности%%' 
                            THEN s."План_всего" ELSE 0 
                        END), 0) as rural_plan,
                        COALESCE(SUM(CASE 
                            WHEN s."Наименование_вида_услуг" LIKE '%%в т.ч. в сельской местности%%' 
                            THEN s."Фактически_выполнено_всего" ELSE 0 
                        END), 0) as rural_fact
                    FROM services s
                    WHERE s."Регистрационный_номер" = %s 
                        AND s."Отчетный_период" = %s 
                        AND s."Код_района" = %s
                    """

                    cur.execute(stats_query, (reg_number, year, district_code))
                    stats_result = cur.fetchone()

                    if stats_result:
                        total_plan = float(stats_result[0]) if stats_result[0] is not None else 0.0
                        total_fact = float(stats_result[1]) if stats_result[1] is not None else 0.0
                        rural_plan = float(stats_result[2]) if stats_result[2] is not None else 0.0
                        rural_fact = float(stats_result[3]) if stats_result[3] is not None else 0.0
                    else:
                        total_plan = total_fact = rural_plan = rural_fact = 0.0

                    # Расчет процентов
                    total_percentage = (total_fact / total_plan * 100) if total_plan > 0 else 0.0
                    rural_percentage = (rural_fact / rural_plan * 100) if rural_plan > 0 else 0.0

                    # Статистика за предыдущий год
                    prev_year = year - 1
                    prev_stats_query = """
                    SELECT 
                        COALESCE(SUM(s."Фактически_выполнено_всего"), 0) as prev_total_fact,
                        COALESCE(SUM(CASE 
                            WHEN s."Наименование_вида_услуг" LIKE '%%в т.ч. в сельской местности%%' 
                            THEN s."Фактически_выполнено_всего" ELSE 0 
                        END), 0) as prev_rural_fact
                    FROM services s
                    WHERE s."Регистрационный_номер" = %s 
                        AND s."Отчетный_период" = %s 
                        AND s."Код_района" = %s
                    """

                    cur.execute(prev_stats_query, (reg_number, prev_year, district_code))
                    prev_stats_result = cur.fetchone()

                    if prev_stats_result:
                        prev_total_fact = float(prev_stats_result[0]) if prev_stats_result[0] is not None else 0.0
                        prev_rural_fact = float(prev_stats_result[1]) if prev_stats_result[1] is not None else 0.0
                    else:
                        prev_total_fact = prev_rural_fact = 0.0

                    # Расчет динамики
                    dynamics_total = (total_fact / prev_total_fact * 100) if prev_total_fact > 0 else 0.0
                    dynamics_rural = (rural_fact / prev_rural_fact * 100) if prev_rural_fact > 0 else 0.0

                    district_data = {
                        "district_code": district_code,
                        "district_name": district_name,
                        "total_plan": total_plan,
                        "total_fact": total_fact,
                        "total_percentage": total_percentage,
                        "rural_plan": rural_plan,
                        "rural_fact": rural_fact,
                        "rural_percentage": rural_percentage,
                        "dynamics_total": dynamics_total,
                        "dynamics_rural": dynamics_rural
                    }

                    districts.append(district_data)
                    print(f"✅ Район {district_name} обработан успешно")

                except Exception as district_error:
                    print(f"❌ Ошибка при обработке района {district_name}: {district_error}")
                    continue

            print(f"✅ Всего обработано районов: {len(districts)}")
            return JSONResponse(content={"success": True, "districts": districts})

        except Exception as e:
            print(f"❌ Критическая ошибка в get_enterprise_districts: {e}")
            import traceback
            print(f"🔍 Детальный traceback: {traceback.format_exc()}")
            return JSONResponse(content={"success": False, "error": str(e)})
        finally:
            conn.close()
    else:
        return JSONResponse(content={"success": False, "error": "Ошибка подключения к БД"})

    # Шаг 3: Выбор района


# API для детальной статистики по услугам в районе
@app.get("/api/reports/enterprise/{reg_number}/periods/{year}/regions/{region_code}/districts/{district_code}/services")
async def get_district_services_detail(reg_number: int, year: int, region_code: int, district_code: int):
    """Возвращает детальную статистику по услугам для района с динамикой"""
    conn = get_main_db_connection()
    if conn:
        try:
            cur = conn.cursor()
            print(f"🔍 Загрузка услуг для района {district_code}, предприятие {reg_number}, год {year}")

            # Данные за текущий год
            current_year_query = """
            SELECT 
                st."Наименование_вида_услуг",
                COALESCE(SUM(s."План_всего"), 0) as plan_total,
                COALESCE(SUM(s."Фактически_выполнено_всего"), 0) as fact_total
            FROM service_types st
            LEFT JOIN services s ON st."Наименование_вида_услуг" = s."Наименование_вида_услуг"
                AND s."Регистрационный_номер" = %s 
                AND s."Отчетный_период" = %s
                AND s."Код_района" = %s
            GROUP BY st."Наименование_вида_услуг"
            ORDER BY st."Наименование_вида_услуг"
            """

            cur.execute(current_year_query, (reg_number, year, district_code))
            current_data = cur.fetchall()

            # Данные за предыдущий год для динамики
            previous_year = year - 1
            previous_year_query = """
            SELECT 
                st."Наименование_вида_услуг",
                COALESCE(SUM(s."Фактически_выполнено_всего"), 0) as previous_fact
            FROM service_types st
            LEFT JOIN services s ON st."Наименование_вида_услуг" = s."Наименование_вида_услуг"
                AND s."Регистрационный_номер" = %s 
                AND s."Отчетный_период" = %s
                AND s."Код_района" = %s
            GROUP BY st."Наименование_вида_услуг"
            """

            cur.execute(previous_year_query, (reg_number, previous_year, district_code))
            previous_data = cur.fetchall()

            # Создаем словарь для быстрого доступа к данным предыдущего года
            previous_dict = {}
            for service in previous_data:
                service_name = service[0]
                previous_fact = float(service[1]) if service[1] else 0.0
                previous_dict[service_name] = previous_fact

            services = []
            for service in current_data:
                service_name = service[0]
                plan_total = float(service[1]) if service[1] else 0.0
                fact_total = float(service[2]) if service[2] else 0.0

                # Расчет процента выполнения
                percentage = (fact_total / plan_total * 100) if plan_total > 0 else 0.0

                # Расчет динамики относительно прошлого года
                previous_fact = previous_dict.get(service_name, 0.0)
                dynamics = (fact_total / previous_fact * 100) if previous_fact > 0 else None

                services.append({
                    "service_name": service_name,
                    "plan_total": plan_total,
                    "fact_total": fact_total,
                    "percentage": percentage,
                    "dynamics": dynamics
                })

            print(f"✅ Загружено {len(services)} услуг для района {district_code}")
            return JSONResponse(content={
                "success": True,
                "services": services,
                "current_year": year,
                "previous_year": previous_year
            })

        except Exception as e:
            print(f"❌ Ошибка в get_district_services_detail: {e}")
            import traceback
            print(f"🔍 Детальный traceback: {traceback.format_exc()}")
            return JSONResponse(content={"success": False, "error": str(e)})
        finally:
            conn.close()
    else:
        return JSONResponse(content={"success": False, "error": "Ошибка подключения к БД"})

@app.get("/reports/enterprise/{reg_number}/periods/{year}/regions/{region_code}/districts")
async def enterprise_districts(request: Request, reg_number: int, year: int, region_code: int):
    user_login = request.query_params.get("user_login")
    user_role = request.query_params.get("user_role")

    if not user_login or not user_role:
        return templates.TemplateResponse("auth/check_auth.html", {"request": request})

    return templates.TemplateResponse("reports/enterprise/step3_districts.html", {
        "request": request,
        "username": user_login,
        "user_role": user_role,
        "reg_number": reg_number,
        "year": year,
        "region_code": region_code
    })

#----------------------------------------------------------------------------------------------------

# API для получения данных для финального отчета (бланк формы № ПУ)
@app.get(
    "/api/reports/enterprise/{reg_number}/periods/{year}/regions/{region_code}/districts/{district_code}/final-report")
async def get_final_report_data(reg_number: int, year: int, region_code: int, district_code: int):
    """Возвращает все данные для заполнения бланка формы № ПУ"""
    conn = get_main_db_connection()
    if conn:
        try:
            cur = conn.cursor()
            print(
                f"🔍 Подготовка данных для финального отчета: предприятие {reg_number}, район {district_code}, год {year}")

            # 1. Данные предприятия и коды
            enterprise_query = """
            SELECT DISTINCT
                e."Наименование_предприятия",
                e."Регистрационный_номер",
                e."Код_министерства",
                e."Код_отрасли",
                e."Код_области",
                d."Код_района",
                d."Наименование_района"
            FROM enterprises e
            JOIN services r ON e."Регистрационный_номер" = r."Регистрационный_номер"
            JOIN districts d ON d."Код_района" = r."Код_района"
            WHERE e."Регистрационный_номер" = %s AND d."Код_района" = %s
            """

            cur.execute(enterprise_query, (reg_number, district_code))
            enterprise_data = cur.fetchone()

            if not enterprise_data:
                print(f"❌ Предприятие {reg_number} не найдено в районе {district_code}")
                return JSONResponse(content={"success": False, "error": "Данные предприятия не найдены"})
            
            print(f"✅ Найдено предприятие: {enterprise_data[0]}")

            # 2. ФИО директора из периода
            director_query = """
            SELECT "ФИО_директора" 
            FROM period 
            WHERE "Регистрационный_номер" = %s AND "Отчетный_период" = %s
            LIMIT 1
            """

            cur.execute(director_query, (reg_number, year))
            director_result = cur.fetchone()
            director_name = director_result[0] if director_result else "Не указано"

            # 3. Данные по услугам для таблицы (зона 5)
            services_query = """
            SELECT 
                "Наименование_вида_услуг",
                "Код_показателя",
                COALESCE(SUM("План_всего"), 0) as plan_total,
                COALESCE(SUM("Фактически_выполнено_всего"), 0) as fact_total
            FROM services 
            WHERE "Регистрационный_номер" = %s 
                AND "Отчетный_период" = %s 
                AND "Код_района" = %s
            GROUP BY "Наименование_вида_услуг", "Код_показателя"
            ORDER BY "Наименование_вида_услуг"
            """

            cur.execute(services_query, (reg_number, year, district_code))
            services_data = cur.fetchall()

            # 4. Данные за предыдущий год для колонки "Выполнено за прошлый год"
            previous_year = year - 1
            previous_year_query = """
            SELECT 
                "Наименование_вида_услуг",
                COALESCE(SUM("Фактически_выполнено_всего"), 0) as previous_fact
            FROM services 
            WHERE "Регистрационный_номер" = %s 
                AND "Отчетный_период" = %s 
                AND "Код_района" = %s
            GROUP BY "Наименование_вида_услуг"
            """

            cur.execute(previous_year_query, (reg_number, previous_year, district_code))
            previous_year_data = cur.fetchall()
            previous_year_dict = {row[0]: float(row[1]) if row[1] else 0.0 for row in previous_year_data}

            # Формируем структурированные данные для таблицы
            service_categories = [
                "Услуги транспорта - всего",
                "Услуги транспорта, в т.ч. в сельской местности",
                "Услуги связи - всего",
                "Услуги связи, в т.ч. в сельской местности",
                "Услуги жилищного хозяйства - всего",
                "Услуги жилищного хозяйства, в т.ч. в сельской местности",
                "Услуги культуры - всего",
                "Услуги культуры, в т.ч. в сельской местности",
                "Прочие услуги - всего",
                "Прочие услуги, в т.ч. в сельской местности"
            ]

            table_data = []
            for i, category in enumerate(service_categories, 1):
                # Ищем данные для этой категории
                service_row = None
                for service in services_data:
                    if service[0] == category:
                        service_row = service
                        break

                if not service_row:
                    print(f"⚠️ Нет данных для услуги: {category}")

                if service_row:
                    plan_total = float(service_row[2]) if service_row[2] else 0.0
                    fact_total = float(service_row[3]) if service_row[3] else 0.0
                    indicator_code = service_row[1] if service_row[1] else ""
                else:
                    plan_total = fact_total = 0.0
                    indicator_code = ""

                # Данные за прошлый год
                previous_fact = previous_year_dict.get(category, 0.0)

                table_data.append({
                    "number": i,
                    "service_name": category,
                    "indicator_code": indicator_code,
                    "plan_total": plan_total,
                    "fact_total": fact_total,
                    "previous_year": previous_fact
                })

            # Собираем все данные для отчета
            report_data = {
                # Зона 1
                "enterprise_name": enterprise_data[0],
                "registration_number": enterprise_data[1],

                # Зона 3
                "ministry_code": enterprise_data[2],
                "industry_code": enterprise_data[3],
                "region_code": enterprise_data[4],
                "district_code": enterprise_data[5],
                
                "district_name": enterprise_data[6],

                # Зона 4
                "report_year": year,

                # Зона 5
                "table_data": table_data,

                # Зона 6
                "director_name": director_name,
                "current_date": datetime.now().strftime("%d.%m.%Y")
            }

            return JSONResponse(content={"success": True, "report_data": report_data})

        except Exception as e:
            print(f"❌ Ошибка в get_final_report_data: {e}")
            import traceback
            print(f"🔍 Детальный traceback: {traceback.format_exc()}")
            return JSONResponse(content={"success": False, "error": str(e)})
        finally:
            conn.close()
    else:
        return JSONResponse(content={"success": False, "error": "Ошибка подключения к БД"})



# Шаг 4: Финальный отчет (бланк формы № ПУ)
@app.get("/reports/enterprise/{reg_number}/periods/{year}/regions/{region_code}/districts/{district_code}/report")
async def enterprise_final_report(request: Request, reg_number: int, year: int, region_code: int, district_code: int):
    user_login = request.query_params.get("user_login")
    user_role = request.query_params.get("user_role")
    combined_mode = request.query_params.get("combined_mode") == "true"
    
    if not user_login or not user_role:
        return templates.TemplateResponse("auth/check_auth.html", {"request": request})

    return templates.TemplateResponse("reports/enterprise/step4_report.html", {
        "request": request,
        "username": user_login,
        "user_role": user_role,
        "reg_number": reg_number,
        "year": year,
        "region_code": region_code,
        "district_code": district_code,
        "combined_mode": combined_mode  # Передаем флаг комбинированного режима
    })

 #-------------------------------------------------------------------------------------------------------

# API для получения всех локаций (областей и районов)
@app.get("/api/filters/locations")
async def get_all_locations():
    """Возвращает список всех областей и районов для фильтра"""
    conn = get_main_db_connection()
    if conn:
        try:
            cur = conn.cursor()

            # Получаем все области
            cur.execute("""
                 SELECT "Код_области", "Наименование_области" 
                 FROM regions 
                 ORDER BY "Наименование_области"
             """)
            regions = [{"id": f"region_{row[0]}", "name": row[1], "type": "region"} for row in cur.fetchall()]

            # Получаем все районы
            cur.execute("""
                 SELECT d."Код_района", d."Наименование_района", r."Наименование_области"
                 FROM districts d
                 JOIN regions r ON d."Код_области" = r."Код_области"
                 ORDER BY r."Наименование_области", d."Наименование_района"
             """)
            districts = [{"id": f"district_{row[0]}", "name": f"{row[1]} ({row[2]})", "type": "district"} for row in
                         cur.fetchall()]

            return JSONResponse(content={
                "success": True,
                "regions": regions,
                "districts": districts
            })

        except Exception as e:
            print(f"❌ Ошибка в get_all_locations: {e}")
            return JSONResponse(content={"success": False, "error": str(e)})
        finally:
            conn.close()
    else:
        return JSONResponse(content={"success": False, "error": "Ошибка подключения к БД"})


# API для формирования отчета по фильтру
# API для формирования отчета по фильтру
@app.get("/api/reports/filtered-report")
async def get_filtered_report(
        enterprise_id: int,
        start_year: int,
        end_year: int,
        location_id: str,  # Формат: "region_1" или "district_1"
        location_type: str  # "region" или "district"
):
    """Формирует отчет по фильтру с учетом периода"""
    conn = get_main_db_connection()
    if conn:
        try:
            cur = conn.cursor()

            # Извлекаем ID из строки (убираем префикс)
            location_id_clean = int(location_id.split('_')[1])
            is_single_year = (start_year == end_year)

            print(
                f"🔍 Формируем отчет: предприятие={enterprise_id}, период={start_year}-{end_year}, локация={location_type}_{location_id_clean}")

            # 1. Получаем информацию о предприятии
            cur.execute("""
                SELECT "Наименование_предприятия", "Регистрационный_номер", 
                       "Код_министерства", "Код_отрасли", "Код_области"
                FROM enterprises 
                WHERE "Регистрационный_номер" = %s
            """, (enterprise_id,))

            enterprise_data = cur.fetchone()
            if not enterprise_data:
                return JSONResponse(content={"success": False, "error": "Предприятие не найдено"})

            # 2. Получаем информацию о локации
            location_name = ""
            region_district_code = None
            

            if location_type == "region":
                cur.execute('SELECT "Наименование_области" FROM regions WHERE "Код_области" = %s', (location_id_clean,))
                region_data = cur.fetchone()
                if region_data:
                    location_name = region_data[0]
                    region_district_code = location_id_clean
            else:  # district
                cur.execute("""
                    SELECT d."Наименование_района", r."Наименование_области", d."Код_области", d."Код_района"
                    FROM districts d
                    JOIN regions r ON d."Код_области" = r."Код_области"
                    WHERE d."Код_района" = %s
                """, (location_id_clean,))
                district_data = cur.fetchone()
                if district_data:
                    location_name = f"{district_data[0]} ({district_data[1]})"
                    region_district_code = location_id_clean
                    

            # 3. Получаем коды показателей для услуг
            cur.execute('SELECT "Наименование_вида_услуг", "Код_показателя" FROM services')
            service_codes = {row[0]: row[1] for row in cur.fetchall()}

            # 4. Формируем запрос для данных в зависимости от типа локации и периода
            services_data = []

            # Базовый список услуг
            service_categories = [
                "Услуги транспорта - всего",
                "Услуги транспорта, в т.ч. в сельской местности",
                "Услуги связи - всего",
                "Услуги связи, в т.ч. в сельской местности",
                "Услуги жилищного хозяйства - всего",
                "Услуги жилищного хозяйства, в т.ч. в сельской местности",
                "Услуги культуры - всего",
                "Услуги культуры, в т.ч. в сельской местности",
                "Прочие услуги - всего",
                "Прочие услуги, в т.ч. в сельской местности"
            ]

            for service_name in service_categories:
                # Для каждого вида услуг формируем запрос
                if location_type == "district":
                    # Отчет по конкретному району
                    if is_single_year:
                        # Один год - включаем данные за предыдущий год
                        query = """
                            SELECT 
                                COALESCE(SUM("План_всего"), 0) as plan_total,
                                COALESCE(SUM("Фактически_выполнено_всего"), 0) as fact_total,
                                COALESCE((
                                    SELECT SUM("Фактически_выполнено_всего")
                                    FROM services s2
                                    WHERE s2."Регистрационный_номер" = %s
                                        AND s2."Код_района" = %s
                                        AND s2."Отчетный_период" = %s
                                        AND s2."Наименование_вида_услуг" = %s
                                ), 0) as previous_year
                            FROM services 
                            WHERE "Регистрационный_номер" = %s
                                AND "Код_района" = %s
                                AND "Отчетный_период" = %s
                                AND "Наименование_вида_услуг" = %s
                        """
                        cur.execute(query, (enterprise_id, region_district_code, start_year - 1, service_name,
                                            enterprise_id, region_district_code, start_year, service_name))
                    else:
                        # Период - суммируем данные
                        query = """
                            SELECT 
                                COALESCE(SUM("План_всего"), 0) as plan_total,
                                COALESCE(SUM("Фактически_выполнено_всего"), 0) as fact_total,
                                0 as previous_year
                            FROM services 
                            WHERE "Регистрационный_номер" = %s
                                AND "Код_района" = %s
                                AND "Отчетный_период" BETWEEN %s AND %s
                                AND "Наименование_вида_услуг" = %s
                        """
                        cur.execute(query, (enterprise_id, region_district_code, start_year, end_year, service_name))
                else:
                    if is_single_year:
                        query = """
                                                SELECT 
                                                    COALESCE(SUM(s."План_всего"), 0) as plan_total,
                                                    COALESCE(SUM(s."Фактически_выполнено_всего"), 0) as fact_total,
                                                    COALESCE((
                                    SELECT SUM("Фактически_выполнено_всего")
                                    FROM services s2
                                                JOIN districts d2 ON s2."Код_района" = d2."Код_района"
                                                WHERE s2."Регистрационный_номер" = %s
                                                    AND d2."Код_области" = %s
                                                    AND s2."Отчетный_период" = %s
                                                    AND s2."Наименование_вида_услуг" = %s
                                ), 0) as previous_year
                                                FROM services s
                                                JOIN districts d ON s."Код_района" = d."Код_района"
                                                WHERE s."Регистрационный_номер" = %s
                                                    AND d."Код_области" = %s
                                                    AND s."Отчетный_период" = %s
                                                    AND s."Наименование_вида_услуг" = %s
                                            """
                        cur.execute(query, (enterprise_id, region_district_code, start_year - 1, service_name,
                                            enterprise_id, region_district_code, start_year, service_name))
                    # Отчет по области (агрегация по всем районам)
                    else:
                        query = """
                                                SELECT 
                                                    COALESCE(SUM(s."План_всего"), 0) as plan_total,
                                                    COALESCE(SUM(s."Фактически_выполнено_всего"), 0) as fact_total,
                                                    0 as previous_year
                                                FROM services s
                                                JOIN districts d ON s."Код_района" = d."Код_района"
                                                WHERE s."Регистрационный_номер" = %s
                                                    AND d."Код_области" = %s
                                                    AND s."Отчетный_период" BETWEEN %s AND %s
                                                    AND s."Наименование_вида_услуг" = %s
                                            """
                        cur.execute(query, (enterprise_id, region_district_code, start_year, end_year, service_name))


                row = cur.fetchone()
                if row:
                    services_data.append({
                        "service_name": service_name,
                        "indicator_code": service_codes.get(service_name, ""),
                        "plan_total": float(row[0]) if row[0] else 0.0,
                        "fact_total": float(row[1]) if row[1] else 0.0,
                        "previous_year": float(row[2]) if row[2] else 0.0
                    })

            # 5. Получаем ФИО директора (берем из последнего периода)
            cur.execute("""
                SELECT "ФИО_директора" 
                FROM period 
                WHERE "Регистрационный_номер" = %s 
                ORDER BY "Отчетный_период" DESC 
                LIMIT 1
            """, (enterprise_id,))
            director_result = cur.fetchone()
            director_name = director_result[0] if director_result else "Не указано"
            print(region_district_code, enterprise_data[4])
            # 6. Формируем ответ
            report_data = {
                "enterprise_name": enterprise_data[0],
                "registration_number": enterprise_data[1],
                "ministry_code": enterprise_data[2],
                "industry_code": enterprise_data[3],
                "region_code": enterprise_data[4],
                "district_code": region_district_code,
                "location_name": location_name,
                "location_type": location_type,
                "start_year": start_year,
                "end_year": end_year,
                "is_single_year": is_single_year,
                "director_name": director_name,
                "services": services_data,
                "current_date": datetime.now().strftime("%d.%m.%Y")
            }

            return JSONResponse(content={"success": True, "report_data": report_data})

        except Exception as e:
            print(f"❌ Ошибка в get_filtered_report: {e}")
            import traceback
            print(f"🔍 Детальный traceback: {traceback.format_exc()}")
            return JSONResponse(content={"success": False, "error": str(e)})
        finally:
            conn.close()
    else:
        return JSONResponse(content={"success": False, "error": "Ошибка подключения к БД"})
    # Страница фильтрованного отчета

@app.get("/reports/filtered-report")
async def filtered_report_page(request: Request):
    user_login = request.query_params.get("user_login")
    user_role = request.query_params.get("user_role")

    if not user_login or not user_role:
        return templates.TemplateResponse("auth/check_auth.html", {"request": request})

    return templates.TemplateResponse("reports/enterprise/step4_filtered_report.html", {
        "request": request,
        "username": user_login,
        "user_role": user_role
    })

#-------------------------------------------------------------------------------------------------


# API для получения областей со статистикой для сводного отчета
@app.get("/api/district/regions")
async def get_district_regions():
    """Возвращает список областей с агрегированной статистикой"""
    conn = get_main_db_connection()
    if conn:
        try:
            cur = conn.cursor()

            # Получаем все области с общей статистикой
            cur.execute("""
                SELECT 
                    r."Код_области",
                    r."Наименование_области",
                    COUNT(DISTINCT s."Регистрационный_номер") as enterprises_count,
                    COALESCE(SUM(s."План_всего"), 0) as total_plan,
                    COALESCE(SUM(s."Фактически_выполнено_всего"), 0) as total_fact,
                    COALESCE(SUM(CASE 
                        WHEN s."Наименование_вида_услуг" LIKE '%%в т.ч. в сельской местности%%' 
                        THEN s."План_всего" ELSE 0 
                    END), 0) as rural_plan,
                    COALESCE(SUM(CASE 
                        WHEN s."Наименование_вида_услуг" LIKE '%%в т.ч. в сельской местности%%' 
                        THEN s."Фактически_выполнено_всего" ELSE 0 
                    END), 0) as rural_fact
                FROM regions r
                LEFT JOIN districts d ON r."Код_области" = d."Код_области"
                LEFT JOIN services s ON d."Код_района" = s."Код_района"
                GROUP BY r."Код_области", r."Наименование_области"
                ORDER BY r."Наименование_области"
            """)

            regions = []
            for row in cur.fetchall():
                region_code = row[0]
                region_name = row[1]
                enterprises_count = row[2]
                total_plan = float(row[3]) if row[3] else 0.0
                total_fact = float(row[4]) if row[4] else 0.0
                rural_plan = float(row[5]) if row[5] else 0.0
                rural_fact = float(row[6]) if row[6] else 0.0

                # Расчет процентов
                total_percentage = (total_fact / total_plan * 100) if total_plan > 0 else 0.0
                rural_percentage = (rural_fact / rural_plan * 100) if rural_plan > 0 else 0.0

                regions.append({
                    "region_code": region_code,
                    "region_name": region_name,
                    "enterprises_count": enterprises_count,
                    "total_plan": total_plan,
                    "total_fact": total_fact,
                    "total_percentage": total_percentage,
                    "rural_plan": rural_plan,
                    "rural_fact": rural_fact,
                    "rural_percentage": rural_percentage
                })

            return JSONResponse(content={"success": True, "regions": regions})

        except Exception as e:
            print(f"❌ Ошибка в get_district_regions: {e}")
            return JSONResponse(content={"success": False, "error": str(e)})
        finally:
            conn.close()
    else:
        return JSONResponse(content={"success": False, "error": "Ошибка подключения к БД"})


# Добавим в main.py более детальные API endpoints

# API для получения предприятий по области с детальной статистикой (ОБНОВЛЕННАЯ ВЕРСИЯ)
@app.get("/api/district/regions/{region_code}/enterprises")
async def get_region_enterprises(region_code: int):
    """Возвращает список предприятий в области с детальной статистикой"""
    conn = get_main_db_connection()
    if conn:
        try:
            cur = conn.cursor()

            print(f"🔍 Загрузка предприятий для области {region_code}")

            cur.execute("""
                SELECT DISTINCT 
                    e."Регистрационный_номер",
                    e."Наименование_предприятия"
                FROM enterprises e
                JOIN services s ON e."Регистрационный_номер" = s."Регистрационный_номер"
                JOIN districts d ON s."Код_района" = d."Код_района"
                WHERE d."Код_области" = %s
                ORDER BY e."Наименование_предприятия"
            """, (region_code,))

            enterprises_list = cur.fetchall()
            print(f"📊 Найдено предприятий: {len(enterprises_list)}")

            enterprises = []
            for enterprise in enterprises_list:
                reg_number = enterprise[0]
                name = enterprise[1]

                # Получаем статистику для каждого предприятия
                cur.execute("""
                    SELECT 
                        COALESCE(SUM(s."План_всего"), 0) as total_plan,
                        COALESCE(SUM(s."Фактически_выполнено_всего"), 0) as total_fact,
                        COALESCE(SUM(CASE 
                            WHEN s."Наименование_вида_услуг" LIKE '%%в т.ч. в сельской местности%%' 
                            THEN s."План_всего" ELSE 0 
                        END), 0) as rural_plan,
                        COALESCE(SUM(CASE 
                            WHEN s."Наименование_вида_услуг" LIKE '%%в т.ч. в сельской местности%%' 
                            THEN s."Фактически_выполнено_всего" ELSE 0 
                        END), 0) as rural_fact
                    FROM services s
                    JOIN districts d ON s."Код_района" = d."Код_района"
                    WHERE s."Регистрационный_номер" = %s AND d."Код_области" = %s
                """, (reg_number, region_code))

                stats = cur.fetchone()
                if stats:
                    total_plan = float(stats[0]) if stats[0] else 0.0
                    total_fact = float(stats[1]) if stats[1] else 0.0
                    rural_plan = float(stats[2]) if stats[2] else 0.0
                    rural_fact = float(stats[3]) if stats[3] else 0.0

                    enterprises.append({
                        "reg_number": reg_number,
                        "name": name,
                        "total_plan": total_plan,
                        "total_fact": total_fact,
                        "rural_plan": rural_plan,
                        "rural_fact": rural_fact
                    })

            print(f"✅ Успешно загружено {len(enterprises)} предприятий")
            return JSONResponse(content={"success": True, "enterprises": enterprises})

        except Exception as e:
            print(f"❌ Ошибка в get_region_enterprises: {e}")
            import traceback
            print(f"🔍 Детальный traceback: {traceback.format_exc()}")
            return JSONResponse(content={"success": False, "error": str(e)})
        finally:
            conn.close()
    else:
        return JSONResponse(content={"success": False, "error": "Ошибка подключения к БД"})


# API для получения услуг по области с детальной статистикой (ОБНОВЛЕННАЯ ВЕРСИЯ)
@app.get("/api/district/regions/{region_code}/services")
async def get_region_services(region_code: int):
    """Возвращает список услуг в области с детальной статистикой"""
    conn = get_main_db_connection()
    if conn:
        try:
            cur = conn.cursor()

            print(f"🔍 Загрузка услуг для области {region_code}")

            # Получаем все виды услуг
            cur.execute('SELECT "Наименование_вида_услуг" FROM service_types ORDER BY "Наименование_вида_услуг"')
            all_services = [row[0] for row in cur.fetchall()]

            services = []

            for service_name in all_services:
                # Для каждого вида услуг получаем статистику по области
                cur.execute("""
                    SELECT 
                        COALESCE(SUM(s."План_всего"), 0) as plan_total,
                        COALESCE(SUM(s."Фактически_выполнено_всего"), 0) as fact_total
                    FROM services s
                    JOIN districts d ON s."Код_района" = d."Код_района"
                    WHERE d."Код_области" = %s AND s."Наименование_вида_услуг" = %s
                """, (region_code, service_name))

                stats = cur.fetchone()
                plan_total = float(stats[0]) if stats[0] else 0.0
                fact_total = float(stats[1]) if stats[1] else 0.0
                percentage = (fact_total / plan_total * 100) if plan_total > 0 else 0.0

                services.append({
                    "service_name": service_name,
                    "plan_total": plan_total,
                    "fact_total": fact_total,
                    "percentage": percentage
                })

            print(f"✅ Успешно загружено {len(services)} услуг")
            return JSONResponse(content={"success": True, "services": services})

        except Exception as e:
            print(f"❌ Ошибка в get_region_services: {e}")
            import traceback
            print(f"🔍 Детальный traceback: {traceback.format_exc()}")
            return JSONResponse(content={"success": False, "error": str(e)})
        finally:
            conn.close()
    else:
        return JSONResponse(content={"success": False, "error": "Ошибка подключения к БД"})


# API для получения детальной информации по услугам предприятия в области
@app.get("/api/district/regions/{region_code}/enterprises/{enterprise_id}/services")
async def get_enterprise_region_services(region_code: int, enterprise_id: int):
    """Возвращает детальную информацию по услугам предприятия в области"""
    conn = get_main_db_connection()
    if conn:
        try:
            cur = conn.cursor()

            print(f"🔍 Загрузка услуг предприятия {enterprise_id} в области {region_code}")

            # Получаем информацию о предприятии
            cur.execute("""
                SELECT "Наименование_предприятия" 
                FROM enterprises 
                WHERE "Регистрационный_номер" = %s
            """, (enterprise_id,))

            enterprise_result = cur.fetchone()
            if not enterprise_result:
                return JSONResponse(content={"success": False, "error": "Предприятие не найдено"})

            enterprise_name = enterprise_result[0]

            # Получаем все виды услуг
            cur.execute('SELECT "Наименование_вида_услуг" FROM service_types ORDER BY "Наименование_вида_услуг"')
            all_services = [row[0] for row in cur.fetchall()]

            services = []

            for service_name in all_services:
                # Для каждого вида услуг получаем статистику по предприятию в области
                cur.execute("""
                    SELECT 
                        COALESCE(SUM(s."План_всего"), 0) as plan_total,
                        COALESCE(SUM(s."Фактически_выполнено_всего"), 0) as fact_total
                    FROM services s
                    JOIN districts d ON s."Код_района" = d."Код_района"
                    WHERE d."Код_области" = %s 
                        AND s."Регистрационный_номер" = %s 
                        AND s."Наименование_вида_услуг" = %s
                """, (region_code, enterprise_id, service_name))

                stats = cur.fetchone()
                plan_total = float(stats[0]) if stats[0] else 0.0
                fact_total = float(stats[1]) if stats[1] else 0.0
                percentage = (fact_total / plan_total * 100) if plan_total > 0 else 0.0

                services.append({
                    "service_name": service_name,
                    "plan_total": plan_total,
                    "fact_total": fact_total,
                    "percentage": percentage
                })

            return JSONResponse(content={
                "success": True,
                "enterprise_name": enterprise_name,
                "enterprise_id": enterprise_id,
                "region_code": region_code,
                "services": services
            })

        except Exception as e:
            print(f"❌ Ошибка в get_enterprise_region_services: {e}")
            import traceback
            print(f"🔍 Детальный traceback: {traceback.format_exc()}")
            return JSONResponse(content={"success": False, "error": str(e)})
        finally:
            conn.close()
    else:
        return JSONResponse(content={"success": False, "error": "Ошибка подключения к БД"})

#------------------------------------------------------------------------------------------------------
# API для получения районов по области со статистикой
@app.get("/api/district/regions/{region_code}/districts")
async def get_district_region_districts(region_code: int):
    """Возвращает список районов в области с агрегированной статистикой"""
    conn = get_main_db_connection()
    if conn:
        try:
            cur = conn.cursor()

            # Получаем районы в области с общей статистикой
            cur.execute("""
                SELECT 
                    d."Код_района",
                    d."Наименование_района",
                    COUNT(DISTINCT s."Регистрационный_номер") as enterprises_count,
                    COALESCE(SUM(s."План_всего"), 0) as total_plan,
                    COALESCE(SUM(s."Фактически_выполнено_всего"), 0) as total_fact,
                    COALESCE(SUM(CASE 
                        WHEN s."Наименование_вида_услуг" LIKE '%%в т.ч. в сельской местности%%' 
                        THEN s."План_всего" ELSE 0 
                    END), 0) as rural_plan,
                    COALESCE(SUM(CASE 
                        WHEN s."Наименование_вида_услуг" LIKE '%%в т.ч. в сельской местности%%' 
                        THEN s."Фактически_выполнено_всего" ELSE 0 
                    END), 0) as rural_fact
                FROM districts d
                LEFT JOIN services s ON d."Код_района" = s."Код_района"
                WHERE d."Код_области" = %s
                GROUP BY d."Код_района", d."Наименование_района"
                ORDER BY d."Наименование_района"
            """, (region_code,))

            districts = []
            for row in cur.fetchall():
                district_code = row[0]
                district_name = row[1]
                enterprises_count = row[2]
                total_plan = float(row[3]) if row[3] else 0.0
                total_fact = float(row[4]) if row[4] else 0.0
                rural_plan = float(row[5]) if row[5] else 0.0
                rural_fact = float(row[6]) if row[6] else 0.0

                # Расчет процентов
                total_percentage = (total_fact / total_plan * 100) if total_plan > 0 else 0.0
                rural_percentage = (rural_fact / rural_plan * 100) if rural_plan > 0 else 0.0

                districts.append({
                    "district_code": district_code,
                    "district_name": district_name,
                    "enterprises_count": enterprises_count,
                    "total_plan": total_plan,
                    "total_fact": total_fact,
                    "total_percentage": total_percentage,
                    "rural_plan": rural_plan,
                    "rural_fact": rural_fact,
                    "rural_percentage": rural_percentage
                })

            return JSONResponse(content={"success": True, "districts": districts})

        except Exception as e:
            print(f"❌ Ошибка в get_district_region_districts: {e}")
            return JSONResponse(content={"success": False, "error": str(e)})
        finally:
            conn.close()
    else:
        return JSONResponse(content={"success": False, "error": "Ошибка подключения к БД"})


# API для получения периодов по району со статистикой
@app.get("/api/district/districts/{district_code}/periods")
async def get_district_district_periods(district_code: int):
    """Возвращает список периодов для района с агрегированной статистикой"""
    conn = get_main_db_connection()
    if conn:
        try:
            cur = conn.cursor()

            # Получаем уникальные периоды для района
            cur.execute("""
                SELECT DISTINCT "Отчетный_период"
                FROM services
                WHERE "Код_района" = %s
                ORDER BY "Отчетный_период" DESC
            """, (district_code,))

            periods_data = cur.fetchall()
            periods = []

            for period in periods_data:
                year = period[0]

                # Статистика за текущий год
                cur.execute("""
                    SELECT 
                        COUNT(DISTINCT "Регистрационный_номер") as enterprises_count,
                        COALESCE(SUM("План_всего"), 0) as total_plan,
                        COALESCE(SUM("Фактически_выполнено_всего"), 0) as total_fact,
                        COALESCE(SUM(CASE 
                            WHEN "Наименование_вида_услуг" LIKE '%%в т.ч. в сельской местности%%' 
                            THEN "План_всего" ELSE 0 
                        END), 0) as rural_plan,
                        COALESCE(SUM(CASE 
                            WHEN "Наименование_вида_услуг" LIKE '%%в т.ч. в сельской местности%%' 
                            THEN "Фактически_выполнено_всего" ELSE 0 
                        END), 0) as rural_fact
                    FROM services
                    WHERE "Код_района" = %s AND "Отчетный_период" = %s
                """, (district_code, year))

                current_stats = cur.fetchone()
                enterprises_count = current_stats[0]
                total_plan = float(current_stats[1]) if current_stats[1] else 0.0
                total_fact = float(current_stats[2]) if current_stats[2] else 0.0
                rural_plan = float(current_stats[3]) if current_stats[3] else 0.0
                rural_fact = float(current_stats[4]) if current_stats[4] else 0.0

                # Проценты выполнения
                total_percentage = (total_fact / total_plan * 100) if total_plan > 0 else 0.0
                rural_percentage = (rural_fact / rural_plan * 100) if rural_plan > 0 else 0.0

                # Статистика за предыдущий год для динамики
                previous_year = year - 1
                cur.execute("""
                    SELECT 
                        COALESCE(SUM("Фактически_выполнено_всего"), 0) as prev_total_fact,
                        COALESCE(SUM(CASE 
                            WHEN "Наименование_вида_услуг" LIKE '%%в т.ч. в сельской местности%%' 
                            THEN "Фактически_выполнено_всего" ELSE 0 
                        END), 0) as prev_rural_fact
                    FROM services
                    WHERE "Код_района" = %s AND "Отчетный_период" = %s
                """, (district_code, previous_year))

                prev_stats = cur.fetchone()
                prev_total_fact = float(prev_stats[0]) if prev_stats[0] else 0.0
                prev_rural_fact = float(prev_stats[1]) if prev_stats[1] else 0.0

                # Расчет динамики
                dynamics_total = (total_fact / prev_total_fact * 100) if prev_total_fact > 0 else 0.0
                dynamics_rural = (rural_fact / prev_rural_fact * 100) if prev_rural_fact > 0 else 0.0

                periods.append({
                    "year": year,
                    "enterprises_count": enterprises_count,
                    "total_plan": total_plan,
                    "total_fact": total_fact,
                    "total_percentage": total_percentage,
                    "rural_plan": rural_plan,
                    "rural_fact": rural_fact,
                    "rural_percentage": rural_percentage,
                    "dynamics_total": dynamics_total,
                    "dynamics_rural": dynamics_rural
                })

            return JSONResponse(content={"success": True, "periods": periods})

        except Exception as e:
            print(f"❌ Ошибка в get_district_district_periods: {e}")
            return JSONResponse(content={"success": False, "error": str(e)})
        finally:
            conn.close()
    else:
        return JSONResponse(content={"success": False, "error": "Ошибка подключения к БД"})





#-------------------------------------------------------------------------------------------------------

# Сводный отчет по району - главная страница (выбор области)
@app.get("/reports/district")
async def district_reports_main(request: Request):
    user_login = request.query_params.get("user_login")
    user_role = request.query_params.get("user_role")

    if not user_login or not user_role:
        return templates.TemplateResponse("auth/check_auth.html", {"request": request})

    return templates.TemplateResponse("reports/district/step0_regions.html", {
        "request": request,
        "username": user_login,
        "user_role": user_role
    })

# Шаг 1: Выбор района в области
@app.get("/reports/district/regions/{region_code}/districts")
async def district_region_districts(request: Request, region_code: int):
    user_login = request.query_params.get("user_login")
    user_role = request.query_params.get("user_role")

    if not user_login or not user_role:
        return templates.TemplateResponse("auth/check_auth.html", {"request": request})

    return templates.TemplateResponse("reports/district/step1_districts.html", {
        "request": request,
        "username": user_login,
        "user_role": user_role,
        "region_code": region_code
    })

# Шаг 2: Выбор периода для района
# Шаг 2: Выбор периода для района
@app.get("/reports/district/districts/{district_code}/periods")
async def district_district_periods(request: Request, district_code: int):
    user_login = request.query_params.get("user_login")
    user_role = request.query_params.get("user_role")
    
    # Получаем region_code из query parameters
    region_code = request.query_params.get("region_code")
    
    if not user_login or not user_role:
        return templates.TemplateResponse("auth/check_auth.html", {"request": request})

    return templates.TemplateResponse("reports/district/step2_periods.html", {
        "request": request,
        "username": user_login,
        "user_role": user_role,
        "district_code": district_code,
        "region_code": region_code
    })



#-----------------------------------------------------------------------------

# API для получения предприятий в районе с детальной статистикой
@app.get("/api/district/districts/{district_code}/enterprises")
async def get_district_enterprises(district_code: int):
    """Возвращает список предприятий в районе с детальной статистикой"""
    conn = get_main_db_connection()
    if conn:
        try:
            cur = conn.cursor()

            # Получаем предприятия, которые предоставляли услуги в этом районе
            cur.execute("""
                SELECT DISTINCT 
                    e."Регистрационный_номер",
                    e."Наименование_предприятия"
                FROM enterprises e
                JOIN services s ON e."Регистрационный_номер" = s."Регистрационный_номер"
                WHERE s."Код_района" = %s
                ORDER BY e."Наименование_предприятия"
            """, (district_code,))

            enterprises_list = cur.fetchall()
            enterprises = []

            for enterprise in enterprises_list:
                reg_number = enterprise[0]
                name = enterprise[1]

                # Получаем статистику для предприятия в этом районе
                cur.execute("""
                    SELECT 
                        COALESCE(SUM(s."План_всего"), 0) as total_plan,
                        COALESCE(SUM(s."Фактически_выполнено_всего"), 0) as total_fact,
                        COALESCE(SUM(CASE 
                            WHEN s."Наименование_вида_услуг" LIKE '%%в т.ч. в сельской местности%%' 
                            THEN s."План_всего" ELSE 0 
                        END), 0) as rural_plan,
                        COALESCE(SUM(CASE 
                            WHEN s."Наименование_вида_услуг" LIKE '%%в т.ч. в сельской местности%%' 
                            THEN s."Фактически_выполнено_всего" ELSE 0 
                        END), 0) as rural_fact
                    FROM services s
                    WHERE s."Регистрационный_номер" = %s AND s."Код_района" = %s
                """, (reg_number, district_code))

                stats = cur.fetchone()
                if stats:
                    total_plan = float(stats[0]) if stats[0] else 0.0
                    total_fact = float(stats[1]) if stats[1] else 0.0
                    rural_plan = float(stats[2]) if stats[2] else 0.0
                    rural_fact = float(stats[3]) if stats[3] else 0.0

                    enterprises.append({
                        "reg_number": reg_number,
                        "name": name,
                        "total_plan": total_plan,
                        "total_fact": total_fact,
                        "rural_plan": rural_plan,
                        "rural_fact": rural_fact
                    })

            return JSONResponse(content={"success": True, "enterprises": enterprises})

        except Exception as e:
            print(f"❌ Ошибка в get_district_enterprises: {e}")
            return JSONResponse(content={"success": False, "error": str(e)})
        finally:
            conn.close()
    else:
        return JSONResponse(content={"success": False, "error": "Ошибка подключения к БД"})


# API для получения услуг в районе с детальной статистикой
@app.get("/api/district/districts/{district_code}/services")
async def get_district_services(district_code: int):
    """Возвращает список услуг в районе с детальной статистикой"""
    conn = get_main_db_connection()
    if conn:
        try:
            cur = conn.cursor()

            # Получаем все виды услуг
            cur.execute('SELECT "Наименование_вида_услуг" FROM service_types ORDER BY "Наименование_вида_услуг"')
            all_services = [row[0] for row in cur.fetchall()]

            services = []

            for service_name in all_services:
                # Для каждого вида услуг получаем статистику по району
                cur.execute("""
                    SELECT 
                        COALESCE(SUM(s."План_всего"), 0) as plan_total,
                        COALESCE(SUM(s."Фактически_выполнено_всего"), 0) as fact_total
                    FROM services s
                    WHERE s."Код_района" = %s AND s."Наименование_вида_услуг" = %s
                """, (district_code, service_name))

                stats = cur.fetchone()
                plan_total = float(stats[0]) if stats[0] else 0.0
                fact_total = float(stats[1]) if stats[1] else 0.0
                percentage = (fact_total / plan_total * 100) if plan_total > 0 else 0.0

                services.append({
                    "service_name": service_name,
                    "plan_total": plan_total,
                    "fact_total": fact_total,
                    "percentage": percentage
                })

            return JSONResponse(content={"success": True, "services": services})

        except Exception as e:
            print(f"❌ Ошибка в get_district_services: {e}")
            return JSONResponse(content={"success": False, "error": str(e)})
        finally:
            conn.close()
    else:
        return JSONResponse(content={"success": False, "error": "Ошибка подключения к БД"})


# API для получения детальной информации по услугам предприятия в районе
@app.get("/api/district/districts/{district_code}/enterprises/{enterprise_id}/services")
async def get_enterprise_district_services(district_code: int, enterprise_id: int):
    """Возвращает детальную информацию по услугам предприятия в районе"""
    conn = get_main_db_connection()
    if conn:
        try:
            cur = conn.cursor()

            # Получаем информацию о предприятии
            cur.execute("""
                SELECT "Наименование_предприятия" 
                FROM enterprises 
                WHERE "Регистрационный_номер" = %s
            """, (enterprise_id,))

            enterprise_result = cur.fetchone()
            if not enterprise_result:
                return JSONResponse(content={"success": False, "error": "Предприятие не найдено"})

            enterprise_name = enterprise_result[0]

            # Получаем все виды услуг
            cur.execute('SELECT "Наименование_вида_услуг" FROM service_types ORDER BY "Наименование_вида_услуг"')
            all_services = [row[0] for row in cur.fetchall()]

            services = []

            for service_name in all_services:
                # Для каждого вида услуг получаем статистику по предприятию в районе
                cur.execute("""
                    SELECT 
                        COALESCE(SUM(s."План_всего"), 0) as plan_total,
                        COALESCE(SUM(s."Фактически_выполнено_всего"), 0) as fact_total
                    FROM services s
                    WHERE s."Код_района" = %s 
                        AND s."Регистрационный_номер" = %s 
                        AND s."Наименование_вида_услуг" = %s
                """, (district_code, enterprise_id, service_name))

                stats = cur.fetchone()
                plan_total = float(stats[0]) if stats[0] else 0.0
                fact_total = float(stats[1]) if stats[1] else 0.0
                percentage = (fact_total / plan_total * 100) if plan_total > 0 else 0.0

                services.append({
                    "service_name": service_name,
                    "plan_total": plan_total,
                    "fact_total": fact_total,
                    "percentage": percentage
                })

            return JSONResponse(content={
                "success": True,
                "enterprise_name": enterprise_name,
                "enterprise_id": enterprise_id,
                "district_code": district_code,
                "services": services
            })

        except Exception as e:
            print(f"❌ Ошибка в get_enterprise_district_services: {e}")
            return JSONResponse(content={"success": False, "error": str(e)})
        finally:
            conn.close()
    else:
        return JSONResponse(content={"success": False, "error": "Ошибка подключения к БД"})
    
#----------------------------------------------------------------------------------------------
# 

# API для получения услуг в районе за конкретный период с динамикой
@app.get("/api/district/districts/{district_code}/periods/{year}/services")
async def get_district_period_services(district_code: int, year: int):
    """Возвращает детальную информацию по услугам в районе за период с динамикой"""
    conn = get_main_db_connection()
    if conn:
        try:
            cur = conn.cursor()

            # Получаем все виды услуг
            cur.execute('SELECT "Наименование_вида_услуг" FROM service_types ORDER BY "Наименование_вида_услуг"')
            all_services = [row[0] for row in cur.fetchall()]

            services = []

            for service_name in all_services:
                # Данные за текущий год
                cur.execute("""
                    SELECT 
                        COALESCE(SUM(s."План_всего"), 0) as plan_total,
                        COALESCE(SUM(s."Фактически_выполнено_всего"), 0) as fact_total
                    FROM services s
                    WHERE s."Код_района" = %s 
                        AND s."Отчетный_период" = %s 
                        AND s."Наименование_вида_услуг" = %s
                """, (district_code, year, service_name))

                current_stats = cur.fetchone()
                plan_total = float(current_stats[0]) if current_stats[0] else 0.0
                fact_total = float(current_stats[1]) if current_stats[1] else 0.0
                percentage = (fact_total / plan_total * 100) if plan_total > 0 else 0.0

                # Данные за предыдущий год для динамики
                previous_year = year - 1
                cur.execute("""
                    SELECT 
                        COALESCE(SUM(s."Фактически_выполнено_всего"), 0) as previous_fact
                    FROM services s
                    WHERE s."Код_района" = %s 
                        AND s."Отчетный_период" = %s 
                        AND s."Наименование_вида_услуг" = %s
                """, (district_code, previous_year, service_name))

                previous_stats = cur.fetchone()
                previous_fact = float(previous_stats[0]) if previous_stats[0] else 0.0

                # Расчет динамики
                dynamics = (fact_total / previous_fact * 100) if previous_fact > 0 else None

                services.append({
                    "service_name": service_name,
                    "plan_total": plan_total,
                    "fact_total": fact_total,
                    "percentage": percentage,
                    "dynamics": dynamics
                })

            return JSONResponse(content={
                "success": True,
                "services": services,
                "current_year": year,
                "previous_year": previous_year
            })

        except Exception as e:
            print(f"❌ Ошибка в get_district_period_services: {e}")
            return JSONResponse(content={"success": False, "error": str(e)})
        finally:
            conn.close()
    else:
        return JSONResponse(content={"success": False, "error": "Ошибка подключения к БД"})


# API для получения предприятий в районе за период с динамикой
@app.get("/api/district/districts/{district_code}/periods/{year}/enterprises")
async def get_district_period_enterprises(district_code: int, year: int):
    """Возвращает детальную информацию по предприятиям в районе за период с динамикой"""
    conn = get_main_db_connection()
    if conn:
        try:
            cur = conn.cursor()

            # Получаем предприятия, которые предоставляли услуги в этом районе за указанный год
            cur.execute("""
                SELECT DISTINCT e."Регистрационный_номер", e."Наименование_предприятия"
                FROM enterprises e
                JOIN services s ON e."Регистрационный_номер" = s."Регистрационный_номер"
                WHERE s."Код_района" = %s AND s."Отчетный_период" = %s
                ORDER BY e."Наименование_предприятия"
            """, (district_code, year))

            enterprises_data = cur.fetchall()
            enterprises = []

            for enterprise in enterprises_data:
                reg_number = enterprise[0]
                name = enterprise[1]

                # Статистика за текущий год
                cur.execute("""
                    SELECT 
                        COALESCE(SUM(s."План_всего"), 0) as total_plan,
                        COALESCE(SUM(s."Фактически_выполнено_всего"), 0) as total_fact,
                        COALESCE(SUM(CASE 
                            WHEN s."Наименование_вида_услуг" LIKE '%%в т.ч. в сельской местности%%' 
                            THEN s."План_всего" ELSE 0 
                        END), 0) as rural_plan,
                        COALESCE(SUM(CASE 
                            WHEN s."Наименование_вида_услуг" LIKE '%%в т.ч. в сельской местности%%' 
                            THEN s."Фактически_выполнено_всего" ELSE 0 
                        END), 0) as rural_fact
                    FROM services s
                    WHERE s."Регистрационный_номер" = %s 
                        AND s."Код_района" = %s 
                        AND s."Отчетный_период" = %s
                """, (reg_number, district_code, year))

                current_stats = cur.fetchone()
                total_plan = float(current_stats[0]) if current_stats[0] else 0.0
                total_fact = float(current_stats[1]) if current_stats[1] else 0.0
                rural_plan = float(current_stats[2]) if current_stats[2] else 0.0
                rural_fact = float(current_stats[3]) if current_stats[3] else 0.0

                # Статистика за предыдущий год для динамики
                previous_year = year - 1
                cur.execute("""
                    SELECT 
                        COALESCE(SUM(s."Фактически_выполнено_всего"), 0) as prev_total_fact,
                        COALESCE(SUM(CASE 
                            WHEN s."Наименование_вида_услуг" LIKE '%%в т.ч. в сельской местности%%' 
                            THEN s."Фактически_выполнено_всего" ELSE 0 
                        END), 0) as prev_rural_fact
                    FROM services s
                    WHERE s."Регистрационный_номер" = %s 
                        AND s."Код_района" = %s 
                        AND s."Отчетный_период" = %s
                """, (reg_number, district_code, previous_year))

                prev_stats = cur.fetchone()
                prev_total_fact = float(prev_stats[0]) if prev_stats[0] else 0.0
                prev_rural_fact = float(prev_stats[1]) if prev_stats[1] else 0.0

                # Расчет динамики
                dynamics_total = (total_fact / prev_total_fact * 100) if prev_total_fact > 0 else 0.0
                dynamics_rural = (rural_fact / prev_rural_fact * 100) if prev_rural_fact > 0 else 0.0

                enterprises.append({
                    "reg_number": reg_number,
                    "name": name,
                    "total_plan": total_plan,
                    "total_fact": total_fact,
                    "rural_plan": rural_plan,
                    "rural_fact": rural_fact,
                    "dynamics_total": dynamics_total,
                    "dynamics_rural": dynamics_rural
                })

            return JSONResponse(content={"success": True, "enterprises": enterprises})

        except Exception as e:
            print(f"❌ Ошибка в get_district_period_enterprises: {e}")
            return JSONResponse(content={"success": False, "error": str(e)})
        finally:
            conn.close()
    else:
        return JSONResponse(content={"success": False, "error": "Ошибка подключения к БД"})
    
# API для получения детальной информации по услугам предприятия в районе за конкретный период с динамикой
@app.get("/api/district/districts/{district_code}/periods/{year}/enterprises/{enterprise_id}/services")
async def get_enterprise_district_period_services(district_code: int, year: int, enterprise_id: int):
    """Возвращает детальную информацию по услугам предприятия в районе за период с динамикой"""
    conn = get_main_db_connection()
    if conn:
        try:
            cur = conn.cursor()

            # Получаем информацию о предприятии
            cur.execute("""
                SELECT "Наименование_предприятия" 
                FROM enterprises 
                WHERE "Регистрационный_номер" = %s
            """, (enterprise_id,))

            enterprise_result = cur.fetchone()
            if not enterprise_result:
                return JSONResponse(content={"success": False, "error": "Предприятие не найдено"})

            enterprise_name = enterprise_result[0]

            # Получаем все виды услуг
            cur.execute('SELECT "Наименование_вида_услуг" FROM service_types ORDER BY "Наименование_вида_услуг"')
            all_services = [row[0] for row in cur.fetchall()]

            services = []

            for service_name in all_services:
                # Данные за текущий год
                cur.execute("""
                    SELECT 
                        COALESCE(SUM(s."План_всего"), 0) as plan_total,
                        COALESCE(SUM(s."Фактически_выполнено_всего"), 0) as fact_total
                    FROM services s
                    WHERE s."Код_района" = %s 
                        AND s."Отчетный_период" = %s 
                        AND s."Регистрационный_номер" = %s
                        AND s."Наименование_вида_услуг" = %s
                """, (district_code, year, enterprise_id, service_name))

                current_stats = cur.fetchone()
                plan_total = float(current_stats[0]) if current_stats[0] else 0.0
                fact_total = float(current_stats[1]) if current_stats[1] else 0.0
                percentage = (fact_total / plan_total * 100) if plan_total > 0 else 0.0

                # Данные за предыдущий год для динамики
                previous_year = year - 1
                cur.execute("""
                    SELECT 
                        COALESCE(SUM(s."Фактически_выполнено_всего"), 0) as previous_fact
                    FROM services s
                    WHERE s."Код_района" = %s 
                        AND s."Отчетный_период" = %s 
                        AND s."Регистрационный_номер" = %s
                        AND s."Наименование_вида_услуг" = %s
                """, (district_code, previous_year, enterprise_id, service_name))

                previous_stats = cur.fetchone()
                previous_fact = float(previous_stats[0]) if previous_stats[0] else 0.0

                # Расчет динамики
                dynamics = (fact_total / previous_fact * 100) if previous_fact > 0 else None

                services.append({
                    "service_name": service_name,
                    "plan_total": plan_total,
                    "fact_total": fact_total,
                    "percentage": percentage,
                    "dynamics": dynamics
                })

            return JSONResponse(content={
                "success": True,
                "enterprise_name": enterprise_name,
                "enterprise_id": enterprise_id,
                "district_code": district_code,
                "year": year,
                "services": services
            })

        except Exception as e:
            print(f"❌ Ошибка в get_enterprise_district_period_services: {e}")
            return JSONResponse(content={"success": False, "error": str(e)})
        finally:
            conn.close()
    else:
        return JSONResponse(content={"success": False, "error": "Ошибка подключения к БД"})

    #----------------------------------------------------------------------------------------------

    # Добавим после существующих API для сводного отчета

# API для получения сводного отчета по району за период# Добавим после существующих API для сводного отчета

# API для получения сводного отчета по району за период
@app.get("/api/district/districts/{district_code}/periods/{year}/summary")
async def get_district_period_summary(district_code: int, year: int):
    """Возвращает данные для сводного отчета по району за период"""
    conn = get_main_db_connection()
    if conn:
        try:
            cur = conn.cursor()
            print(f"🔍 Формирование сводного отчета для района {district_code} за {year} год")

            # 1. Получаем информацию о районе
            cur.execute("""
                SELECT d."Наименование_района", d."Код_района", r."Наименование_области", r."Код_области"
                FROM districts d
                JOIN regions r ON d."Код_области" = r."Код_области"
                WHERE d."Код_района" = %s
            """, (district_code,))
            
            district_info = cur.fetchone()
            if not district_info:
                return JSONResponse(content={"success": False, "error": "Район не найден"})

            district_name = district_info[0]
            region_name = district_info[2]
            region_code = district_info[3]

            # 2. Получаем предприятия в районе за указанный период с детальной статистикой
            cur.execute("""
                SELECT DISTINCT 
                    e."Регистрационный_номер",
                    e."Наименование_предприятия"
                FROM enterprises e
                JOIN services s ON e."Регистрационный_номер" = s."Регистрационный_номер"
                WHERE s."Код_района" = %s AND s."Отчетный_период" = %s
                ORDER BY e."Наименование_предприятия"
            """, (district_code, year))

            enterprises_list = cur.fetchall()
            enterprises = []

            # Итоговые суммы
            total_plan_all = 0
            total_rural_plan_all = 0
            total_fact_all = 0
            total_rural_fact_all = 0

            for enterprise in enterprises_list:
                reg_number = enterprise[0]
                name = enterprise[1]

                # Статистика за текущий год
                cur.execute("""
                    SELECT 
                        COALESCE(SUM(s."План_всего"), 0) as total_plan,
                        COALESCE(SUM(s."Фактически_выполнено_всего"), 0) as total_fact,
                        COALESCE(SUM(CASE 
                            WHEN s."Наименование_вида_услуг" LIKE '%%в т.ч. в сельской местности%%' 
                            THEN s."План_всего" ELSE 0 
                        END), 0) as rural_plan,
                        COALESCE(SUM(CASE 
                            WHEN s."Наименование_вида_услуг" LIKE '%%в т.ч. в сельской местности%%' 
                            THEN s."Фактически_выполнено_всего" ELSE 0 
                        END), 0) as rural_fact
                    FROM services s
                    WHERE s."Регистрационный_номер" = %s 
                        AND s."Код_района" = %s 
                        AND s."Отчетный_период" = %s
                """, (reg_number, district_code, year))

                current_stats = cur.fetchone()
                total_plan = float(current_stats[0]) if current_stats[0] else 0.0
                total_fact = float(current_stats[1]) if current_stats[1] else 0.0
                rural_plan = float(current_stats[2]) if current_stats[2] else 0.0
                rural_fact = float(current_stats[3]) if current_stats[3] else 0.0

                # Статистика за предыдущий год для динамики
                previous_year = year - 1
                cur.execute("""
                    SELECT 
                        COALESCE(SUM(s."Фактически_выполнено_всего"), 0) as prev_total_fact,
                        COALESCE(SUM(CASE 
                            WHEN s."Наименование_вида_услуг" LIKE '%%в т.ч. в сельской местности%%' 
                            THEN s."Фактически_выполнено_всего" ELSE 0 
                        END), 0) as prev_rural_fact
                    FROM services s
                    WHERE s."Регистрационный_номер" = %s 
                        AND s."Код_района" = %s 
                        AND s."Отчетный_период" = %s
                """, (reg_number, district_code, previous_year))

                prev_stats = cur.fetchone()
                prev_total_fact = float(prev_stats[0]) if prev_stats[0] else 0.0
                prev_rural_fact = float(prev_stats[1]) if prev_stats[1] else 0.0

                # Расчет динамики
                dynamics_total = (total_fact / prev_total_fact * 100) if prev_total_fact > 0 else 0.0
                dynamics_rural = (rural_fact / prev_rural_fact * 100) if prev_rural_fact > 0 else 0.0

                # Суммируем для итогов
                total_plan_all += total_plan
                total_rural_plan_all += rural_plan
                total_fact_all += total_fact
                total_rural_fact_all += rural_fact

                enterprises.append({
                    "reg_number": reg_number,
                    "name": name,
                    "total_plan": total_plan,
                    "rural_plan": rural_plan,
                    "total_fact": total_fact,
                    "rural_fact": rural_fact,
                    "dynamics_total": dynamics_total,
                    "dynamics_rural": dynamics_rural
                })

            # Расчет итоговой динамики
            prev_year_total_query = """
                SELECT 
                    COALESCE(SUM(s."Фактически_выполнено_всего"), 0) as prev_total_fact,
                    COALESCE(SUM(CASE 
                        WHEN s."Наименование_вида_услуг" LIKE '%%в т.ч. в сельской местности%%' 
                        THEN s."Фактически_выполнено_всего" ELSE 0 
                    END), 0) as prev_rural_fact
                FROM services s
                WHERE s."Код_района" = %s AND s."Отчетный_период" = %s
            """
            cur.execute(prev_year_total_query, (district_code, year - 1))
            prev_totals = cur.fetchone()
            prev_total_fact_all = float(prev_totals[0]) if prev_totals[0] else 0.0
            prev_rural_fact_all = float(prev_totals[1]) if prev_totals[1] else 0.0

            dynamics_total_all = (total_fact_all / prev_total_fact_all * 100) if prev_total_fact_all > 0 else 0.0
            dynamics_rural_all = (total_rural_fact_all / prev_rural_fact_all * 100) if prev_rural_fact_all > 0 else 0.0

            summary_data = {
                "district_name": district_name,
                "district_code": district_code,
                "region_name": region_name,
                "region_code": region_code,
                "year": year,
                "enterprises": enterprises,
                "totals": {
                    "total_plan": total_plan_all,
                    "rural_plan": total_rural_plan_all,
                    "total_fact": total_fact_all,
                    "rural_fact": total_rural_fact_all,
                    "dynamics_total": dynamics_total_all,
                    "dynamics_rural": dynamics_rural_all
                }
            }

            return JSONResponse(content={"success": True, "summary_data": summary_data})

        except Exception as e:
            print(f"❌ Ошибка в get_district_period_summary: {e}")
            import traceback
            print(f"🔍 Детальный traceback: {traceback.format_exc()}")
            return JSONResponse(content={"success": False, "error": str(e)})
        finally:
            conn.close()
    else:
        return JSONResponse(content={"success": False, "error": "Ошибка подключения к БД"})
    
# Шаг 3: Сводный отчет по району за период
# Шаг 3: Сводный отчет по району за период
@app.get("/reports/district/districts/{district_code}/periods/{year}/summary")
async def district_period_summary(request: Request, district_code: int, year: int):
    user_login = request.query_params.get("user_login")
    user_role = request.query_params.get("user_role")
    region_code = request.query_params.get("region_code")
    
    if not user_login or not user_role:
        return templates.TemplateResponse("auth/check_auth.html", {"request": request})

    return templates.TemplateResponse("reports/district/step3_summary.html", {
        "request": request,
        "username": user_login,
        "user_role": user_role,
        "district_code": district_code,
        "year": year,
        "region_code": region_code
    })

#-------------------------------------------------------------------------------------------------------

# API для получения списка предприятий в районе за период (упрощенная версия)
@app.get("/api/district/districts/{district_code}/periods/{year}/enterprises-list")
async def get_district_enterprises_list(district_code: int, year: int):
    """Возвращает список предприятий в районе за период для генерации отчетов"""
    conn = get_main_db_connection()
    if conn:
        try:
            cur = conn.cursor()

            # Получаем информацию о районе
            cur.execute("""
                SELECT d."Наименование_района", r."Наименование_области"
                FROM districts d
                JOIN regions r ON d."Код_области" = r."Код_области"
                WHERE d."Код_района" = %s
            """, (district_code,))
            
            district_info = cur.fetchone()
            if not district_info:
                return JSONResponse(content={"success": False, "error": "Район не найден"})

            # Получаем предприятия
            cur.execute("""
                SELECT DISTINCT 
                    e."Регистрационный_номер",
                    e."Наименование_предприятия"
                FROM enterprises e
                JOIN services s ON e."Регистрационный_номер" = s."Регистрационный_номер"
                WHERE s."Код_района" = %s AND s."Отчетный_период" = %s
                ORDER BY e."Наименование_предприятия"
            """, (district_code, year))

            enterprises_list = cur.fetchall()
            enterprises = [{"reg_number": row[0], "name": row[1]} for row in enterprises_list]

            return JSONResponse(content={
                "success": True,
                "district_name": district_info[0],
                "region_name": district_info[1],
                "year": year,
                "enterprises": enterprises
            })

        except Exception as e:
            print(f"❌ Ошибка в get_district_enterprises_list: {e}")
            return JSONResponse(content={"success": False, "error": str(e)})
        finally:
            conn.close()
    else:
        return JSONResponse(content={"success": False, "error": "Ошибка подключения к БД"})
    


# Новый endpoint для серверного рендеринга всех отчетов
@app.get("/reports/district/districts/{district_code}/periods/{year}/combined-reports-server")
async def combined_enterprise_reports_server(request: Request, district_code: int, year: int):
    """Страница с объединенными отчетами всех предприятий (серверный рендеринг)"""
    user_login = request.query_params.get("user_login")
    user_role = request.query_params.get("user_role")
    region_code = request.query_params.get("region_code")
    
    if not user_login or not user_role:
        return templates.TemplateResponse("auth/check_auth.html", {"request": request})

    # Получаем список предприятий
    enterprises_response = await get_district_enterprises_list(district_code, year)
    enterprises_data = enterprises_response.body
    import json
    enterprises_json = json.loads(enterprises_data)

    if not enterprises_json["success"]:
        return templates.TemplateResponse("error.html", {
            "request": request,
            "error": enterprises_json["error"]
        })

    # Получаем данные для всех отчетов
    enterprises_with_data = []
    for enterprise in enterprises_json["enterprises"]:
        report_data_response = await get_final_report_data(
            enterprise["reg_number"], year, region_code, district_code
        )
        
        if isinstance(report_data_response, JSONResponse):
            report_data = json.loads(report_data_response.body)
            if report_data["success"]:
                enterprises_with_data.append({
                    "reg_number": enterprise["reg_number"],
                    "name": enterprise["name"],
                    "report_data": report_data["report_data"]
                })

    return templates.TemplateResponse("reports/district/combined_reports_server.html", {
        "request": request,
        "username": user_login,
        "user_role": user_role,
        "district_code": district_code,
        "year": year,
        "region_code": region_code,
        "district_name": enterprises_json["district_name"],
        "region_name": enterprises_json["region_name"],
        "enterprises": enterprises_with_data
    })
#-------------------------------------------------------------------------------------------------------

# ДОБАВИТЬ В main.py ПОСЛЕ СУЩЕСТВУЮЩИХ API ДЛЯ СВОДНОГО ОТЧЕТА

# API для формирования сводного отчета по фильтру (район/область + период)
@app.get("/api/district/filtered-summary")
async def get_filtered_district_summary(
    location_id: str,  # Формат: "region_1" или "district_1"
    location_type: str,  # "region" или "district"
    start_year: int,
    end_year: int
):
    """Возвращает данные для сводного отчета по фильтру района/области за период"""
    conn = get_main_db_connection()
    if conn:
        try:
            cur = conn.cursor()
            
            # Извлекаем ID из строки (убираем префикс)
            location_id_clean = int(location_id.split('_')[1])
            is_single_year = (start_year == end_year)
            
            print(f"🔍 Формирование сводного отчета по фильтру: {location_type}_{location_id_clean}, период {start_year}-{end_year}")

            # 1. Получаем информацию о локации
            location_name = ""
            region_district_code = None
            region_code = None
            region_name = ""  # ДОБАВЛЯЕМ переменную для названия области

            if location_type == "region":
                cur.execute('SELECT "Код_области", "Наименование_области" FROM regions WHERE "Код_области" = %s', (location_id_clean,))
                region_data = cur.fetchone()
                if region_data:
                    region_district_code = region_data[0]
                    region_code = region_data[0]
                    location_name = region_data[1]
                    region_name = region_data[1]  # Сохраняем название области
            else:  # district
                cur.execute("""
                    SELECT d."Код_района", d."Наименование_района", r."Наименование_области", d."Код_области"
                    FROM districts d
                    JOIN regions r ON d."Код_области" = r."Код_области"
                    WHERE d."Код_района" = %s
                """, (location_id_clean,))
                district_data = cur.fetchone()
                if district_data:
                    region_district_code = district_data[0]
                    region_code = district_data[3]
                    # ИЗМЕНЕНИЕ: убираем область из названия района
                    location_name = district_data[1]  # Только название района
                    
                    region_name = district_data[2]  # Сохраняем название области отдельно
            print(region_district_code)
            if not location_name:
                return JSONResponse(content={"success": False, "error": "Локация не найдена"})

            # 2. Получаем предприятия в локации за указанный период
            enterprises_query = """
                SELECT DISTINCT 
                    e."Регистрационный_номер",
                    e."Наименование_предприятия"
                FROM enterprises e
                JOIN services s ON e."Регистрационный_номер" = s."Регистрационный_номер"
            """
            
            where_conditions = []
            params = []

            if location_type == "district":
                where_conditions.append('s."Код_района" = %s')
                
            else:  # region
                where_conditions.append('s."Код_района" IN (SELECT "Код_района" FROM districts WHERE "Код_области" = %s)')
                

            params.append(region_district_code)
            # Добавляем условие по периоду
            if is_single_year:
                where_conditions.append('s."Отчетный_период" = %s')
                params.append(start_year)
            else:
                where_conditions.append('s."Отчетный_период" BETWEEN %s AND %s')
                params.extend([start_year, end_year])

            enterprises_query += " WHERE " + " AND ".join(where_conditions) + ' ORDER BY e."Наименование_предприятия"'
            
            cur.execute(enterprises_query, params)
            enterprises_list = cur.fetchall()
            enterprises = []

            # Итоговые суммы
            total_plan_all = 0
            total_rural_plan_all = 0
            total_fact_all = 0
            total_rural_fact_all = 0

            for enterprise in enterprises_list:
                reg_number = enterprise[0]
                name = enterprise[1]

                # Статистика за период
                stats_query = """
                    SELECT 
                        COALESCE(SUM(s."План_всего"), 0) as total_plan,
                        COALESCE(SUM(s."Фактически_выполнено_всего"), 0) as total_fact,
                        COALESCE(SUM(CASE 
                            WHEN s."Наименование_вида_услуг" LIKE '%%в т.ч. в сельской местности%%' 
                            THEN s."План_всего" ELSE 0 
                        END), 0) as rural_plan,
                        COALESCE(SUM(CASE 
                            WHEN s."Наименование_вида_услуг" LIKE '%%в т.ч. в сельской местности%%' 
                            THEN s."Фактически_выполнено_всего" ELSE 0 
                        END), 0) as rural_fact
                    FROM services s
                    WHERE s."Регистрационный_номер" = %s
                """
                stats_params = [reg_number]

                # Добавляем условия локации
                if location_type == "district":
                    stats_query += ' AND s."Код_района" = %s'
                    
                else:  # region
                    stats_query += ' AND s."Код_района" IN (SELECT "Код_района" FROM districts WHERE "Код_области" = %s)'
                    
                stats_params.append(region_district_code)

                # Добавляем условие по периоду
                if is_single_year:
                    stats_query += ' AND s."Отчетный_период" = %s'
                    stats_params.append(start_year)
                else:
                    stats_query += ' AND s."Отчетный_период" BETWEEN %s AND %s'
                    stats_params.extend([start_year, end_year])

                cur.execute(stats_query, stats_params)
                current_stats = cur.fetchone()
                
                total_plan = float(current_stats[0]) if current_stats[0] else 0.0
                total_fact = float(current_stats[1]) if current_stats[1] else 0.0
                rural_plan = float(current_stats[2]) if current_stats[2] else 0.0
                rural_fact = float(current_stats[3]) if current_stats[3] else 0.0

                # Расчет динамики только для одного года
                dynamics_total = 0.0
                dynamics_rural = 0.0
                
                if is_single_year:
                    # Статистика за предыдущий год для динамики
                    prev_year = start_year - 1
                    prev_stats_query = stats_query.replace(
                        's."Отчетный_период" = %s' if is_single_year else 's."Отчетный_период" BETWEEN %s AND %s',
                        's."Отчетный_период" = %s'
                    )
                    prev_stats_params = [reg_number]
                    
                    # if location_type == "district":
                    #     prev_stats_params.append(district_code)
                    # else:
                    #     prev_stats_params.append(region_code)

                    prev_stats_params.append(region_district_code)
                    prev_stats_params.append(prev_year)

                    cur.execute(prev_stats_query, prev_stats_params)
                    prev_stats = cur.fetchone()
                    
                    prev_total_fact = float(prev_stats[1]) if prev_stats and prev_stats[1] else 0.0
                    prev_rural_fact = float(prev_stats[3]) if prev_stats and prev_stats[3] else 0.0

                    # Расчет динамики
                    dynamics_total = (total_fact / prev_total_fact * 100) if prev_total_fact > 0 else 0.0
                    dynamics_rural = (rural_fact / prev_rural_fact * 100) if prev_rural_fact > 0 else 0.0

                # Суммируем для итогов
                total_plan_all += total_plan
                total_rural_plan_all += rural_plan
                total_fact_all += total_fact
                total_rural_fact_all += rural_fact

                enterprises.append({
                    "reg_number": reg_number,
                    "name": name,
                    "total_plan": total_plan,
                    "rural_plan": rural_plan,
                    "total_fact": total_fact,
                    "rural_fact": rural_fact,
                    "dynamics_total": dynamics_total,
                    "dynamics_rural": dynamics_rural
                })

            # Расчет итоговой динамики только для одного года
            dynamics_total_all = 0.0
            dynamics_rural_all = 0.0
            
            if is_single_year:
                # Получаем общие данные за предыдущий год для всей локации
                prev_year = start_year - 1
                prev_totals_query = """
                    SELECT 
                        COALESCE(SUM(s."Фактически_выполнено_всего"), 0) as prev_total_fact,
                        COALESCE(SUM(CASE 
                            WHEN s."Наименование_вида_услуг" LIKE '%%в т.ч. в сельской местности%%' 
                            THEN s."Фактически_выполнено_всего" ELSE 0 
                        END), 0) as prev_rural_fact
                    FROM services s
                """
                prev_totals_params = []

                if location_type == "district":
                    prev_totals_query += ' WHERE s."Код_района" = %s'
                    
                else:
                    prev_totals_query += ' WHERE s."Код_района" IN (SELECT "Код_района" FROM districts WHERE "Код_области" = %s)'
                    
                prev_totals_params.append(region_district_code)
                prev_totals_query += ' AND s."Отчетный_период" = %s'
                prev_totals_params.append(prev_year)

                cur.execute(prev_totals_query, prev_totals_params)
                prev_totals = cur.fetchone()
                
                prev_total_fact_all = float(prev_totals[0]) if prev_totals[0] else 0.0
                prev_rural_fact_all = float(prev_totals[1]) if prev_totals[1] else 0.0

                dynamics_total_all = (total_fact_all / prev_total_fact_all * 100) if prev_total_fact_all > 0 else 0.0
                dynamics_rural_all = (total_rural_fact_all / prev_rural_fact_all * 100) if prev_rural_fact_all > 0 else 0.0
            
            

            summary_data = {
                "location_name": location_name,
                "location_type": location_type,
                "region_code": region_code,
                "region_name": region_name,  # ДОБАВЛЯЕМ название области
                "district_code": region_district_code,
                "start_year": start_year,
                "end_year": end_year,
                "is_single_year": is_single_year,
                "enterprises": enterprises,
                "totals": {
                    "total_plan": total_plan_all,
                    "rural_plan": total_rural_plan_all,
                    "total_fact": total_fact_all,
                    "rural_fact": total_rural_fact_all,
                    "dynamics_total": dynamics_total_all,
                    "dynamics_rural": dynamics_rural_all
                }
            }

            return JSONResponse(content={"success": True, "summary_data": summary_data})

        except Exception as e:
            print(f"❌ Ошибка в get_filtered_district_summary: {e}")
            import traceback
            print(f"🔍 Детальный traceback: {traceback.format_exc()}")
            return JSONResponse(content={"success": False, "error": str(e)})
        finally:
            conn.close()
    else:
        return JSONResponse(content={"success": False, "error": "Ошибка подключения к БД"})
    

# ДОБАВИТЬ В main.py ПОСЛЕ СУЩЕСТВУЮЩИХ ROUTES ДЛЯ СВОДНОГО ОТЧЕТА

# Страница фильтрованного сводного отчета
@app.get("/reports/district/filtered-summary")
async def filtered_district_summary(request: Request):
    user_login = request.query_params.get("user_login")
    user_role = request.query_params.get("user_role")
    
    if not user_login or not user_role:
        return templates.TemplateResponse("auth/check_auth.html", {"request": request})

    return templates.TemplateResponse("reports/district/filtered_district_summary.html", {
        "request": request,
        "username": user_login,
        "user_role": user_role
    })
#-------------------------------------------------------------------------------------------------------


# Добавить в main.py после существующих API для сводного отчета

@app.get("/api/district/filtered-summary/enterprises-list")
async def get_filtered_enterprises_list(
    location_id: str,
    location_type: str, 
    start_year: int,
    end_year: int
):
    """Возвращает список предприятий для фильтрованного отчета"""
    conn = get_main_db_connection()
    if conn:
        try:
            cur = conn.cursor()
            
            # Извлекаем ID из строки (убираем префикс)
            location_id_clean = int(location_id.split('_')[1])
            
            print(f"🔍 Получение предприятий для фильтра: {location_type}_{location_id_clean}, период {start_year}-{end_year}")

            # Получаем информацию о локации
            location_name = ""
            region_district_code = None
            district_code = None

            if location_type == "region":
                cur.execute('SELECT "Код_области", "Наименование_области" FROM regions WHERE "Код_области" = %s', (location_id_clean,))
                region_data = cur.fetchone()
                if region_data:
                    region_district_code = region_data[0]
                    location_name = region_data[1]
            else:  # district
                cur.execute("""
                    SELECT d."Код_района", d."Наименование_района", r."Наименование_области", d."Код_области"
                    FROM districts d
                    JOIN regions r ON d."Код_области" = r."Код_области"
                    WHERE d."Код_района" = %s
                """, (location_id_clean,))
                district_data = cur.fetchone()
                if district_data:
                    region_district_code = district_data[0]
                    location_name = f"{district_data[1]} ({district_data[2]})"
                    
            print(region_district_code) 
            if not location_name:
                return JSONResponse(content={"success": False, "error": "Локация не найдена"})

            # Получаем предприятия
            enterprises_query = """
                SELECT DISTINCT 
                    e."Регистрационный_номер",
                    e."Наименование_предприятия"
                FROM enterprises e
                JOIN services s ON e."Регистрационный_номер" = s."Регистрационный_номер"
            """
            
            where_conditions = []
            params = []

            if location_type == "district":
                where_conditions.append('s."Код_района" = %s')
                
            else:  # region
                where_conditions.append('s."Код_района" IN (SELECT "Код_района" FROM districts WHERE "Код_области" = %s)')
                
            params.append(region_district_code)

            # Добавляем условие по периоду
            if start_year == end_year:
                where_conditions.append('s."Отчетный_период" = %s')
                params.append(start_year)
            else:
                where_conditions.append('s."Отчетный_период" BETWEEN %s AND %s')
                params.extend([start_year, end_year])

            enterprises_query += " WHERE " + " AND ".join(where_conditions) + ' ORDER BY e."Наименование_предприятия"'
            
            cur.execute(enterprises_query, params)
            enterprises_list = cur.fetchall()
            enterprises = [{"reg_number": row[0], "name": row[1]} for row in enterprises_list]
             
            print(district_code) 

            return JSONResponse(content={
                "success": True,
                "location_name": location_name,
                "location_type": location_type,
                
                "district_code": region_district_code,
                "start_year": start_year,
                "end_year": end_year,
                "enterprises": enterprises
            })

        except Exception as e:
            print(f"❌ Ошибка в get_filtered_enterprises_list: {e}")
            import traceback
            print(f"🔍 Детальный traceback: {traceback.format_exc()}")
            return JSONResponse(content={"success": False, "error": str(e)})
        finally:
            conn.close()
    else:
        return JSONResponse(content={"success": False, "error": "Ошибка подключения к БД"})
    

# Добавить в main.py после предыдущего endpoint

@app.get("/reports/district/filtered-summary/combined-reports-server")
async def combined_filtered_reports_server(request: Request):
    """Страница с объединенными отчетами всех предприятий по фильтру"""
    user_login = request.query_params.get("user_login")
    user_role = request.query_params.get("user_role")
    location_id = request.query_params.get("location_id")
    location_type = request.query_params.get("location_type")
    start_year = request.query_params.get("start_year")
    end_year = request.query_params.get("end_year")
    
    if not user_login or not user_role:
        return templates.TemplateResponse("auth/check_auth.html", {"request": request})

    # Получаем список предприятий
    enterprises_response = await get_filtered_enterprises_list(
        location_id, location_type, int(start_year), int(end_year)
    )
    
    import json
    enterprises_data = enterprises_response.body
    enterprises_json = json.loads(enterprises_data)

    if not enterprises_json["success"]:
        return templates.TemplateResponse("error.html", {
            "request": request,
            "error": enterprises_json["error"]
        })

    # Получаем данные для всех отчетов предприятий
    enterprises_with_data = []
    for enterprise in enterprises_json["enterprises"]:
        # Используем существующий API для получения отчета по фильтру
        report_data_response = await get_filtered_report(
            enterprise["reg_number"], 
            int(start_year), 
            int(end_year),
            location_id,
            location_type
        )
        
        if isinstance(report_data_response, JSONResponse):
            report_data = json.loads(report_data_response.body)
            if report_data["success"]:
                enterprises_with_data.append({
                    "reg_number": enterprise["reg_number"],
                    "name": enterprise["name"],
                    "report_data": report_data["report_data"]
                })
    summary_response = await get_filtered_district_summary(
        location_id, location_type, int(start_year), int(end_year)
    )
    summary_data = json.loads(summary_response.body) if isinstance(summary_response, JSONResponse) else {}   

         

    return templates.TemplateResponse("reports/district/combined_filtered_reports_server.html", {
        "request": request,
        "username": user_login,
        "user_role": user_role,
        "location_id": location_id,
        "location_type": location_type,
        "start_year": start_year,
        "end_year": end_year,
        "location_name": enterprises_json["location_name"],
        "region_code": enterprises_json.get("region_code"),
        "region_name": summary_data.get("summary_data", {}).get("region_name", ""),
        "district_code": enterprises_json.get("district_code"),
        "enterprises": enterprises_with_data
    })

#-------------------------------------------------------------------------------------------------------

# API для справочников
@app.get("/api/catalogs/enterprises")
async def get_catalog_enterprises():
    """Возвращает список всех предприятий для справочника"""
    conn = get_main_db_connection()
    if conn:
        try:
            cur = conn.cursor()
            
            cur.execute("""
                SELECT 
                    e."Регистрационный_номер",
                    e."Наименование_предприятия",
                    m."Наименование_министерства",
                    i."Наименование_отрасли",
                    r."Наименование_области"
                FROM enterprises e
                LEFT JOIN ministries m ON e."Код_министерства" = m."Код_министерства"
                LEFT JOIN industries i ON e."Код_отрасли" = i."Код_отрасли"
                LEFT JOIN regions r ON e."Код_области" = r."Код_области"
                ORDER BY e."Наименование_предприятия"
            """)
            
            enterprises = []
            for row in cur.fetchall():
                enterprises.append({
                    "reg_number": row[0],
                    "name": row[1],
                    "ministry_name": row[2] or "Не указано",
                    "industry_name": row[3] or "Не указано",
                    "region_name": row[4] or "Не указано"
                })
            
            return JSONResponse(content={"success": True, "enterprises": enterprises})
            
        except Exception as e:
            print(f"❌ Ошибка в get_catalog_enterprises: {e}")
            return JSONResponse(content={"success": False, "error": str(e)})
        finally:
            conn.close()
    else:
        return JSONResponse(content={"success": False, "error": "Ошибка подключения к БД"})

@app.get("/api/catalogs/ministries")
async def get_catalog_ministries():
    """Возвращает список всех министерств для справочника"""
    conn = get_main_db_connection()
    if conn:
        try:
            cur = conn.cursor()
            
            cur.execute('SELECT "Код_министерства", "Наименование_министерства" FROM ministries ORDER BY "Наименование_министерства"')
            
            ministries = []
            for row in cur.fetchall():
                ministries.append({
                    "code": row[0],
                    "name": row[1]
                })
            
            return JSONResponse(content={"success": True, "ministries": ministries})
            
        except Exception as e:
            print(f"❌ Ошибка в get_catalog_ministries: {e}")
            return JSONResponse(content={"success": False, "error": str(e)})
        finally:
            conn.close()
    else:
        return JSONResponse(content={"success": False, "error": "Ошибка подключения к БД"})

@app.get("/api/catalogs/industries")
async def get_catalog_industries():
    """Возвращает список всех отраслей для справочника"""
    conn = get_main_db_connection()
    if conn:
        try:
            cur = conn.cursor()
            
            cur.execute('SELECT "Код_отрасли", "Наименование_отрасли" FROM industries ORDER BY "Наименование_отрасли"')
            
            industries = []
            for row in cur.fetchall():
                industries.append({
                    "code": row[0],
                    "name": row[1]
                })
            
            return JSONResponse(content={"success": True, "industries": industries})
            
        except Exception as e:
            print(f"❌ Ошибка в get_catalog_industries: {e}")
            return JSONResponse(content={"success": False, "error": str(e)})
        finally:
            conn.close()
    else:
        return JSONResponse(content={"success": False, "error": "Ошибка подключения к БД"})

@app.get("/api/catalogs/regions")
async def get_catalog_regions():
    """Возвращает список всех областей для справочника"""
    conn = get_main_db_connection()
    if conn:
        try:
            cur = conn.cursor()
            
            cur.execute('SELECT "Код_области", "Наименование_области" FROM regions ORDER BY "Наименование_области"')
            
            regions = []
            for row in cur.fetchall():
                regions.append({
                    "code": row[0],
                    "name": row[1]
                })
            
            return JSONResponse(content={"success": True, "regions": regions})
            
        except Exception as e:
            print(f"❌ Ошибка в get_catalog_regions: {e}")
            return JSONResponse(content={"success": False, "error": str(e)})
        finally:
            conn.close()
    else:
        return JSONResponse(content={"success": False, "error": "Ошибка подключения к БД"})

@app.get("/api/catalogs/districts")
async def get_catalog_districts():
    """Возвращает список всех районов для справочника"""
    conn = get_main_db_connection()
    if conn:
        try:
            cur = conn.cursor()
            
            cur.execute("""
                SELECT 
                    d."Код_района",
                    d."Наименование_района",
                    r."Наименование_области",
                    r."Код_области"
                FROM districts d
                JOIN regions r ON d."Код_области" = r."Код_области"
                ORDER BY r."Наименование_области", d."Наименование_района"
            """)
            
            districts = []
            for row in cur.fetchall():
                districts.append({
                    "code": row[0],
                    "name": row[1],
                    "region_name": row[2],
                    "region_code": row[3]
                })
            
            return JSONResponse(content={"success": True, "districts": districts})
            
        except Exception as e:
            print(f"❌ Ошибка в get_catalog_districts: {e}")
            return JSONResponse(content={"success": False, "error": str(e)})
        finally:
            conn.close()
    else:
        return JSONResponse(content={"success": False, "error": "Ошибка подключения к БД"})

# Добавить после существующих endpoints для справочников
@app.get("/api/catalogs/services")
async def get_catalog_services():
    """Возвращает список всех видов услуг для справочника (алиас для service-types)"""
    conn = get_main_db_connection()
    if conn:
        try:
            cur = conn.cursor()
            
            cur.execute('SELECT "Наименование_вида_услуг" FROM service_types ORDER BY "Наименование_вида_услуг"')
            
            services = []
            for row in cur.fetchall():
                services.append({
                    "name": row[0]
                })
            
            return JSONResponse(content={"success": True, "services": services})
            
        except Exception as e:
            print(f"❌ Ошибка в get_catalog_services: {e}")
            return JSONResponse(content={"success": False, "error": str(e)})
        finally:
            conn.close()
    else:
        return JSONResponse(content={"success": False, "error": "Ошибка подключения к БД"})
    

# Добавить в main.py (опционально, для улучшения UX)
@app.get("/api/catalogs/stats")
async def get_catalogs_stats():
    """Возвращает статистику по справочникам"""
    conn = get_main_db_connection()
    if conn:
        try:
            cur = conn.cursor()
            
            stats = {}
            
            # Количество предприятий
            cur.execute('SELECT COUNT(*) FROM enterprises')
            stats['enterprises_count'] = cur.fetchone()[0]
            
            # Количество министерств
            cur.execute('SELECT COUNT(*) FROM ministries')
            stats['ministries_count'] = cur.fetchone()[0]
            
            # Количество отраслей
            cur.execute('SELECT COUNT(*) FROM industries')
            stats['industries_count'] = cur.fetchone()[0]
            
            # Количество областей
            cur.execute('SELECT COUNT(*) FROM regions')
            stats['regions_count'] = cur.fetchone()[0]
            
            # Количество районов
            cur.execute('SELECT COUNT(*) FROM districts')
            stats['districts_count'] = cur.fetchone()[0]
            
            # Количество видов услуг
            cur.execute('SELECT COUNT(*) FROM service_types')
            stats['services_count'] = cur.fetchone()[0]
            
            return JSONResponse(content={"success": True, "stats": stats})
            
        except Exception as e:
            print(f"❌ Ошибка в get_catalogs_stats: {e}")
            return JSONResponse(content={"success": False, "error": str(e)})
        finally:
            conn.close()
    else:
        return JSONResponse(content={"success": False, "error": "Ошибка подключения к БД"})
    
 #-------------------------------------------------------------------------------------------------------
 # админ дальше
 # -------------------------------------------------------------------------------------------------------

 # Добавить в main.py после существующих endpoints

# API для проверки статуса БД
@app.get("/api/admin/db-status")
async def get_admin_db_status():
    """Проверяет статус подключения к базам данных"""
    main_conn = None
    users_conn = None
    
    try:
        main_conn = get_main_db_connection()
        users_conn = get_users_db_connection()
        
        return JSONResponse(content={
            "success": True,
            "main_db": main_conn is not None,
            "users_db": users_conn is not None
        })
    except Exception as e:
        print(f"❌ Ошибка проверки статуса БД: {e}")
        return JSONResponse(content={
            "success": False,
            "main_db": False,
            "users_db": False
        })
    finally:
        if main_conn:
            main_conn.close()
        if users_conn:
            users_conn.close()

# API для статистики дашборда
@app.get("/api/admin/dashboard-stats")
async def get_admin_dashboard_stats():
    """Возвращает статистику для дашборда администратора"""
    conn = get_main_db_connection()
    users_conn = get_users_db_connection()
    
    if not conn or not users_conn:
        return JSONResponse(content={"success": False, "error": "Ошибка подключения к БД"})
    
    try:
        cur = conn.cursor()
        users_cur = users_conn.cursor()
        
        # Количество предприятий
        cur.execute('SELECT COUNT(*) FROM enterprises')
        enterprises_count = cur.fetchone()[0]
        
        # Количество услуг
        cur.execute('SELECT COUNT(*) FROM services')
        services_count = cur.fetchone()[0]
        
        # Количество отчетных периодов
        cur.execute('SELECT COUNT(DISTINCT "Отчетный_период") FROM period')
        periods_count = cur.fetchone()[0]
        
        # Количество пользователей
        users_cur.execute('SELECT COUNT(*) FROM users')
        users_count = users_cur.fetchone()[0]
        
        # Тренды (заглушки - в реальности нужно считать разницу с предыдущим месяцем)
        enterprises_trend = 0
        services_trend = 0
        periods_trend = 0
        users_trend = 0
        
        return JSONResponse(content={
            "success": True,
            "stats": {
                "enterprises_count": enterprises_count,
                "services_count": services_count,
                "periods_count": periods_count,
                "users_count": users_count,
                "enterprises_trend": enterprises_trend,
                "services_trend": services_trend,
                "periods_trend": periods_trend,
                "users_trend": users_trend
            }
        })
        
    except Exception as e:
        print(f"❌ Ошибка в get_admin_dashboard_stats: {e}")
        return JSONResponse(content={"success": False, "error": str(e)})
    finally:
        conn.close()
        users_conn.close()

# Маршруты админ-панели
@app.get("/admin/dashboard")
async def admin_dashboard(request: Request):
    """Главная страница админ-панели"""
    user_login = request.query_params.get("user_login")
    user_role = request.query_params.get("user_role")
    
    if not user_login or user_role != "admin":
        return templates.TemplateResponse("auth/check_auth.html", {"request": request})
    
    return templates.TemplateResponse("admin/dashboard.html", {
        "request": request,
        "username": user_login,
        "user_role": user_role
    })

@app.get("/admin/enterprises")
async def admin_enterprises(request: Request):
    user_login = request.query_params.get("user_login")
    user_role = request.query_params.get("user_role")
    
    if not user_login or user_role != "admin":
        return templates.TemplateResponse("auth/check_auth.html", {"request": request})
    
    return templates.TemplateResponse("admin/enterprises.html", {
        "request": request,
        "username": user_login,
        "user_role": user_role
    })

@app.get("/admin/services")
async def admin_services(request: Request):
    user_login = request.query_params.get("user_login")
    user_role = request.query_params.get("user_role")
    
    if not user_login or user_role != "admin":
        return templates.TemplateResponse("auth/check_auth.html", {"request": request})
    
    return templates.TemplateResponse("admin/services.html", {
        "request": request,
        "username": user_login,
        "user_role": user_role
    })

@app.get("/admin/periods")
async def admin_periods(request: Request):
    user_login = request.query_params.get("user_login")
    user_role = request.query_params.get("user_role")
    
    if not user_login or user_role != "admin":
        return templates.TemplateResponse("auth/check_auth.html", {"request": request})
    
    return templates.TemplateResponse("admin/periods.html", {
        "request": request,
        "username": user_login,
        "user_role": user_role
    })

@app.get("/admin/users")
async def admin_users(request: Request):
    user_login = request.query_params.get("user_login")
    user_role = request.query_params.get("user_role")
    
    if not user_login or user_role != "admin":
        return templates.TemplateResponse("auth/check_auth.html", {"request": request})
    
    return templates.TemplateResponse("admin/users.html", {
        "request": request,
        "username": user_login,
        "user_role": user_role
    })

#------------------------------------------------------------------------------------------------------


# Добавить в main.py после существующих API endpoints

# API для управления предприятиями в админ-панели
@app.get("/api/admin/enterprises")
async def get_admin_enterprises():
    """Возвращает список всех предприятий для админ-панели"""
    conn = get_main_db_connection()
    if conn:
        try:
            cur = conn.cursor()
            
            cur.execute("""
                SELECT 
                    "Наименование_предприятия" as name,
                    "Регистрационный_номер" as reg_number,
                    "Код_министерства" as ministry_code,
                    "Код_отрасли" as industry_code,
                    "Код_области" as region_code
                FROM enterprises 
                ORDER BY "Наименование_предприятия"
            """)
            
            enterprises = []
            for row in cur.fetchall():
                enterprises.append({
                    "name": row[0],
                    "reg_number": row[1],
                    "ministry_code": row[2],
                    "industry_code": row[3],
                    "region_code": row[4]
                })
            
            return JSONResponse(content={"success": True, "enterprises": enterprises})
            
        except Exception as e:
            print(f"❌ Ошибка в get_admin_enterprises: {e}")
            return JSONResponse(content={"success": False, "error": str(e)})
        finally:
            conn.close()
    else:
        return JSONResponse(content={"success": False, "error": "Ошибка подключения к БД"})

@app.post("/api/admin/enterprises")
async def create_enterprise(request: Request):
    """Создает новое предприятие"""
    conn = get_main_db_connection()
    if conn:
        try:
            data = await request.json()
            
            # Валидация обязательных полей
            if not data.get('name') or not data.get('reg_number'):
                return JSONResponse(content={"success": False, "error": "Обязательные поля: name и reg_number"})
            
            cur = conn.cursor()
            
            # Проверяем уникальность регистрационного номера
            cur.execute('SELECT COUNT(*) FROM enterprises WHERE "Регистрационный_номер" = %s', (data['reg_number'],))
            if cur.fetchone()[0] > 0:
                return JSONResponse(content={"success": False, "error": "Предприятие с таким регистрационным номером уже существует"})
            
            # Вставляем новое предприятие
            cur.execute("""
                INSERT INTO enterprises 
                ("Наименование_предприятия", "Регистрационный_номер", "Код_министерства", "Код_отрасли", "Код_области")
                VALUES (%s, %s, %s, %s, %s)
            """, (
                data['name'],
                data['reg_number'],
                data.get('ministry_code'),
                data.get('industry_code'), 
                data.get('region_code')
            ))
            
            conn.commit()
            return JSONResponse(content={"success": True, "message": "Предприятие успешно создано"})
            
        except Exception as e:
            conn.rollback()
            print(f"❌ Ошибка в create_enterprise: {e}")
            return JSONResponse(content={"success": False, "error": str(e)})
        finally:
            conn.close()
    else:
        return JSONResponse(content={"success": False, "error": "Ошибка подключения к БД"})

@app.put("/api/admin/enterprises/{reg_number}")
async def update_enterprise(reg_number: int, request: Request):
    """Обновляет данные предприятия"""
    conn = get_main_db_connection()
    if conn:
        try:
            data = await request.json()
            
            # Валидация
            if not data.get('name'):
                return JSONResponse(content={"success": False, "error": "Поле name обязательно"})
            
            cur = conn.cursor()
            
            # Проверяем существование предприятия
            cur.execute('SELECT COUNT(*) FROM enterprises WHERE "Регистрационный_номер" = %s', (reg_number,))
            if cur.fetchone()[0] == 0:
                return JSONResponse(content={"success": False, "error": "Предприятие не найдено"})
            
            # Обновляем данные
            cur.execute("""
                UPDATE enterprises 
                SET "Наименование_предприятия" = %s,
                    "Код_министерства" = %s,
                    "Код_отрасли" = %s,
                    "Код_области" = %s
                WHERE "Регистрационный_номер" = %s
            """, (
                data['name'],
                data.get('ministry_code'),
                data.get('industry_code'),
                data.get('region_code'),
                reg_number
            ))
            
            conn.commit()
            return JSONResponse(content={"success": True, "message": "Предприятие успешно обновлено"})
            
        except Exception as e:
            conn.rollback()
            print(f"❌ Ошибка в update_enterprise: {e}")
            return JSONResponse(content={"success": False, "error": str(e)})
        finally:
            conn.close()
    else:
        return JSONResponse(content={"success": False, "error": "Ошибка подключения к БД"})

@app.delete("/api/admin/enterprises/{reg_number}")
async def delete_enterprise(reg_number: int):
    """Удаляет предприятие"""
    conn = get_main_db_connection()
    if conn:
        try:
            cur = conn.cursor()
            
            # Проверяем существование предприятия
            cur.execute('SELECT COUNT(*) FROM enterprises WHERE "Регистрационный_номер" = %s', (reg_number,))
            if cur.fetchone()[0] == 0:
                return JSONResponse(content={"success": False, "error": "Предприятие не найдено"})
            
            # Удаляем предприятие
            cur.execute('DELETE FROM enterprises WHERE "Регистрационный_номер" = %s', (reg_number,))
            
            conn.commit()
            return JSONResponse(content={"success": True, "message": "Предприятие успешно удалено"})
            
        except Exception as e:
            conn.rollback()
            print(f"❌ Ошибка в delete_enterprise: {e}")
            return JSONResponse(content={"success": False, "error": str(e)})
        finally:
            conn.close()
    else:
        return JSONResponse(content={"success": False, "error": "Ошибка подключения к БД"})

# API для справочников
@app.get("/api/admin/reference/ministries")
async def get_ministries_reference():
    """Возвращает справочник министерств"""
    conn = get_main_db_connection()
    if conn:
        try:
            cur = conn.cursor()
            
            cur.execute('SELECT id, "Код_министерства" as code, "Наименование_министерства" as name FROM ministries ORDER BY "Наименование_министерства"')
            
            ministries = []
            for row in cur.fetchall():
                ministries.append({
                    "id": row[0],
                    "code": row[1],
                    "name": row[2]
                })
            
            return JSONResponse(content={"success": True, "data": ministries})
            
        except Exception as e:
            print(f"❌ Ошибка в get_ministries_reference: {e}")
            return JSONResponse(content={"success": False, "error": str(e)})
        finally:
            conn.close()
    else:
        return JSONResponse(content={"success": False, "error": "Ошибка подключения к БД"})

@app.get("/api/admin/reference/industries")
async def get_industries_reference():
    """Возвращает справочник отраслей"""
    conn = get_main_db_connection()
    if conn:
        try:
            cur = conn.cursor()
            
            cur.execute('SELECT id, "Код_отрасли" as code, "Наименование_отрасли" as name FROM industries ORDER BY "Наименование_отрасли"')
            
            industries = []
            for row in cur.fetchall():
                industries.append({
                    "id": row[0],
                    "code": row[1],
                    "name": row[2]
                })
            
            return JSONResponse(content={"success": True, "data": industries})
            
        except Exception as e:
            print(f"❌ Ошибка в get_industries_reference: {e}")
            return JSONResponse(content={"success": False, "error": str(e)})
        finally:
            conn.close()
    else:
        return JSONResponse(content={"success": False, "error": "Ошибка подключения к БД"})

@app.get("/api/admin/reference/regions")
async def get_regions_reference():
    """Возвращает справочник областей"""
    conn = get_main_db_connection()
    if conn:
        try:
            cur = conn.cursor()
            
            cur.execute('SELECT id, "Код_области" as code, "Наименование_области" as name FROM regions ORDER BY "Наименование_области"')
            
            regions = []
            for row in cur.fetchall():
                regions.append({
                    "id": row[0],
                    "code": row[1],
                    "name": row[2]
                })
            
            return JSONResponse(content={"success": True, "data": regions})
            
        except Exception as e:
            print(f"❌ Ошибка в get_regions_reference: {e}")
            return JSONResponse(content={"success": False, "error": str(e)})
        finally:
            conn.close()
    else:
        return JSONResponse(content={"success": False, "error": "Ошибка подключения к БД"})
    
#-------------------------------------------------------------------------------------------------------

# Добавить в main.py после существующих API endpoints для предприятий

# API для управления отчётными периодами в админ-панели
@app.get("/api/admin/periods")
async def get_admin_periods():
    """Возвращает список всех отчётных периодов для админ-панели"""
    conn = get_main_db_connection()
    if conn:
        try:
            cur = conn.cursor()
            
            cur.execute("""
                SELECT 
                    p."Регистрационный_номер" as reg_number,
                    p."Отчетный_период" as year,
                    p."ФИО_директора" as director_name,
                    e."Наименование_предприятия" as enterprise_name
                FROM period p
                JOIN enterprises e ON p."Регистрационный_номер" = e."Регистрационный_номер"
                ORDER BY e."Наименование_предприятия", p."Отчетный_период" DESC
            """)
            
            periods = []
            for row in cur.fetchall():
                periods.append({
                    "reg_number": row[0],
                    "year": row[1],
                    "director_name": row[2],
                    "enterprise_name": row[3]
                })
            
            return JSONResponse(content={"success": True, "periods": periods})
            
        except Exception as e:
            print(f"❌ Ошибка в get_admin_periods: {e}")
            return JSONResponse(content={"success": False, "error": str(e)})
        finally:
            conn.close()
    else:
        return JSONResponse(content={"success": False, "error": "Ошибка подключения к БД"})

@app.post("/api/admin/periods")
async def create_period(request: Request):
    """Создает новый отчётный период"""
    conn = get_main_db_connection()
    if conn:
        try:
            data = await request.json()
            
            # Валидация обязательных полей
            if not data.get('reg_number') or not data.get('year'):
                return JSONResponse(content={"success": False, "error": "Обязательные поля: reg_number и year"})
            
            cur = conn.cursor()
            
            # Проверяем существование предприятия
            cur.execute('SELECT COUNT(*) FROM enterprises WHERE "Регистрационный_номер" = %s', (data['reg_number'],))
            if cur.fetchone()[0] == 0:
                return JSONResponse(content={"success": False, "error": "Предприятие с указанным регистрационным номером не найдено"})
            
            # Проверяем уникальность комбинации (предприятие + год)
            cur.execute('SELECT COUNT(*) FROM period WHERE "Регистрационный_номер" = %s AND "Отчетный_период" = %s', 
                       (data['reg_number'], data['year']))
            if cur.fetchone()[0] > 0:
                return JSONResponse(content={"success": False, "error": "Отчётный период для этого предприятия уже существует"})
            
            # Вставляем новый период
            cur.execute("""
                INSERT INTO period 
                ("Регистрационный_номер", "Отчетный_период", "ФИО_директора")
                VALUES (%s, %s, %s)
            """, (
                data['reg_number'],
                data['year'],
                data.get('director_name')
            ))
            
            conn.commit()
            return JSONResponse(content={"success": True, "message": "Отчётный период успешно создан"})
            
        except Exception as e:
            conn.rollback()
            print(f"❌ Ошибка в create_period: {e}")
            return JSONResponse(content={"success": False, "error": str(e)})
        finally:
            conn.close()
    else:
        return JSONResponse(content={"success": False, "error": "Ошибка подключения к БД"})

@app.put("/api/admin/periods/{reg_number}/{year}")
async def update_period(reg_number: int, year: int, request: Request):
    """Обновляет данные отчётного периода"""
    conn = get_main_db_connection()
    if conn:
        try:
            data = await request.json()
            
            cur = conn.cursor()
            
            # Проверяем существование периода
            cur.execute('SELECT COUNT(*) FROM period WHERE "Регистрационный_номер" = %s AND "Отчетный_период" = %s', 
                       (reg_number, year))
            if cur.fetchone()[0] == 0:
                return JSONResponse(content={"success": False, "error": "Отчётный период не найден"})
            
            # Обновляем данные (только ФИО директора, так как предприятие и год менять нельзя)
            cur.execute("""
                UPDATE period 
                SET "ФИО_директора" = %s
                WHERE "Регистрационный_номер" = %s AND "Отчетный_период" = %s
            """, (
                data.get('director_name'),
                reg_number,
                year
            ))
            
            conn.commit()
            return JSONResponse(content={"success": True, "message": "Отчётный период успешно обновлен"})
            
        except Exception as e:
            conn.rollback()
            print(f"❌ Ошибка в update_period: {e}")
            return JSONResponse(content={"success": False, "error": str(e)})
        finally:
            conn.close()
    else:
        return JSONResponse(content={"success": False, "error": "Ошибка подключения к БД"})

@app.delete("/api/admin/periods/{reg_number}/{year}")
async def delete_period(reg_number: int, year: int):
    """Удаляет отчётный период"""
    conn = get_main_db_connection()
    if conn:
        try:
            cur = conn.cursor()
            
            # Проверяем существование периода
            cur.execute('SELECT COUNT(*) FROM period WHERE "Регистрационный_номер" = %s AND "Отчетный_период" = %s', 
                       (reg_number, year))
            if cur.fetchone()[0] == 0:
                return JSONResponse(content={"success": False, "error": "Отчётный период не найден"})
            
            # Удаляем период
            cur.execute('DELETE FROM period WHERE "Регистрационный_номер" = %s AND "Отчетный_период" = %s', 
                       (reg_number, year))
            
            conn.commit()
            return JSONResponse(content={"success": True, "message": "Отчётный период успешно удален"})
            
        except Exception as e:
            conn.rollback()
            print(f"❌ Ошибка в delete_period: {e}")
            return JSONResponse(content={"success": False, "error": str(e)})
        finally:
            conn.close()
    else:
        return JSONResponse(content={"success": False, "error": "Ошибка подключения к БД"})

# API для справочника предприятий (упрощенная версия)
@app.get("/api/admin/reference/enterprises")
async def get_enterprises_reference():
    """Возвращает справочник предприятий для выпадающих списков"""
    conn = get_main_db_connection()
    if conn:
        try:
            cur = conn.cursor()
            
            cur.execute("""
                SELECT 
                    "Регистрационный_номер" as reg_number,
                    "Наименование_предприятия" as name
                FROM enterprises 
                ORDER BY "Наименование_предприятия"
            """)
            
            enterprises = []
            for row in cur.fetchall():
                enterprises.append({
                    "reg_number": row[0],
                    "name": row[1]
                })
            
            return JSONResponse(content={"success": True, "data": enterprises})
            
        except Exception as e:
            print(f"❌ Ошибка в get_enterprises_reference: {e}")
            return JSONResponse(content={"success": False, "error": str(e)})
        finally:
            conn.close()
    else:
        return JSONResponse(content={"success": False, "error": "Ошибка подключения к БД"})
    
#-------------------------------------------------------------------------------------------------------

# Добавить в main.py после существующих API endpoints для периодов

# API для управления услугами в админ-панели
@app.get("/api/admin/services")
async def get_admin_services():
    """Возвращает список всех услуг для админ-панели"""
    conn = get_main_db_connection()
    if conn:
        try:
            cur = conn.cursor()
            
            cur.execute("""
                SELECT 
                    s.id,
                    s."Регистрационный_номер" as reg_number,
                    s."Код_района" as district_code,
                    s."Отчетный_период" as year,
                    s."Наименование_вида_услуг" as service_type,
                    s."Код_показателя" as indicator_code,
                    s."План_всего" as plan_total,
                    s."Фактически_выполнено_всего" as fact_total,
                    e."Наименование_предприятия" as enterprise_name,
                    d."Наименование_района" as district_name,
                    r."Наименование_области" as region_name
                FROM services s
                JOIN enterprises e ON s."Регистрационный_номер" = e."Регистрационный_номер"
                JOIN districts d ON s."Код_района" = d."Код_района"
                JOIN regions r ON d."Код_области" = r."Код_области"
                ORDER BY e."Наименование_предприятия", s."Отчетный_период" DESC, s."Наименование_вида_услуг"
            """)
            
            services = []
            for row in cur.fetchall():
                services.append({
                    "id": row[0],
                    "reg_number": row[1],
                    "district_code": row[2],
                    "year": row[3],
                    "service_type": row[4],
                    "indicator_code": row[5],
                    "plan_total": float(row[6]) if row[6] else None,
                    "fact_total": float(row[7]) if row[7] else None,
                    "enterprise_name": row[8],
                    "district_name": row[9],
                    "region_name": row[10]
                })
            
            return JSONResponse(content={"success": True, "services": services})
            
        except Exception as e:
            print(f"❌ Ошибка в get_admin_services: {e}")
            return JSONResponse(content={"success": False, "error": str(e)})
        finally:
            conn.close()
    else:
        return JSONResponse(content={"success": False, "error": "Ошибка подключения к БД"})

@app.post("/api/admin/services")
async def create_service(request: Request):
    """Создает новую услугу"""
    conn = get_main_db_connection()
    if conn:
        try:
            data = await request.json()
            
            # Валидация обязательных полей
            required_fields = ['reg_number', 'district_code', 'year', 'service_type']
            for field in required_fields:
                if not data.get(field):
                    return JSONResponse(content={"success": False, "error": f"Обязательное поле: {field}"})
            
            cur = conn.cursor()
            
            # Проверяем существование предприятия
            cur.execute('SELECT COUNT(*) FROM enterprises WHERE "Регистрационный_номер" = %s', (data['reg_number'],))
            if cur.fetchone()[0] == 0:
                return JSONResponse(content={"success": False, "error": "Предприятие не найдено"})
            
            # Проверяем существование района
            cur.execute('SELECT COUNT(*) FROM districts WHERE "Код_района" = %s', (data['district_code'],))
            if cur.fetchone()[0] == 0:
                return JSONResponse(content={"success": False, "error": "Район не найден"})
            
            # Проверяем существование вида услуги
            cur.execute('SELECT COUNT(*) FROM service_types WHERE "Наименование_вида_услуг" = %s', (data['service_type'],))
            if cur.fetchone()[0] == 0:
                return JSONResponse(content={"success": False, "error": "Вид услуги не найден"})
            
            # Проверяем уникальность комбинации (предприятие + район + год + вид услуги)
            cur.execute("""
                SELECT COUNT(*) FROM services 
                WHERE "Регистрационный_номер" = %s 
                AND "Код_района" = %s 
                AND "Отчетный_период" = %s 
                AND "Наименование_вида_услуг" = %s
            """, (data['reg_number'], data['district_code'], data['year'], data['service_type']))
            
            if cur.fetchone()[0] > 0:
                return JSONResponse(content={"success": False, "error": "Услуга с такими параметрами уже существует"})
            
            # Вставляем новую услугу
            cur.execute("""
                INSERT INTO services 
                ("Регистрационный_номер", "Код_района", "Отчетный_период", 
                 "Наименование_вида_услуг", "Код_показателя", "План_всего", "Фактически_выполнено_всего")
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (
                data['reg_number'],
                data['district_code'],
                data['year'],
                data['service_type'],
                data.get('indicator_code'),
                data.get('plan_total'),
                data.get('fact_total')
            ))
            
            conn.commit()
            return JSONResponse(content={"success": True, "message": "Услуга успешно создана"})
            
        except Exception as e:
            conn.rollback()
            print(f"❌ Ошибка в create_service: {e}")
            return JSONResponse(content={"success": False, "error": str(e)})
        finally:
            conn.close()
    else:
        return JSONResponse(content={"success": False, "error": "Ошибка подключения к БД"})

@app.put("/api/admin/services/{service_id}")
async def update_service(service_id: int, request: Request):
    """Обновляет данные услуги"""
    conn = get_main_db_connection()
    if conn:
        try:
            data = await request.json()
            
            cur = conn.cursor()
            
            # Проверяем существование услуги
            cur.execute('SELECT COUNT(*) FROM services WHERE id = %s', (service_id,))
            if cur.fetchone()[0] == 0:
                return JSONResponse(content={"success": False, "error": "Услуга не найдена"})
            
            # Обновляем данные (можно менять только код показателя, план и факт)
            cur.execute("""
                UPDATE services 
                SET "Код_показателя" = %s,
                    "План_всего" = %s,
                    "Фактически_выполнено_всего" = %s
                WHERE id = %s
            """, (
                data.get('indicator_code'),
                data.get('plan_total'),
                data.get('fact_total'),
                service_id
            ))
            
            conn.commit()
            return JSONResponse(content={"success": True, "message": "Услуга успешно обновлена"})
            
        except Exception as e:
            conn.rollback()
            print(f"❌ Ошибка в update_service: {e}")
            return JSONResponse(content={"success": False, "error": str(e)})
        finally:
            conn.close()
    else:
        return JSONResponse(content={"success": False, "error": "Ошибка подключения к БД"})

@app.delete("/api/admin/services/{service_id}")
async def delete_service(service_id: int):
    """Удаляет услугу"""
    conn = get_main_db_connection()
    if conn:
        try:
            cur = conn.cursor()
            
            # Проверяем существование услуги
            cur.execute('SELECT COUNT(*) FROM services WHERE id = %s', (service_id,))
            if cur.fetchone()[0] == 0:
                return JSONResponse(content={"success": False, "error": "Услуга не найдена"})
            
            # Удаляем услугу
            cur.execute('DELETE FROM services WHERE id = %s', (service_id,))
            
            conn.commit()
            return JSONResponse(content={"success": True, "message": "Услуга успешно удалена"})
            
        except Exception as e:
            conn.rollback()
            print(f"❌ Ошибка в delete_service: {e}")
            return JSONResponse(content={"success": False, "error": str(e)})
        finally:
            conn.close()
    else:
        return JSONResponse(content={"success": False, "error": "Ошибка подключения к БД"})

# API для справочника районов
@app.get("/api/admin/reference/districts")
async def get_districts_reference():
    """Возвращает справочник районов для выпадающих списков"""
    conn = get_main_db_connection()
    if conn:
        try:
            cur = conn.cursor()
            
            cur.execute("""
                SELECT 
                    d."Код_района" as code,
                    d."Наименование_района" as name,
                    r."Наименование_области" as region_name
                FROM districts d
                JOIN regions r ON d."Код_области" = r."Код_области"
                ORDER BY r."Наименование_области", d."Наименование_района"
            """)
            
            districts = []
            for row in cur.fetchall():
                districts.append({
                    "code": row[0],
                    "name": row[1],
                    "region_name": row[2]
                })
            
            return JSONResponse(content={"success": True, "data": districts})
            
        except Exception as e:
            print(f"❌ Ошибка в get_districts_reference: {e}")
            return JSONResponse(content={"success": False, "error": str(e)})
        finally:
            conn.close()
    else:
        return JSONResponse(content={"success": False, "error": "Ошибка подключения к БД"})

# API для справочника видов услуг
@app.get("/api/admin/reference/service-types")
async def get_service_types_reference():
    """Возвращает справочник видов услуг для выпадающих списков"""
    conn = get_main_db_connection()
    if conn:
        try:
            cur = conn.cursor()
            
            cur.execute('SELECT "Наименование_вида_услуг" as name FROM service_types ORDER BY "Наименование_вида_услуг"')
            
            service_types = []
            for row in cur.fetchall():
                service_types.append({
                    "name": row[0]
                })
            
            return JSONResponse(content={"success": True, "data": service_types})
            
        except Exception as e:
            print(f"❌ Ошибка в get_service_types_reference: {e}")
            return JSONResponse(content={"success": False, "error": str(e)})
        finally:
            conn.close()
    else:
        return JSONResponse(content={"success": False, "error": "Ошибка подключения к БД"})
    
#-----------------------------------------------------------------------------------------------

# Добавить в main.py после существующих API endpoints для услуг

# API для управления пользователями в админ-панели
@app.get("/api/admin/users")
async def get_admin_users():
    """Возвращает список всех пользователей для админ-панели"""
    conn = get_users_db_connection()
    if conn:
        try:
            cur = conn.cursor()
            
            cur.execute("""
                SELECT 
                    id,
                    "ФИО" as full_name,
                    email,
                    "логин" as login,
                    "роль" as role,
                    "Дата_регистрации" as reg_date,
                    "Последний_вход" as last_login,
                    "статус" as status
                FROM users 
                ORDER BY "Дата_регистрации" DESC
            """)
            
            users = []
            for row in cur.fetchall():
                users.append({
                    "id": row[0],
                    "full_name": row[1],
                    "email": row[2],
                    "login": row[3],
                    "role": row[4],
                    "reg_date": row[5].isoformat() if row[5] else None,
                    "last_login": row[6].isoformat() if row[6] else None,
                    "status": row[7]
                })
            
            # Получаем количество администраторов
            cur.execute('SELECT COUNT(*) FROM users WHERE "роль" = %s AND "статус" = %s', ('admin', 'active'))
            admin_count = cur.fetchone()[0]
            
            return JSONResponse(content={
                "success": True, 
                "users": users,
                "admin_count": admin_count
            })
            
        except Exception as e:
            print(f"❌ Ошибка в get_admin_users: {e}")
            return JSONResponse(content={"success": False, "error": str(e)})
        finally:
            conn.close()
    else:
        return JSONResponse(content={"success": False, "error": "Ошибка подключения к БД пользователей"})

@app.post("/api/admin/users")
async def create_admin_user(request: Request):
    """Создает нового пользователя"""
    conn = get_users_db_connection()
    if conn:
        try:
            data = await request.json()
            
            # Валидация обязательных полей
            required_fields = ['full_name', 'email', 'login', 'password', 'role', 'status']
            for field in required_fields:
                if not data.get(field):
                    return JSONResponse(content={"success": False, "error": f"Обязательное поле: {field}"})
            
            # Проверка длины пароля
            if len(data['password']) < 6:
                return JSONResponse(content={"success": False, "error": "Пароль должен содержать минимум 6 символов"})
            
            cur = conn.cursor()
            
            # Проверяем уникальность email
            cur.execute('SELECT COUNT(*) FROM users WHERE email = %s', (data['email'],))
            if cur.fetchone()[0] > 0:
                return JSONResponse(content={"success": False, "error": "Пользователь с таким email уже существует"})
            
            # Проверяем уникальность логина
            cur.execute('SELECT COUNT(*) FROM users WHERE "логин" = %s', (data['login'],))
            if cur.fetchone()[0] > 0:
                return JSONResponse(content={"success": False, "error": "Пользователь с таким логином уже существует"})
            
            # Хэшируем пароль
            from app.auth.utils import hash_password
            password_hash = hash_password(data['password'])
            
            # Вставляем нового пользователя
            cur.execute("""
                INSERT INTO users 
                ("ФИО", email, "логин", "пароль_хэш", "роль", "статус")
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (
                data['full_name'],
                data['email'],
                data['login'],
                password_hash,
                data['role'],
                data['status']
            ))
            
            conn.commit()
            return JSONResponse(content={"success": True, "message": "Пользователь успешно создан"})
            
        except Exception as e:
            conn.rollback()
            print(f"❌ Ошибка в create_admin_user: {e}")
            return JSONResponse(content={"success": False, "error": str(e)})
        finally:
            conn.close()
    else:
        return JSONResponse(content={"success": False, "error": "Ошибка подключения к БД пользователей"})

@app.put("/api/admin/users/{user_id}")
async def update_admin_user(user_id: int, request: Request):
    """Обновляет данные пользователя"""
    conn = get_users_db_connection()
    if conn:
        try:
            data = await request.json()
            
            # Валидация обязательных полей
            required_fields = ['full_name', 'email', 'login', 'role', 'status']
            for field in required_fields:
                if not data.get(field):
                    return JSONResponse(content={"success": False, "error": f"Обязательное поле: {field}"})
            
            cur = conn.cursor()
            
            # Проверяем существование пользователя
            cur.execute('SELECT "роль" FROM users WHERE id = %s', (user_id,))
            user_result = cur.fetchone()
            if not user_result:
                return JSONResponse(content={"success": False, "error": "Пользователь не найден"})
            
            current_role = user_result[0]
            
            # Проверяем, не пытаемся ли изменить роль последнего активного администратора
            if current_role == 'admin' and data['role'] != 'admin':
                cur.execute('SELECT COUNT(*) FROM users WHERE "роль" = %s AND "статус" = %s AND id != %s', 
                           ('admin', 'active', user_id))
                if cur.fetchone()[0] == 0:
                    return JSONResponse(content={"success": False, "error": "Нельзя изменить роль последнего активного администратора"})
            
            # Проверяем уникальность email (исключая текущего пользователя)
            cur.execute('SELECT COUNT(*) FROM users WHERE email = %s AND id != %s', (data['email'], user_id))
            if cur.fetchone()[0] > 0:
                return JSONResponse(content={"success": False, "error": "Пользователь с таким email уже существует"})
            
            # Проверяем уникальность логина (исключая текущего пользователя)
            cur.execute('SELECT COUNT(*) FROM users WHERE "логин" = %s AND id != %s', (data['login'], user_id))
            if cur.fetchone()[0] > 0:
                return JSONResponse(content={"success": False, "error": "Пользователь с таким логином уже существует"})
            
            # Формируем запрос обновления
            update_fields = []
            update_values = []
            
            update_fields.append('"ФИО" = %s')
            update_values.append(data['full_name'])
            
            update_fields.append('email = %s')
            update_values.append(data['email'])
            
            update_fields.append('"логин" = %s')
            update_values.append(data['login'])
            
            update_fields.append('"роль" = %s')
            update_values.append(data['role'])
            
            update_fields.append('"статус" = %s')
            update_values.append(data['status'])
            
            # Если указан пароль, обновляем его
            if data.get('password'):
                if len(data['password']) < 6:
                    return JSONResponse(content={"success": False, "error": "Пароль должен содержать минимум 6 символов"})
                from app.auth.utils import hash_password
                password_hash = hash_password(data['password'])
                update_fields.append('"пароль_хэш" = %s')
                update_values.append(password_hash)
            
            update_values.append(user_id)
            
            # Выполняем обновление
            query = f"UPDATE users SET {', '.join(update_fields)} WHERE id = %s"
            cur.execute(query, update_values)
            
            conn.commit()
            return JSONResponse(content={"success": True, "message": "Пользователь успешно обновлен"})
            
        except Exception as e:
            conn.rollback()
            print(f"❌ Ошибка в update_admin_user: {e}")
            return JSONResponse(content={"success": False, "error": str(e)})
        finally:
            conn.close()
    else:
        return JSONResponse(content={"success": False, "error": "Ошибка подключения к БД пользователей"})

@app.delete("/api/admin/users/{user_id}")
async def delete_admin_user(user_id: int):
    """Удаляет пользователя"""
    conn = get_users_db_connection()
    if conn:
        try:
            cur = conn.cursor()
            
            # Проверяем существование пользователя
            cur.execute('SELECT "роль" FROM users WHERE id = %s', (user_id,))
            user_result = cur.fetchone()
            if not user_result:
                return JSONResponse(content={"success": False, "error": "Пользователь не найден"})
            
            # Проверяем, не пытаемся ли удалить последнего активного администратора
            if user_result[0] == 'admin':
                cur.execute('SELECT COUNT(*) FROM users WHERE "роль" = %s AND "статус" = %s AND id != %s', 
                           ('admin', 'active', user_id))
                if cur.fetchone()[0] == 0:
                    return JSONResponse(content={"success": False, "error": "Нельзя удалить последнего активного администратора"})
            
            # Удаляем пользователя
            cur.execute('DELETE FROM users WHERE id = %s', (user_id,))
            
            conn.commit()
            return JSONResponse(content={"success": True, "message": "Пользователь успешно удален"})
            
        except Exception as e:
            conn.rollback()
            print(f"❌ Ошибка в delete_admin_user: {e}")
            return JSONResponse(content={"success": False, "error": str(e)})
        finally:
            conn.close()
    else:
        return JSONResponse(content={"success": False, "error": "Ошибка подключения к БД пользователей"})

@app.put("/api/admin/users/{user_id}/status")
async def update_user_status(user_id: int, request: Request):
    """Изменяет статус пользователя (активен/заблокирован)"""
    conn = get_users_db_connection()
    if conn:
        try:
            data = await request.json()
            new_status = data.get('status')
            
            if new_status not in ['active', 'blocked']:
                return JSONResponse(content={"success": False, "error": "Некорректный статус"})
            
            cur = conn.cursor()
            
            # Проверяем существование пользователя
            cur.execute('SELECT "роль" FROM users WHERE id = %s', (user_id,))
            user_result = cur.fetchone()
            if not user_result:
                return JSONResponse(content={"success": False, "error": "Пользователь не найден"})
            
            # Проверяем, не пытаемся ли заблокировать последнего активного администратора
            if user_result[0] == 'admin' and new_status == 'blocked':
                cur.execute('SELECT COUNT(*) FROM users WHERE "роль" = %s AND "статус" = %s AND id != %s', 
                           ('admin', 'active', user_id))
                if cur.fetchone()[0] == 0:
                    return JSONResponse(content={"success": False, "error": "Нельзя заблокировать последнего активного администратора"})
            
            # Обновляем статус
            cur.execute('UPDATE users SET "статус" = %s WHERE id = %s', (new_status, user_id))
            
            conn.commit()
            return JSONResponse(content={"success": True, "message": f"Статус пользователя успешно изменен на {new_status}"})
            
        except Exception as e:
            conn.rollback()
            print(f"❌ Ошибка в update_user_status: {e}")
            return JSONResponse(content={"success": False, "error": str(e)})
        finally:
            conn.close()
    else:
        return JSONResponse(content={"success": False, "error": "Ошибка подключения к БД пользователей"})


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)