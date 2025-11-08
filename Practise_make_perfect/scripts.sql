CREATE TABLE service_types (
    id SERIAL PRIMARY KEY,
    "Наименование_вида_услуг" VARCHAR(50) NOT NULL UNIQUE
);

-- 2. Таблица министерств
CREATE TABLE ministries (
    id SERIAL PRIMARY KEY,
    "Код_министерства" INTEGER NOT NULL UNIQUE,
    "Наименование_министерства" VARCHAR(100) NOT NULL
);

-- 3. Таблица отраслей
CREATE TABLE industries (
    id SERIAL PRIMARY KEY,
    "Код_отрасли" INTEGER NOT NULL UNIQUE,
    "Наименование_отрасли" VARCHAR(100) NOT NULL
);

-- 4. Таблица областей
CREATE TABLE regions (
    id SERIAL PRIMARY KEY,
    "Код_области" INTEGER NOT NULL UNIQUE,
    "Наименование_области" VARCHAR(50) NOT NULL
);

-- 5. Таблица районов
CREATE TABLE districts (
    id SERIAL PRIMARY KEY,
    "Код_района" INTEGER NOT NULL UNIQUE,
    "Наименование_района" VARCHAR(50) NOT NULL
    "Код_области" INTEGER
    FOREIGN KEY ("Код_области") REFERENCES regions("Код_области")
);

CREATE TABLE enterprises (
    id SERIAL PRIMARY KEY,
    "Наименование_предприятия" VARCHAR(255) NOT NULL,
    "Регистрационный_номер" BIGINT NOT NULL UNIQUE,
    "Код_министерства" INTEGER,
    "Код_отрасли" INTEGER,
    "Код_области" INTEGER,
    FOREIGN KEY ("Код_министерства") REFERENCES ministries("Код_министерства"),
    FOREIGN KEY ("Код_отрасли") REFERENCES industries("Код_отрасли"),
    FOREIGN KEY ("Код_области") REFERENCES regions("Код_области")
);

CREATE TABLE period (
    id SERIAL PRIMARY KEY,
    "Регистрационный_номер" BIGINT NOT NULL,
    "Отчетный_период" INTEGER NOT NULL,
    
    "ФИО_директора" VARCHAR(250),
    FOREIGN KEY ("Регистрационный_номер") REFERENCES enterprises("Регистрационный_номер") ON DELETE CASCADE,
    CONSTRAINT unique_reg_period UNIQUE ("Регистрационный_номер", "Отчетный_период")
);

CREATE TABLE services (
    id SERIAL PRIMARY KEY,
    "Регистрационный_номер" BIGINT NOT NULL,
    "Код_района" INTEGER,
    "Отчетный_период" INTEGER,
    "Наименование_вида_услуг" VARCHAR(250) NOT NULL,
    "Код_показателя" INTEGER,
    "План_всего" BIGINT,
    "Фактически_выполнено_всего" BIGINT,
    
    FOREIGN KEY ("Регистрационный_номер") REFERENCES enterprises("Регистрационный_номер") ON DELETE CASCADE,
    FOREIGN KEY ("Код_района") REFERENCES districts("Код_района"),
    FOREIGN KEY ("Регистрационный_номер", "Отчетный_период") REFERENCES period("Регистрационный_номер", "Отчетный_период"),
    FOREIGN KEY ("Наименование_вида_услуг") REFERENCES service_types("Наименование_вида_услуг")
);

-- Для поиска предприятий по названию
CREATE INDEX idx_enterprises_name ON enterprises("Наименование_предприятия");

-- Для поиска услуг по предприятию (основной сценарий)
CREATE INDEX idx_services_reg_number ON services("Регистрационный_номер");

-- Для фильтрации услуг по району
CREATE INDEX idx_services_district ON services("Код_района");

-- Для фильтрации услуг по периоду
CREATE INDEX idx_services_period ON services("Отчетный_период");

-- Для поиска услуг по виду услуги
CREATE INDEX idx_services_service_type ON services("Наименование_вида_услуг");

-- Для поиска периодов по предприятию
CREATE INDEX idx_period_reg_number ON period("Регистрационный_номер");

отдельная база данных "юзер"

CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    "ФИО" VARCHAR(250) NOT NULL,
    "email" VARCHAR(100) UNIQUE NOT NULL,
    "логин" VARCHAR(50) UNIQUE NOT NULL,
    "пароль_хэш" VARCHAR(255) NOT NULL,
    "роль" VARCHAR(20) NOT NULL DEFAULT 'user',
    "статус" VARCHAR(20) NOT NULL DEFAULT 'active',
    "Дата_регистрации" TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "Последний_вход" TIMESTAMP,
    
    CONSTRAINT valid_role CHECK ("роль" IN ('user', 'admin')),
    CONSTRAINT valid_status CHECK ("статус" IN ('active', 'blocked'))
);

-- Индексы для быстрого поиска
CREATE INDEX idx_users_login ON users("логин");
CREATE INDEX idx_users_email ON users("email");
CREATE INDEX idx_users_status ON users("статус");