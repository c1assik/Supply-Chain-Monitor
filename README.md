# PyPI Supply Chain Monitor

Сервис следит за новыми релизами на PyPI и поднимает алерт, когда релиз похож на supply chain атаку.
Готов этап 1: поток релизов, статический анализ, скоринг и алерты. Цели и план описаны в спецификации.

## Запуск

```sh
deploy/generate-env.sh   # создаёт .env со случайными секретами
docker compose up --detach --build --wait
```

Для алертов нужно заполнить в `.env` значения `SCM_TELEGRAM_TOKEN` и `SCM_TELEGRAM_CHAT_ID`. Без секретов
из `.env` ни compose, ни приложение не запустятся: значений по умолчанию у них нет.

При смене паролей помните, что Postgres и Grafana применяют их только при создании своих томов: в
существующих томах пароль меняется через `ALTER ROLE` и `grafana cli admin reset-admin-password`.

Compose применяет миграции и запускает поллер и воркер. При первом старте воркер загружает топ-5000
пакетов, дальше обновляет его каждую ночь. Без настроек Telegram алерты пишутся в лог воркера.

| Сервис | Адрес |
| --- | --- |
| Grafana (`admin` / `GRAFANA_PASSWORD`) | `http://localhost:3000` |
| Prometheus | `http://localhost:9090` |

Правила в `deploy/prometheus/alerts.yml` срабатывают на падение потока до нуля и на p95 задержки выше
10 минут. В Prometheus их видно на странице Alerts, Alertmanager пока не подключён.

## Как устроен пайплайн

Поллер кладёт новые релизы в `releases` и очередь arq. Воркер ведёт релиз по стадиям, каждая из
которых коммитит результат вместе со следующим статусом:

| Стадия | Что делает | Статус после неё |
| --- | --- | --- |
| `download` | Метаданные PyPI, sdist и один wheel, проверка sha256, запись в S3 | `downloaded` |
| `analyze` | Безопасная распаковка, анализаторы, запись `signals` | `analyzed` |
| `score` | Вердикт по `config/scoring.yaml` | `clean` или ждёт `alert` |
| `alert` | Сообщение в Telegram для High и Critical | `alerted` |

- Упавшая стадия повторяется `SCM_MAX_TRIES` раз, затем релиз получает `failed`.
- Раз в 5 минут `sweep` возвращает в очередь релизы, застрявшие после падения.
- Код из пакетов никогда не исполняется. Анализаторы и распаковка работают в пуле процессов, и воркер
  запускается без capabilities.

### Источники релизов

RSS опрашивается раз в 45 секунд ради задержки, `changelog_since_serial` раз в 5 минут и при старте
ради полноты. Замеры от 31.10.2026: `updates.xml` отдаёт 100 записей, это около 20 минут потока;
`packages.xml` — около 40 записей; всего выходит около 350 релизов в час. XML-RPC ограничен по
частоте, поэтому `user_packages` вызывается не чаще раза в 6 секунд, а сверх этого сигнал
`metadata.first_account_release` пропускается.

### Скоринг

Каждое правило считается один раз. Находки `threat-*` из GuardDog в коде, который исполняется сам
(`setup.py`, `.pth`, верхнеуровневый `__init__.py`), получают правило `guarddog.install.*` и полный вес.
В остальных файлах вес умножается на 0,2: там эти правила в основном описывают обычные CLI-инструменты
и агентов. Поэтому полезная нагрузка в модуле, который импортируется из `__init__.py`, сама по себе
набирает меньше и может не дойти до алерта. Цену этого решения покажет бенчмарк этапа 4.

Ложные срабатывания подавляются через `allowlist` в `config/scoring.yaml`.

## Разработка

Нужны Python 3.12+ и Docker с Compose. Под Python 3.14 у `pygit2` и `yara-python` нет готовых wheels:
понадобятся компилятор и `libgit2`. Образ и CI используют 3.13.

```sh
python -m venv .venv
.venv/bin/pip install -e . --group dev
.venv/bin/pre-commit install
deploy/generate-env.sh
```

Окружение и схема БД:

```sh
docker compose up --detach --wait
.venv/bin/alembic upgrade head
```

| Сервис | Адрес |
| --- | --- |
| PostgreSQL | `localhost:5432` |
| Redis | `localhost:6379` |
| S3 (SeaweedFS) | `http://localhost:8333` |

Проверки:

```sh
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/mypy
TEST_DATABASE_URL=postgresql+psycopg://scm:<POSTGRES_PASSWORD>@localhost:5432/scm_test .venv/bin/pytest
```

Без `TEST_DATABASE_URL` тесты миграций пропускаются. База из этой переменной очищается при каждом
запуске, поэтому она должна быть отдельной:

```sh
docker compose exec postgres createdb -U scm scm_test
```

Новая миграция после изменения `src/pypi_monitor/db/models.py`:

```sh
.venv/bin/alembic revision --autogenerate -m "описание"
```

## Структура

| Путь | Назначение |
| --- | --- |
| `src/pypi_monitor/analyzers/` | Анализаторы: метаданные, тайпсквоттинг, GuardDog |
| `src/pypi_monitor/scoring/` | Веса скоринга и расчёт скора |
| `src/pypi_monitor/db/` | Модели SQLAlchemy и сессии |
| `src/pypi_monitor/pypi/` | Клиент PyPI и разбор фидов |
| `src/pypi_monitor/ingest/` | Поллер: RSS и догон по changelog |
| `src/pypi_monitor/pipeline/` | Стадии пайплайна, очередь, безопасная распаковка |
| `src/pypi_monitor/alerts/` | Telegram |
| `src/pypi_monitor/worker.py` | Воркер arq |
| `deploy/` | Prometheus и Grafana |
| `migrations/` | Миграции Alembic |
| `config/scoring.yaml` | Веса скоринга и пороги уровней |
