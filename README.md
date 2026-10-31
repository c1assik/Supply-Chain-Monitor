# PyPI Supply Chain Monitor

Сервис следит за новыми релизами на PyPI и поднимает алерт, когда релиз похож на supply chain атаку.
Проект на этапе 0: каркас без логики мониторинга. Цели и план описаны в спецификации.

## Разработка

Нужны Python 3.12+ и Docker с Compose.

```sh
python -m venv .venv
.venv/bin/pip install -e . --group dev
.venv/bin/pre-commit install
cp .env.example .env
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
TEST_DATABASE_URL=postgresql+psycopg://scm:scm@localhost:5432/scm_test .venv/bin/pytest
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
| `src/pypi_monitor/analyzers/` | Интерфейс анализатора и формат сигнала |
| `src/pypi_monitor/scoring/` | Загрузка весов скоринга |
| `src/pypi_monitor/db/` | Модели SQLAlchemy |
| `migrations/` | Миграции Alembic |
| `config/scoring.yaml` | Веса скоринга и пороги уровней |
