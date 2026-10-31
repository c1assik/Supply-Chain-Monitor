# 3.13: под 3.14 у зависимостей GuardDog (pygit2, yara-python) пока нет готовых wheels.
FROM python:3.13-slim

RUN useradd --create-home scm
WORKDIR /app
COPY pyproject.toml README.md alembic.ini ./
COPY src ./src
COPY migrations ./migrations
COPY config ./config
RUN pip install --no-cache-dir .

# GuardDog обновляет кэш топ-пакетов при импорте прямо в каталоге своих ресурсов.
RUN chown -R scm "$(python -c 'import guarddog, pathlib; print(pathlib.Path(guarddog.__file__).parent)')/analyzer/metadata/resources"

USER scm
ENTRYPOINT ["pypi-monitor"]
