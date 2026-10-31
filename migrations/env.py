from alembic import context
from sqlalchemy import create_engine

from pypi_monitor.db.models import Base
from pypi_monitor.settings import get_settings

# Tests point Alembic at their own database through sqlalchemy.url.
url = context.config.get_main_option("sqlalchemy.url") or (
    get_settings().database_url.get_secret_value()
)

if context.is_offline_mode():
    context.configure(url=url, target_metadata=Base.metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()
else:
    with create_engine(url).connect() as connection:
        context.configure(connection=connection, target_metadata=Base.metadata)
        with context.begin_transaction():
            context.run_migrations()
