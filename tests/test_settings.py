import pytest
from pydantic import ValidationError

from pypi_monitor.settings import Settings


def test_service_refuses_to_start_without_secrets(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SCM_S3_SECRET_KEY")

    with pytest.raises(ValidationError, match="s3_secret_key"):
        Settings(_env_file=None)


def test_secrets_do_not_appear_in_repr(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SCM_S3_SECRET_KEY", "hunter2")

    assert "hunter2" not in repr(Settings(_env_file=None))
