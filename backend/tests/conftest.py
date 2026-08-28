import pytest
from fastapi.testclient import TestClient

from clicksafe.core.config import get_settings
from clicksafe.infrastructure.database.session import reset_database_state
from clicksafe.main import create_app


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch, tmp_path) -> TestClient:
    database_path = tmp_path / "clicksafe-test.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite+aiosqlite:///{database_path}")
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("OPENAI_API_KEY", "")
    monkeypatch.setenv("BLOCK_PRIVATE_NETWORKS", "false")
    get_settings.cache_clear()
    reset_database_state()

    with TestClient(create_app()) as test_client:
        yield test_client

    get_settings.cache_clear()
    reset_database_state()
