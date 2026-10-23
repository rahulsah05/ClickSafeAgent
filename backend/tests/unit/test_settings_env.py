from pathlib import Path

import pytest
from pydantic_settings import SettingsConfigDict

from clicksafe.core.config import Settings, get_settings


def test_settings_env_file_points_at_the_backend_dotenv() -> None:
    env_files = Settings.model_config["env_file"]
    backend_env = Path(env_files[0])
    root_env = Path(env_files[1])

    assert backend_env.is_absolute()
    assert backend_env.name == ".env"
    assert backend_env.parent.name == "backend"
    assert backend_env.is_file()
    assert root_env == backend_env.parent.parent / ".env"


def test_explicit_env_file_loads_outside_the_working_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    env_dir = tmp_path / "config"
    work_dir = tmp_path / "other"
    env_dir.mkdir()
    work_dir.mkdir()
    env_path = env_dir / ".env"
    env_path.write_text(
        "APP_NAME=From File\nOPENAI_MODEL=gpt-from-file\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(work_dir)
    for name in ("APP_NAME", "OPENAI_MODEL"):
        monkeypatch.delenv(name, raising=False)

    class IsolatedSettings(Settings):
        model_config = SettingsConfigDict(
            env_file=env_path,
            env_file_encoding="utf-8",
            extra="ignore",
            case_sensitive=False,
        )

    loaded = IsolatedSettings()

    assert loaded.app_name == "From File"
    assert loaded.openai_model == "gpt-from-file"

    monkeypatch.setenv("OPENAI_MODEL", "gpt-from-env")
    overridden = IsolatedSettings()

    assert overridden.openai_model == "gpt-from-env"
    get_settings.cache_clear()


def test_backend_dotenv_sets_gpt_5_4_mini() -> None:
    backend_env = Path(Settings.model_config["env_file"][0])
    model_lines = [
        line.split("=", 1)[1].strip().strip('"').strip("'")
        for line in backend_env.read_text(encoding="utf-8").splitlines()
        if line.startswith("OPENAI_MODEL=")
    ]

    assert model_lines == ["gpt-5.4-mini"]


def test_code_default_model_is_gpt_5_4_mini(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    env_path = tmp_path / ".env"
    env_path.write_text("APP_NAME=From File\n", encoding="utf-8")
    monkeypatch.delenv("OPENAI_MODEL", raising=False)

    class BareSettings(Settings):
        model_config = SettingsConfigDict(
            env_file=env_path,
            env_file_encoding="utf-8",
            extra="ignore",
            case_sensitive=False,
        )

    assert BareSettings().openai_model == "gpt-5.4-mini"


def test_process_environment_overrides_dotenv_model(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENAI_MODEL", "gpt-process-override")
    monkeypatch.setenv("OPENAI_API_KEY", "")
    get_settings.cache_clear()
    try:
        loaded = get_settings()
        key_overridden = loaded.openai_api_key == ""
        assert loaded.openai_model == "gpt-process-override"
        assert key_overridden
    finally:
        get_settings.cache_clear()
