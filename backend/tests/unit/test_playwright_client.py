from pathlib import Path

from playwright.async_api import Error as PlaywrightError
from playwright.async_api import TimeoutError as PlaywrightTimeoutError

from clicksafe.core.config import Settings
from clicksafe.infrastructure.browser.playwright_client import (
    BrowserNavigationError,
    BrowserSetupError,
    PlaywrightClient,
    map_playwright_error,
)


def test_limits_html_to_configured_byte_count() -> None:
    client = PlaywrightClient(Settings(max_html_bytes=10_000))

    limited_html, html_size_bytes, truncated = client._limit_html("a" * 10_001)

    assert len(limited_html) == 10_000
    assert html_size_bytes == 10_001
    assert truncated is True


def test_writes_html_artifact(tmp_path: Path) -> None:
    client = PlaywrightClient(Settings(html_dir=str(tmp_path)))

    artifact_path = client._write_text_artifact(
        directory=str(tmp_path),
        artifact_id="analysis-id",
        suffix=".html",
        content="<html></html>",
    )

    assert artifact_path.read_text(encoding="utf-8") == "<html></html>"


def test_maps_playwright_timeout_to_navigation_error() -> None:
    mapped_error = map_playwright_error(PlaywrightTimeoutError("Timeout 1000ms exceeded"))

    assert isinstance(mapped_error, BrowserNavigationError)
    assert mapped_error.error_code == "navigation_timeout"


def test_maps_missing_browser_to_setup_error() -> None:
    mapped_error = map_playwright_error(
        PlaywrightError("Executable doesn't exist. Please run playwright install.")
    )

    assert isinstance(mapped_error, BrowserSetupError)
    assert mapped_error.error_code == "browser_not_installed"


def test_maps_generic_playwright_error_to_navigation_error() -> None:
    mapped_error = map_playwright_error(PlaywrightError("net::ERR_NAME_NOT_RESOLVED"))

    assert isinstance(mapped_error, BrowserNavigationError)
    assert mapped_error.error_code == "navigation_failed"
