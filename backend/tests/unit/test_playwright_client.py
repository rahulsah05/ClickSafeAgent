import asyncio
import sys
from pathlib import Path

import pytest
from playwright.async_api import Error as PlaywrightError
from playwright.async_api import TimeoutError as PlaywrightTimeoutError

from clicksafe.core.config import Settings
from clicksafe.infrastructure.browser.playwright_client import (
    BrowserCapture,
    BrowserNavigationError,
    BrowserSetupError,
    PlaywrightClient,
    _loop_can_spawn_subprocess,
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


def test_windows_selector_loop_cannot_spawn_a_subprocess() -> None:
    selector_loop = asyncio.SelectorEventLoop()
    try:
        if sys.platform == "win32":
            assert _loop_can_spawn_subprocess(selector_loop) is False
            proactor_loop = asyncio.ProactorEventLoop()
            try:
                assert _loop_can_spawn_subprocess(proactor_loop) is True
            finally:
                proactor_loop.close()
        else:
            assert _loop_can_spawn_subprocess(selector_loop) is True
    finally:
        selector_loop.close()


@pytest.mark.asyncio
async def test_capture_uses_proactor_thread_when_loop_cannot_spawn_subprocess(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = PlaywrightClient(Settings())
    expected = BrowserCapture(
        final_url="https://example.com/",
        redirects=[],
        status_code=200,
        html_path="page.html",
        html_size_bytes=12,
        html_truncated=False,
        screenshot_path="page.png",
    )
    seen: dict[str, str] = {}

    async def allow_destination(_url: str) -> None:
        return None

    def capture_on_thread(url: str, artifact_id: str) -> BrowserCapture:
        seen["url"] = url
        seen["artifact_id"] = artifact_id
        return expected

    monkeypatch.setattr(client, "_validate_destination", allow_destination)
    monkeypatch.setattr(
        "clicksafe.infrastructure.browser.playwright_client._loop_can_spawn_subprocess",
        lambda _loop: False,
    )
    monkeypatch.setattr(client, "_capture_on_proactor_loop", capture_on_thread)

    result = await client.capture("https://example.com", analysis_id="job-1")

    assert result is expected
    assert seen == {"url": "https://example.com", "artifact_id": "job-1"}


@pytest.mark.asyncio
async def test_capture_stays_on_the_running_loop_when_it_can_spawn_subprocess(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = PlaywrightClient(Settings())
    expected = BrowserCapture(
        final_url="https://example.com/",
        redirects=[],
        status_code=200,
        html_path="page.html",
        html_size_bytes=12,
        html_truncated=False,
        screenshot_path="page.png",
    )

    async def allow_destination(_url: str) -> None:
        return None

    async def capture_here(url: str, artifact_id: str) -> BrowserCapture:
        assert url == "https://example.com"
        assert artifact_id == "job-2"
        return expected

    def fail_if_threaded(_url: str, _artifact_id: str) -> BrowserCapture:
        raise AssertionError("browser capture moved to another thread")

    monkeypatch.setattr(client, "_validate_destination", allow_destination)
    monkeypatch.setattr(
        "clicksafe.infrastructure.browser.playwright_client._loop_can_spawn_subprocess",
        lambda _loop: True,
    )
    monkeypatch.setattr(client, "_capture_with_browser", capture_here)
    monkeypatch.setattr(client, "_capture_on_proactor_loop", fail_if_threaded)

    result = await client.capture("https://example.com", analysis_id="job-2")

    assert result is expected
