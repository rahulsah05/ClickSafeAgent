from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

from playwright.async_api import (
    Error as PlaywrightError,
)
from playwright.async_api import (
    Page,
    Request,
    Response,
    Route,
    async_playwright,
)
from playwright.async_api import TimeoutError as PlaywrightTimeoutError

from clicksafe.application.errors import UnsafeDestinationError
from clicksafe.application.services.network_safety import (
    DestinationSafetyClient,
    DestinationSafetyService,
)
from clicksafe.core.config import Settings, get_settings

REDIRECT_STATUS_CODES = {301, 302, 303, 307, 308}


class BrowserCaptureError(RuntimeError):
    def __init__(self, message: str, *, error_code: str) -> None:
        super().__init__(message)
        self.error_code = error_code


class BrowserSetupError(BrowserCaptureError):
    pass


class BrowserNavigationError(BrowserCaptureError):
    pass


class BrowserContentLimitError(BrowserCaptureError):
    pass


@dataclass(frozen=True, slots=True)
class BrowserRedirect:
    url: str
    status_code: int
    location: str | None


@dataclass(frozen=True, slots=True)
class BrowserCapture:
    final_url: str
    redirects: list[BrowserRedirect]
    status_code: int | None
    html_path: str
    html_size_bytes: int
    html_truncated: bool
    screenshot_path: str
    blocked_request_count: int = 0


class PlaywrightClient:
    def __init__(
        self,
        settings: Settings | None = None,
        destination_safety_service: DestinationSafetyClient | None = None,
    ) -> None:
        self._settings = settings or get_settings()
        self._destination_safety_service = destination_safety_service or DestinationSafetyService(
            self._settings
        )

    async def capture(self, url: str, *, analysis_id: str | None = None) -> BrowserCapture:
        redirects: list[BrowserRedirect] = []
        blocked_request_count = 0
        artifact_id = analysis_id or str(uuid4())
        await self._validate_destination(url)

        try:
            async with async_playwright() as playwright:
                browser = await playwright.chromium.launch(
                    headless=self._settings.playwright_headless,
                )
                try:
                    context = await browser.new_context(
                        accept_downloads=False,
                        ignore_https_errors=True,
                        java_script_enabled=True,
                        service_workers="block",
                        user_agent=(
                            "ClickSafe/0.1 security scanner "
                            "(Playwright; compatible; phishing analysis)"
                        ),
                        viewport={"width": 1365, "height": 768},
                    )
                    context.set_default_timeout(self._settings.browser_timeout_ms)
                    context.set_default_navigation_timeout(self._settings.browser_timeout_ms)

                    async def guard_request(route: Route, request: Request) -> None:
                        nonlocal blocked_request_count
                        if not _is_http_url(request.url):
                            await route.continue_()
                            return
                        try:
                            await self._validate_destination(request.url)
                        except BrowserNavigationError:
                            blocked_request_count += 1
                            await route.abort("blockedbyclient")
                            return
                        await route.continue_()

                    await context.route("**/*", guard_request)

                    page = await context.new_page()
                    page.on("response", lambda response: self._record_redirect(response, redirects))
                    try:
                        response = await page.goto(
                            url,
                            wait_until="domcontentloaded",
                            timeout=self._settings.browser_timeout_ms,
                        )
                    except (PlaywrightError, PlaywrightTimeoutError) as exc:
                        if blocked_request_count:
                            raise BrowserNavigationError(
                                "Browser navigation was blocked by the destination safety policy.",
                                error_code="unsafe_destination",
                            ) from exc
                        raise
                    await self._wait_for_quiet_page(page)

                    if len(redirects) > self._settings.max_redirects:
                        raise BrowserNavigationError(
                            "Redirect limit exceeded during browser navigation.",
                            error_code="redirect_limit_exceeded",
                        )

                    html = await page.content()
                    limited_html, html_size_bytes, html_truncated = self._limit_html(html)
                    html_path = self._write_text_artifact(
                        directory=self._settings.html_dir,
                        artifact_id=artifact_id,
                        suffix=".html",
                        content=limited_html,
                    )
                    screenshot_path = await self._capture_screenshot(page, artifact_id)

                    return BrowserCapture(
                        final_url=page.url,
                        redirects=redirects,
                        status_code=response.status if response is not None else None,
                        html_path=str(html_path),
                        html_size_bytes=html_size_bytes,
                        html_truncated=html_truncated,
                        screenshot_path=str(screenshot_path),
                        blocked_request_count=blocked_request_count,
                    )
                finally:
                    await browser.close()
        except BrowserCaptureError:
            raise
        except (PlaywrightError, PlaywrightTimeoutError) as exc:
            raise map_playwright_error(exc) from exc

    async def _wait_for_quiet_page(self, page: Page) -> None:
        try:
            await page.wait_for_load_state(
                "networkidle",
                timeout=min(self._settings.browser_timeout_ms, 5_000),
            )
        except PlaywrightTimeoutError:
            return

    async def _validate_destination(self, url: str) -> None:
        try:
            await self._destination_safety_service.validate_url(url)
        except UnsafeDestinationError as exc:
            raise BrowserNavigationError(
                "Browser navigation was blocked by the destination safety policy.",
                error_code="unsafe_destination",
            ) from exc

    def _record_redirect(self, response: Response, redirects: list[BrowserRedirect]) -> None:
        if response.status not in REDIRECT_STATUS_CODES:
            return

        redirects.append(
            BrowserRedirect(
                url=response.url,
                status_code=response.status,
                location=response.headers.get("location"),
            )
        )

    def _limit_html(self, html: str) -> tuple[str, int, bool]:
        encoded_html = html.encode("utf-8")
        html_size_bytes = len(encoded_html)
        if html_size_bytes <= self._settings.max_html_bytes:
            return html, html_size_bytes, False

        limited_html = encoded_html[: self._settings.max_html_bytes].decode(
            "utf-8",
            errors="ignore",
        )
        return limited_html, html_size_bytes, True

    def _write_text_artifact(
        self,
        *,
        directory: str,
        artifact_id: str,
        suffix: str,
        content: str,
    ) -> Path:
        artifact_dir = self._resolve_artifact_dir(directory)
        artifact_dir.mkdir(parents=True, exist_ok=True)
        artifact_path = artifact_dir / f"{artifact_id}{suffix}"
        artifact_path.write_text(content, encoding="utf-8")
        return artifact_path

    async def _capture_screenshot(self, page: Page, artifact_id: str) -> Path:
        screenshot_dir = self._resolve_artifact_dir(self._settings.screenshot_dir)
        screenshot_dir.mkdir(parents=True, exist_ok=True)
        screenshot_path = screenshot_dir / f"{artifact_id}.png"
        await page.screenshot(path=str(screenshot_path), full_page=True)
        return screenshot_path

    def _resolve_artifact_dir(self, directory: str) -> Path:
        path = Path(directory)
        if path.is_absolute():
            return path
        return Path.cwd() / path


def map_playwright_error(exc: PlaywrightError | PlaywrightTimeoutError) -> BrowserCaptureError:
    message = str(exc)
    if isinstance(exc, PlaywrightTimeoutError):
        return BrowserNavigationError(
            "Browser navigation timed out while loading the URL.",
            error_code="navigation_timeout",
        )

    lower_message = message.lower()
    if "executable doesn't exist" in lower_message or "playwright install" in lower_message:
        return BrowserSetupError(
            "Playwright Chromium is not installed. Run `python -m playwright install chromium`.",
            error_code="browser_not_installed",
        )

    return BrowserNavigationError(
        "Browser navigation failed while loading the URL.",
        error_code="navigation_failed",
    )


def _is_http_url(url: str) -> bool:
    return url.startswith(("http://", "https://"))
