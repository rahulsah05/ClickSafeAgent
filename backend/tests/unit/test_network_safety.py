import pytest

from clicksafe.application.errors import UnsafeDestinationError
from clicksafe.application.services.network_safety import DestinationSafetyService
from clicksafe.core.config import Settings
from clicksafe.infrastructure.browser.playwright_client import (
    BrowserNavigationError,
    PlaywrightClient,
)


async def public_resolver(hostname: str, port: int) -> set[str]:
    assert hostname == "example.com"
    assert port == 443
    return {"93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"}


@pytest.mark.asyncio
async def test_allows_hostname_resolving_only_to_public_addresses() -> None:
    service = DestinationSafetyService(Settings(), resolver=public_resolver)

    result = await service.validate_url("https://example.com/path")

    assert result.hostname == "example.com"
    assert result.port == 443
    assert result.resolved_addresses == ("2606:2800:220:1:248:1893:25c8:1946", "93.184.216.34")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/",
        "http://10.0.0.4/",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]/",
        "http://localhost/",
        "http://service.internal/",
    ],
)
async def test_rejects_private_and_special_use_destinations(url: str) -> None:
    service = DestinationSafetyService(Settings())

    with pytest.raises(UnsafeDestinationError):
        await service.validate_url(url)


@pytest.mark.asyncio
async def test_rejects_hostname_that_resolves_to_a_private_address() -> None:
    async def private_resolver(hostname: str, port: int) -> set[str]:
        _ = hostname, port
        return {"93.184.216.34", "192.168.1.10"}

    service = DestinationSafetyService(Settings(), resolver=private_resolver)

    with pytest.raises(UnsafeDestinationError, match="restricted IP"):
        await service.validate_url("https://example.com/")


@pytest.mark.asyncio
async def test_browser_client_maps_unsafe_destination_to_a_navigation_error() -> None:
    async def private_resolver(hostname: str, port: int) -> set[str]:
        _ = hostname, port
        return {"127.0.0.1"}

    safety_service = DestinationSafetyService(Settings(), resolver=private_resolver)
    client = PlaywrightClient(destination_safety_service=safety_service)

    with pytest.raises(BrowserNavigationError) as error:
        await client._validate_destination("https://example.com/")

    assert error.value.error_code == "unsafe_destination"
