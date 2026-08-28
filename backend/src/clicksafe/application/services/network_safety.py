import asyncio
import ipaddress
import socket
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import urlparse

from clicksafe.application.errors import UnsafeDestinationError
from clicksafe.core.config import Settings, get_settings

Resolver = Callable[[str, int], Awaitable[set[str]]]

BLOCKED_HOST_SUFFIXES = (".localhost", ".local", ".internal")
BLOCKED_HOSTNAMES = {"localhost", "local", "internal", "metadata.google.internal"}
DEFAULT_PORTS = {"http": 80, "https": 443}


@dataclass(frozen=True, slots=True)
class DestinationSafetyResult:
    hostname: str
    port: int
    resolved_addresses: tuple[str, ...]


class DestinationSafetyClient(Protocol):
    async def validate_url(self, url: str) -> DestinationSafetyResult:
        ...


class DestinationSafetyService:
    """Validates that browser navigation targets are publicly routable destinations."""

    def __init__(
        self,
        settings: Settings | None = None,
        resolver: Resolver | None = None,
    ) -> None:
        self._settings = settings or get_settings()
        self._resolver = resolver or self._resolve_host

    async def validate_url(self, url: str) -> DestinationSafetyResult:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if hostname is None:
            raise UnsafeDestinationError("URL hostname could not be validated for safe scanning.")

        try:
            port = parsed.port or DEFAULT_PORTS.get(parsed.scheme, 443)
        except ValueError as exc:
            raise UnsafeDestinationError(
                "URL port could not be validated for safe scanning."
            ) from exc

        hostname = hostname.rstrip(".").lower()
        if not self._settings.block_private_networks:
            return DestinationSafetyResult(hostname=hostname, port=port, resolved_addresses=())

        if self._is_blocked_hostname(hostname):
            raise UnsafeDestinationError(
                "URLs targeting local or private hostnames are not allowed."
            )

        literal_address = self._parse_address(hostname)
        if literal_address is not None:
            self._require_public_address(literal_address)
            return DestinationSafetyResult(
                hostname=hostname,
                port=port,
                resolved_addresses=(str(literal_address),),
            )

        addresses = await self._resolve_public_addresses(hostname, port)
        return DestinationSafetyResult(
            hostname=hostname,
            port=port,
            resolved_addresses=tuple(sorted(addresses)),
        )

    def _is_blocked_hostname(self, hostname: str) -> bool:
        return hostname in BLOCKED_HOSTNAMES or hostname.endswith(BLOCKED_HOST_SUFFIXES)

    async def _resolve_public_addresses(self, hostname: str, port: int) -> set[str]:
        try:
            addresses = await asyncio.wait_for(
                self._resolver(hostname, port),
                timeout=self._settings.dns_resolution_timeout_seconds,
            )
        except (OSError, TimeoutError) as exc:
            raise UnsafeDestinationError(
                "URL hostname could not be resolved for safe scanning."
            ) from exc

        if not addresses:
            raise UnsafeDestinationError("URL hostname could not be resolved for safe scanning.")

        for value in addresses:
            address = self._parse_address(value)
            if address is None:
                raise UnsafeDestinationError("URL hostname returned an invalid network address.")
            self._require_public_address(address)
        return addresses

    async def _resolve_host(self, hostname: str, port: int) -> set[str]:
        loop = asyncio.get_running_loop()
        results = await loop.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
        return {str(result[4][0]) for result in results}

    def _parse_address(self, value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
        try:
            return ipaddress.ip_address(value)
        except ValueError:
            return None

    def _require_public_address(
        self,
        address: ipaddress.IPv4Address | ipaddress.IPv6Address,
    ) -> None:
        if not address.is_global:
            raise UnsafeDestinationError(
                "URLs targeting local, private, or otherwise restricted IP addresses are not "
                "allowed."
            )
