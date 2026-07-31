import asyncio
import socket
import ssl
from datetime import UTC, datetime
from typing import Any, cast
from urllib.parse import urlparse

from clicksafe.domain.analysis import UrlAnalysisContext
from clicksafe.domain.enums import EvidenceSeverity
from clicksafe.domain.evidence import EvidenceCategory, EvidenceItem


class SslAnalyzer:
    def __init__(self, timeout_seconds: float = 5.0) -> None:
        self._timeout_seconds = timeout_seconds

    @property
    def name(self) -> str:
        return "ssl"

    async def analyze(self, context: UrlAnalysisContext) -> list[EvidenceItem]:
        parsed_url = urlparse(context.final_url or context.normalized_url or context.submitted_url)
        hostname = parsed_url.hostname
        if parsed_url.scheme != "https" or not hostname:
            return [
                EvidenceItem(
                    source=self.name,
                    category=EvidenceCategory.TECHNICAL,
                    severity=EvidenceSeverity.MEDIUM,
                    title="HTTPS certificate unavailable",
                    description="The final URL is not HTTPS or no hostname was available.",
                    data={"has_certificate": False, "scheme": parsed_url.scheme},
                )
            ]

        port = parsed_url.port or 443
        try:
            certificate = await asyncio.wait_for(
                asyncio.to_thread(self._fetch_certificate, hostname, port),
                timeout=self._timeout_seconds + 1,
            )
        except (OSError, ssl.SSLError, TimeoutError) as exc:
            return [
                EvidenceItem(
                    source=self.name,
                    category=EvidenceCategory.TECHNICAL,
                    severity=EvidenceSeverity.HIGH,
                    title="TLS certificate inspection failed",
                    description="The TLS certificate could not be retrieved for the final URL.",
                    data={
                        "hostname": hostname,
                        "port": port,
                        "has_certificate": False,
                        "error": type(exc).__name__,
                    },
                )
            ]

        not_after = self._parse_cert_datetime(certificate.get("notAfter"))
        days_until_expiry = (
            (not_after - datetime.now(UTC)).days if not_after is not None else None
        )
        severity = EvidenceSeverity.INFO
        if days_until_expiry is not None and days_until_expiry < 0:
            severity = EvidenceSeverity.CRITICAL
        elif days_until_expiry is not None and days_until_expiry < 14:
            severity = EvidenceSeverity.MEDIUM

        return [
            EvidenceItem(
                source=self.name,
                category=EvidenceCategory.TECHNICAL,
                severity=severity,
                title="TLS certificate inspected",
                description="The final HTTPS certificate was retrieved and summarized.",
                data={
                    "hostname": hostname,
                    "port": port,
                    "has_certificate": True,
                    "subject": self._name_tuple_to_dict(certificate.get("subject", ())),
                    "issuer": self._name_tuple_to_dict(certificate.get("issuer", ())),
                    "not_before": certificate.get("notBefore"),
                    "not_after": certificate.get("notAfter"),
                    "days_until_expiry": days_until_expiry,
                    "serial_number": certificate.get("serialNumber"),
                    "version": certificate.get("version"),
                },
            )
        ]

    def _fetch_certificate(self, hostname: str, port: int) -> dict[str, Any]:
        ssl_context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=self._timeout_seconds) as sock:
            with ssl_context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                return cast(dict[str, Any], tls_sock.getpeercert())

    def _parse_cert_datetime(self, value: object) -> datetime | None:
        if not isinstance(value, str):
            return None
        try:
            return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)
        except ValueError:
            return None

    def _name_tuple_to_dict(self, value: object) -> dict[str, str]:
        output: dict[str, str] = {}
        if not isinstance(value, tuple):
            return output
        for group in value:
            if not isinstance(group, tuple):
                continue
            for item in group:
                if isinstance(item, tuple) and len(item) == 2:
                    output[str(item[0])] = str(item[1])
        return output
