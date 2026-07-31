import asyncio
import importlib
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

import tldextract

from clicksafe.domain.analysis import UrlAnalysisContext
from clicksafe.domain.enums import EvidenceSeverity
from clicksafe.domain.evidence import EvidenceCategory, EvidenceItem


class WhoisAnalyzer:
    def __init__(self, timeout_seconds: float = 8.0) -> None:
        self._timeout_seconds = timeout_seconds

    @property
    def name(self) -> str:
        return "whois"

    async def analyze(self, context: UrlAnalysisContext) -> list[EvidenceItem]:
        target_url = context.final_url or context.normalized_url or context.submitted_url
        hostname = urlparse(target_url).hostname
        registered_domain = self._registered_domain(hostname)
        if registered_domain is None:
            return [
                EvidenceItem(
                    source=self.name,
                    category=EvidenceCategory.TECHNICAL,
                    severity=EvidenceSeverity.LOW,
                    title="WHOIS lookup skipped",
                    description="No registered domain could be derived for WHOIS lookup.",
                    data={"available": False},
                )
            ]

        try:
            whois_data = await asyncio.wait_for(
                asyncio.to_thread(self._lookup_whois, registered_domain),
                timeout=self._timeout_seconds,
            )
        except (OSError, TimeoutError, AttributeError) as exc:
            return [
                EvidenceItem(
                    source=self.name,
                    category=EvidenceCategory.TECHNICAL,
                    severity=EvidenceSeverity.LOW,
                    title="WHOIS lookup unavailable",
                    description="WHOIS data could not be retrieved within the configured timeout.",
                    data={
                        "available": False,
                        "domain": registered_domain,
                        "error": type(exc).__name__,
                    },
                )
            ]

        creation_date = self._first_datetime(whois_data.get("creation_date"))
        expiration_date = self._first_datetime(whois_data.get("expiration_date"))
        domain_age_days = (
            (datetime.now(UTC) - creation_date).days if creation_date is not None else None
        )
        days_until_expiry = (
            (expiration_date - datetime.now(UTC)).days if expiration_date is not None else None
        )

        severity = EvidenceSeverity.INFO
        if domain_age_days is not None and domain_age_days < 30:
            severity = EvidenceSeverity.HIGH
        elif domain_age_days is not None and domain_age_days < 180:
            severity = EvidenceSeverity.MEDIUM

        return [
            EvidenceItem(
                source=self.name,
                category=EvidenceCategory.TECHNICAL,
                severity=severity,
                title="WHOIS registration data inspected",
                description="Domain registration metadata was retrieved when available.",
                data={
                    "available": True,
                    "domain": registered_domain,
                    "registrar": self._first_string(whois_data.get("registrar")),
                    "creation_date": creation_date.isoformat() if creation_date else None,
                    "expiration_date": expiration_date.isoformat() if expiration_date else None,
                    "domain_age_days": domain_age_days,
                    "days_until_expiry": days_until_expiry,
                    "name_servers": self._string_list(whois_data.get("name_servers")),
                },
            )
        ]

    def _registered_domain(self, hostname: str | None) -> str | None:
        if not hostname:
            return None
        extracted = tldextract.extract(hostname)
        if not extracted.domain or not extracted.suffix:
            return hostname
        return f"{extracted.domain}.{extracted.suffix}"

    def _lookup_whois(self, domain: str) -> dict[str, Any]:
        whois_module = importlib.import_module("whois")
        result = whois_module.whois(domain)
        return dict(result)

    def _first_datetime(self, value: object) -> datetime | None:
        if isinstance(value, datetime):
            return value.replace(tzinfo=value.tzinfo or UTC)
        if isinstance(value, list):
            for item in value:
                parsed = self._first_datetime(item)
                if parsed is not None:
                    return parsed
        return None

    def _first_string(self, value: object) -> str | None:
        if isinstance(value, str):
            return value
        if isinstance(value, list):
            for item in value:
                if isinstance(item, str):
                    return item
        return None

    def _string_list(self, value: object) -> list[str]:
        if isinstance(value, str):
            return [value]
        if isinstance(value, list):
            return sorted({str(item) for item in value if item})
        return []
