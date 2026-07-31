import asyncio
from urllib.parse import urlparse

import dns.asyncresolver
import dns.exception

from clicksafe.domain.analysis import UrlAnalysisContext
from clicksafe.domain.enums import EvidenceSeverity
from clicksafe.domain.evidence import EvidenceCategory, EvidenceItem

DNS_RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "NS")


class DnsAnalyzer:
    def __init__(self, timeout_seconds: float = 5.0) -> None:
        self._timeout_seconds = timeout_seconds

    @property
    def name(self) -> str:
        return "dns"

    async def analyze(self, context: UrlAnalysisContext) -> list[EvidenceItem]:
        target_url = context.final_url or context.normalized_url or context.submitted_url
        hostname = urlparse(target_url).hostname
        if not hostname:
            return [
                EvidenceItem(
                    source=self.name,
                    category=EvidenceCategory.TECHNICAL,
                    severity=EvidenceSeverity.MEDIUM,
                    title="DNS lookup skipped",
                    description="No hostname was available for DNS lookup.",
                    data={"resolved": False},
                )
            ]

        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = self._timeout_seconds
        resolver.timeout = min(self._timeout_seconds, 2.0)

        records: dict[str, list[str]] = {}
        errors: dict[str, str] = {}
        for record_type in DNS_RECORD_TYPES:
            try:
                answer = await asyncio.wait_for(
                    resolver.resolve(hostname, record_type),
                    timeout=self._timeout_seconds,
                )
                records[record_type] = [record.to_text() for record in answer]
            except (dns.exception.DNSException, TimeoutError) as exc:
                errors[record_type] = type(exc).__name__

        resolved = bool(records.get("A") or records.get("AAAA"))
        severity = EvidenceSeverity.INFO if resolved else EvidenceSeverity.MEDIUM

        return [
            EvidenceItem(
                source=self.name,
                category=EvidenceCategory.TECHNICAL,
                severity=severity,
                title="DNS records resolved" if resolved else "DNS address records not resolved",
                description="DNS records were collected for the final page hostname.",
                data={
                    "hostname": hostname,
                    "resolved": resolved,
                    "records": records,
                    "errors": errors,
                },
            )
        ]
