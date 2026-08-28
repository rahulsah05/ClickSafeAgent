import re
from typing import Any
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from clicksafe.domain.analysis import UrlAnalysisContext
from clicksafe.domain.enums import EvidenceSeverity
from clicksafe.domain.evidence import EvidenceCategory, EvidenceItem
from clicksafe.infrastructure.payment.intelligence import PaymentIntelligenceClient

PAYMENT_PROVIDER_DOMAINS = {
    "paypal.com",
    "stripe.com",
    "squareup.com",
    "checkout.com",
    "razorpay.com",
    "pay.google.com",
    "paytm.com",
}
WALLET_PATTERNS = {
    "bitcoin": re.compile(r"\b(?:bc1[a-zA-HJ-NP-Z0-9]{25,87}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b"),
    "ethereum": re.compile(r"\b0x[a-fA-F0-9]{40}\b"),
    "tron": re.compile(r"\bT[1-9A-HJ-NP-Za-km-z]{33}\b"),
}
PAYMENT_LANGUAGE = re.compile(
    r"\b(pay(?:ment)?|crypto(?:currency)?|bitcoin|ethereum|wallet|wire transfer|bank transfer|gift card)\b",
    re.IGNORECASE,
)
URGENCY_LANGUAGE = re.compile(
    r"\b(urgent(?:ly)?|immediately|act now|within \d+ (?:hours?|days?)|final notice)\b",
    re.IGNORECASE,
)


class PaymentAnalyzer:
    def __init__(self, intelligence_client: PaymentIntelligenceClient | None = None) -> None:
        self._intelligence_client = intelligence_client

    @property
    def name(self) -> str:
        return "payment"

    async def analyze(self, context: UrlAnalysisContext) -> list[EvidenceItem]:
        soup = BeautifulSoup(context.html or "", "html.parser")
        base_url = context.final_url or context.normalized_url or context.submitted_url
        page_host = urlparse(base_url).hostname
        text = soup.get_text(" ", strip=True)
        wallets = self._wallets(text)
        payment_domains = self._payment_domains(soup, base_url)
        payment_methods = self._payment_methods(text, wallets, payment_domains)
        merchant_identity = self._merchant_identity(soup, page_host)
        destinations = self._destinations(wallets, payment_domains)
        identity_match = self._identity_destination_match(page_host, payment_domains)
        urgency_detected = bool(URGENCY_LANGUAGE.search(text))
        intelligence = await self._wallet_intelligence(wallets)
        suspicious_indicators = self._suspicious_indicators(
            wallets=wallets,
            payment_domains=payment_domains,
            identity_match=identity_match,
            urgency_detected=urgency_detected,
        )
        severity = self._severity(wallets, payment_methods, suspicious_indicators)

        primary_destination = destinations[0] if destinations else None
        primary_wallet = wallets[0]["address"] if wallets else None
        primary_domain = payment_domains[0] if payment_domains else None
        reputation_status = "not_available" if self._intelligence_client is None else "unknown"
        if intelligence and all(entry["status"] == "not_available" for entry in intelligence):
            reputation_status = "not_available"

        return [
            EvidenceItem(
                source=self.name,
                category=EvidenceCategory.TECHNICAL,
                severity=severity,
                title=(
                    "Payment destinations inspected"
                    if payment_methods
                    else "No payment indicators detected"
                ),
                description=(
                    "Payment-related content was inspected for destinations, wallet addresses, "
                    "identity mismatch, and urgency signals."
                ),
                data={
                    "payment_method": payment_methods or ["not_detected"],
                    "payment_destination": primary_destination,
                    "payment_destinations": destinations,
                    "destination_type": primary_destination["destination_type"]
                    if primary_destination
                    else "not_detected",
                    "destination_domain": primary_domain,
                    "wallet_address": primary_wallet,
                    "external_payment_domain": primary_domain,
                    "merchant_identity": merchant_identity,
                    "identity_destination_match": identity_match,
                    "reputation_status": reputation_status,
                    "wallet_intelligence": intelligence,
                    "suspicious_indicators": suspicious_indicators,
                    "confidence": self._confidence(payment_methods, destinations),
                },
            )
        ]

    def _wallets(self, text: str) -> list[dict[str, str]]:
        wallets: list[dict[str, str]] = []
        seen: set[str] = set()
        for network, pattern in WALLET_PATTERNS.items():
            for address in pattern.findall(text):
                if address not in seen:
                    wallets.append({"network": network, "address": address})
                    seen.add(address)
        return wallets[:20]

    def _payment_domains(self, soup: BeautifulSoup, base_url: str) -> list[str]:
        domains: list[str] = []
        for tag in [*soup.find_all("a"), *soup.find_all("form")]:
            raw_target = str(tag.get("href") or tag.get("action") or "").strip()
            if not raw_target:
                continue
            hostname = urlparse(urljoin(base_url, raw_target)).hostname
            if hostname and self._is_payment_provider(hostname) and hostname not in domains:
                domains.append(hostname)
        return domains[:20]

    def _payment_methods(
        self,
        text: str,
        wallets: list[dict[str, str]],
        payment_domains: list[str],
    ) -> list[str]:
        methods: list[str] = []
        if wallets or re.search(r"\b(crypto|bitcoin|ethereum|wallet)\b", text, re.IGNORECASE):
            methods.append("cryptocurrency")
        if payment_domains:
            methods.append("external_payment_provider")
        if re.search(r"\b(wire transfer|bank transfer)\b", text, re.IGNORECASE):
            methods.append("bank_transfer")
        if re.search(r"\bgift card\b", text, re.IGNORECASE):
            methods.append("gift_card")
        return methods

    def _merchant_identity(self, soup: BeautifulSoup, page_host: str | None) -> str | None:
        for attribute, value in (("property", "og:site_name"), ("name", "application-name")):
            tag = soup.find("meta", attrs={attribute: value})
            content = tag.get("content") if tag else None
            if content:
                return str(content).strip()
        if soup.title and soup.title.string:
            return soup.title.string.strip()
        return page_host

    def _destinations(
        self,
        wallets: list[dict[str, str]],
        payment_domains: list[str],
    ) -> list[dict[str, str]]:
        destinations = [
            {
                "destination_type": "wallet",
                "destination": wallet["address"],
                "network": wallet["network"],
            }
            for wallet in wallets
        ]
        destinations.extend(
            {
                "destination_type": "payment_provider_domain",
                "destination": domain,
                "network": "not_applicable",
            }
            for domain in payment_domains
        )
        return destinations[:20]

    def _identity_destination_match(
        self,
        page_host: str | None,
        payment_domains: list[str],
    ) -> str:
        if not payment_domains:
            return "unknown"
        if page_host and all(domain == page_host or domain.endswith(f".{page_host}") for domain in payment_domains):
            return "match"
        if all(self._is_payment_provider(domain) for domain in payment_domains):
            return "unknown"
        return "mismatch"

    def _suspicious_indicators(
        self,
        *,
        wallets: list[dict[str, str]],
        payment_domains: list[str],
        identity_match: str,
        urgency_detected: bool,
    ) -> list[str]:
        indicators: list[str] = []
        if wallets:
            indicators.append("cryptocurrency_wallet_present")
        if identity_match == "mismatch":
            indicators.append("payment_destination_identity_mismatch")
        if urgency_detected and (wallets or payment_domains):
            indicators.append("urgent_payment_language")
        return indicators

    def _severity(
        self,
        wallets: list[dict[str, str]],
        payment_methods: list[str],
        indicators: list[str],
    ) -> EvidenceSeverity:
        if wallets and len(indicators) > 1:
            return EvidenceSeverity.HIGH
        if "payment_destination_identity_mismatch" in indicators or "urgent_payment_language" in indicators:
            return EvidenceSeverity.MEDIUM
        if payment_methods:
            return EvidenceSeverity.LOW
        return EvidenceSeverity.INFO

    def _confidence(
        self,
        payment_methods: list[str],
        destinations: list[dict[str, str]],
    ) -> float:
        if destinations:
            return 0.9
        if payment_methods:
            return 0.65
        return 0.2

    def _wallet_intelligence(self, wallets: list[dict[str, str]]) -> list[dict[str, Any]]:
        if self._intelligence_client is None:
            return [
                {
                    "wallet_address": wallet["address"],
                    "network": wallet["network"],
                    "status": "not_available",
                }
                for wallet in wallets
            ]
        return []

    def _is_payment_provider(self, hostname: str) -> bool:
        return any(
            hostname == provider or hostname.endswith(f".{provider}")
            for provider in PAYMENT_PROVIDER_DOMAINS
        )
