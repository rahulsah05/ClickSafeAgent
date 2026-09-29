"""Local URL pre-scanner.

Extracts structural and lexical signals before the deep analysis pipeline.
Suspicious keywords are evidence only and never add risk points.
"""

import ipaddress
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import unquote, urlparse

import tldextract

# Keywords describe page intent. A legitimate site can contain any of them.
SUSPICIOUS_KEYWORDS = frozenset(
    {
        "account",
        "alert",
        "banking",
        "billing",
        "confirm",
        "credential",
        "credentials",
        "expire",
        "expired",
        "invoice",
        "limited",
        "login",
        "logon",
        "otp",
        "passwd",
        "password",
        "payment",
        "recover",
        "recovery",
        "secure",
        "security",
        "signin",
        "ssn",
        "support",
        "suspend",
        "suspended",
        "unlock",
        "update",
        "urgent",
        "verification",
        "verify",
        "wallet",
        "webscr",
    }
)
PHRASE_KEYWORDS = ("log-in", "log_in", "sign-in", "sign_in")
KEYWORD_SCORE_CONTRIBUTION = 0

BRAND_OFFICIAL_DOMAINS: dict[str, frozenset[str]] = {
    "adobe": frozenset({"adobe.com"}),
    "amazon": frozenset({"amazon.com", "amazonaws.com"}),
    "apple": frozenset({"apple.com", "icloud.com"}),
    "binance": frozenset({"binance.com"}),
    "chase": frozenset({"chase.com"}),
    "coinbase": frozenset({"coinbase.com"}),
    "dhl": frozenset({"dhl.com"}),
    "dropbox": frozenset({"dropbox.com"}),
    "facebook": frozenset({"facebook.com", "fb.com"}),
    "fedex": frozenset({"fedex.com"}),
    "github": frozenset({"github.com"}),
    "google": frozenset({"google.com", "gmail.com", "youtube.com", "youtu.be"}),
    "icloud": frozenset({"icloud.com", "apple.com"}),
    "instagram": frozenset({"instagram.com"}),
    "linkedin": frozenset({"linkedin.com", "lnkd.in"}),
    "microsoft": frozenset(
        {"microsoft.com", "live.com", "office.com", "outlook.com", "microsoftonline.com"}
    ),
    "netflix": frozenset({"netflix.com"}),
    "outlook": frozenset({"outlook.com", "live.com", "microsoft.com"}),
    "paypal": frozenset({"paypal.com"}),
    "roblox": frozenset({"roblox.com"}),
    "steam": frozenset({"steampowered.com", "steamcommunity.com"}),
    "telegram": frozenset({"telegram.org", "t.me"}),
    "wellsfargo": frozenset({"wellsfargo.com"}),
    "whatsapp": frozenset({"whatsapp.com"}),
}

SUSPICIOUS_TLDS = frozenset(
    {
        "bond",
        "buzz",
        "cam",
        "cfd",
        "cf",
        "click",
        "country",
        "cyou",
        "date",
        "download",
        "ga",
        "gdn",
        "gq",
        "icu",
        "loan",
        "men",
        "ml",
        "monster",
        "mov",
        "quest",
        "racing",
        "rest",
        "review",
        "sbs",
        "stream",
        "support",
        "tk",
        "top",
        "work",
        "xyz",
        "zip",
    }
)

URL_SHORTENERS = frozenset(
    {
        "adf.ly",
        "bit.do",
        "bit.ly",
        "buff.ly",
        "clck.ru",
        "cutt.ly",
        "db.tt",
        "goo.gl",
        "is.gd",
        "ity.im",
        "j.mp",
        "lnkd.in",
        "mcaf.ee",
        "ow.ly",
        "po.st",
        "rb.gy",
        "rebrand.ly",
        "rotf.lol",
        "s.id",
        "short.io",
        "shorturl.at",
        "t.co",
        "t.ly",
        "tiny.cc",
        "tinyurl.com",
        "v.gd",
        "youtu.be",
    }
)

ENCODED_CHARACTER_PATTERN = re.compile(r"%[0-9A-Fa-f]{2}")
TOKEN_PATTERN = re.compile(r"[a-z0-9]+")

FEATURE_KEYS = (
    "url_length",
    "domain_length",
    "path_length",
    "query_length",
    "subdomain_count",
    "dot_count",
    "hyphen_count",
    "digit_count",
    "special_character_count",
    "has_ip_address",
    "has_at_symbol",
    "has_encoded_characters",
    "has_punycode",
    "suspicious_tld",
    "is_url_shortener",
    "suspicious_keywords",
    "brand_tokens",
    "brand_domain_mismatch",
)


@dataclass(frozen=True, slots=True)
class UrlPreScanResult:
    risk_score: int
    risk_level: str
    features: dict[str, Any]
    suspicious_keywords: list[str]
    brand_matches: list[str]
    warnings: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "features": self.features,
            "suspicious_keywords": self.suspicious_keywords,
            "brand_matches": self.brand_matches,
            "warnings": self.warnings,
        }


class UrlPreScanner:
    """Reusable local URL risk analysis service.

    `scan` returns the structured assessment. It does not fetch the URL and it
    does not produce the ClickSafe verdict.
    """

    def scan(self, url: str) -> dict[str, Any]:
        candidate = url.strip()
        features = self.extract_features(candidate)
        keywords = list(features["suspicious_keywords"])
        brands = list(features["brand_tokens"])
        score, warnings = self._score(features)
        if keywords:
            warnings.append(
                "Suspicious keywords are evidence only and did not change the pre-scan "
                f"score: {', '.join(keywords)}."
            )
        bounded_score = max(0, min(score, 100))
        return UrlPreScanResult(
            risk_score=bounded_score,
            risk_level=self.risk_level(bounded_score),
            features=features,
            suspicious_keywords=keywords,
            brand_matches=brands,
            warnings=warnings,
        ).to_dict()

    def extract_features(self, url: str) -> dict[str, Any]:
        candidate = url.strip()
        parsed = self._parse(candidate)
        hostname = (parsed.hostname or "").rstrip(".").lower()
        extracted = tldextract.extract(hostname) if hostname else None
        registered_domain = self._registered_domain(extracted)
        keywords = self.detect_keywords(candidate)
        brand_tokens, brand_mismatch, mismatched_brands = self._brand_signals(
            candidate,
            extracted,
        )
        suffix = extracted.suffix.lower() if extracted is not None else ""
        hostname_tld = ""
        if hostname and not self._is_ip_address(hostname):
            hostname_tld = hostname.split(".")[-1]
        tld = suffix.split(".")[-1] if suffix else hostname_tld

        features: dict[str, Any] = {
            "url_length": len(candidate),
            "domain_length": len(hostname),
            "path_length": len(parsed.path),
            "query_length": len(parsed.query),
            "subdomain_count": self._subdomain_count(extracted),
            "dot_count": candidate.count("."),
            "hyphen_count": candidate.count("-"),
            "digit_count": sum(character.isdigit() for character in candidate),
            "special_character_count": sum(not character.isalnum() for character in candidate),
            "has_ip_address": self._is_ip_address(hostname),
            "has_at_symbol": "@" in candidate,
            "has_encoded_characters": ENCODED_CHARACTER_PATTERN.search(candidate) is not None,
            "has_punycode": "xn--" in hostname,
            "suspicious_tld": bool(tld) and (tld in SUSPICIOUS_TLDS or suffix in SUSPICIOUS_TLDS),
            "is_url_shortener": self._is_shortener(hostname, registered_domain),
            "suspicious_keywords": keywords,
            "brand_tokens": brand_tokens,
            "brand_domain_mismatch": brand_mismatch,
            "tld": tld or None,
            "registered_domain": registered_domain,
            "mismatched_brands": mismatched_brands,
            "keyword_score_contribution": KEYWORD_SCORE_CONTRIBUTION,
        }
        return features

    def detect_keywords(self, url: str) -> list[str]:
        decoded = unquote(url).lower()
        tokens = set(TOKEN_PATTERN.findall(decoded))
        found = {keyword for keyword in SUSPICIOUS_KEYWORDS if keyword in tokens}
        for phrase in PHRASE_KEYWORDS:
            if re.search(rf"(?<![a-z0-9]){re.escape(phrase)}(?![a-z0-9])", decoded):
                found.add(phrase)
        return sorted(found)

    def risk_level(self, risk_score: int) -> str:
        if risk_score >= 55:
            return "high"
        if risk_score >= 25:
            return "medium"
        return "low"

    def _score(self, features: dict[str, Any]) -> tuple[int, list[str]]:
        findings: list[tuple[int, str]] = []
        if features["has_ip_address"]:
            findings.append((30, "Hostname is an IP address."))
        if features["has_at_symbol"]:
            findings.append((30, "URL contains an @ symbol."))
        if features["has_punycode"]:
            findings.append((20, "Hostname uses Punycode."))
        if features["suspicious_tld"]:
            findings.append((15, f"Top-level domain '.{features['tld']}' is often abused."))
        if features["is_url_shortener"]:
            findings.append((15, "Domain is a known URL shortener."))
        if features["has_encoded_characters"]:
            findings.append((10, "URL contains percent-encoded characters."))
        mismatched_brands = features["mismatched_brands"]
        if mismatched_brands:
            quoted_brands = ", ".join(f"'{brand}'" for brand in mismatched_brands)
            brand_label = "Brand token" if len(mismatched_brands) == 1 else "Brand tokens"
            findings.append(
                (
                    25,
                    f"{brand_label} {quoted_brands} "
                    f"{'does' if len(mismatched_brands) == 1 else 'do'} not match "
                    f"registered domain '{features['registered_domain'] or 'unknown'}'.",
                )
            )
        if features["url_length"] >= 150:
            findings.append((8, f"URL length is {features['url_length']} characters."))
        if features["domain_length"] >= 50:
            findings.append((8, f"Domain length is {features['domain_length']} characters."))
        if features["subdomain_count"] >= 4:
            findings.append((10, f"Hostname has {features['subdomain_count']} subdomains."))
        if features["dot_count"] >= 7:
            findings.append((6, f"URL contains {features['dot_count']} dots."))
        if features["hyphen_count"] >= 5:
            findings.append((6, f"URL contains {features['hyphen_count']} hyphens."))
        if features["digit_count"] >= 15:
            findings.append((6, f"URL contains {features['digit_count']} digits."))
        if features["special_character_count"] >= 20:
            findings.append(
                (6, f"URL contains {features['special_character_count']} special characters.")
            )

        # Keyword matches are already stored on the result. They add no points.
        score = sum(points for points, _warning in findings) + KEYWORD_SCORE_CONTRIBUTION
        warnings = [warning for _points, warning in findings]
        return score, warnings

    def _brand_signals(
        self,
        url: str,
        extracted: Any,
    ) -> tuple[list[str], bool, list[str]]:
        tokens = set(TOKEN_PATTERN.findall(unquote(url).lower()))
        matched = sorted(brand for brand in BRAND_OFFICIAL_DOMAINS if brand in tokens)
        mismatched = [
            brand
            for brand in matched
            if not self._brand_is_aligned(brand, extracted, BRAND_OFFICIAL_DOMAINS[brand])
        ]
        return matched, bool(mismatched), mismatched

    def _brand_is_aligned(
        self,
        brand: str,
        extracted: Any,
        official_domains: frozenset[str],
    ) -> bool:
        if extracted is None or not extracted.domain:
            return False
        registered_domain = self._registered_domain(extracted)
        if registered_domain in official_domains:
            return True
        if extracted.domain == brand:
            return True
        official_labels = {domain.split(".", maxsplit=1)[0] for domain in official_domains}
        return extracted.domain in official_labels

    def _parse(self, url: str) -> Any:
        parsed = urlparse(url)
        if parsed.scheme and parsed.netloc:
            return parsed
        return urlparse(f"https://{url}")

    def _subdomain_count(self, extracted: Any) -> int:
        if extracted is None or not extracted.subdomain:
            return 0
        return len([label for label in extracted.subdomain.split(".") if label])

    def _registered_domain(self, extracted: Any) -> str | None:
        if extracted is None or not extracted.domain:
            return None
        if not extracted.suffix:
            return str(extracted.domain)
        return f"{extracted.domain}.{extracted.suffix}"

    def _is_ip_address(self, hostname: str) -> bool:
        if not hostname:
            return False
        try:
            ipaddress.ip_address(hostname.strip("[]"))
        except ValueError:
            return False
        return True

    def _is_shortener(self, hostname: str, registered_domain: str | None) -> bool:
        candidates = {hostname}
        if registered_domain is not None:
            candidates.add(registered_domain)
        return any(candidate in URL_SHORTENERS for candidate in candidates if candidate)
