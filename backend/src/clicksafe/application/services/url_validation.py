from dataclasses import dataclass
from urllib.parse import ParseResult, quote, unquote, urlparse, urlunparse

from clicksafe.application.errors import UrlValidationError

ALLOWED_SCHEMES = {"http", "https"}
DEFAULT_PORTS = {"http": 80, "https": 443}


@dataclass(frozen=True, slots=True)
class NormalizedUrl:
    original: str
    normalized: str
    scheme: str
    hostname: str
    port: int | None


class UrlValidationService:
    def normalize(self, raw_url: str) -> NormalizedUrl:
        candidate = raw_url.strip()
        if not candidate:
            raise UrlValidationError("URL is required.")

        parsed = urlparse(candidate)
        if not parsed.scheme:
            candidate = f"https://{candidate}"
            parsed = urlparse(candidate)

        scheme = parsed.scheme.lower()
        if scheme not in ALLOWED_SCHEMES:
            raise UrlValidationError("Only HTTP and HTTPS URLs can be analyzed.")

        if not parsed.hostname:
            raise UrlValidationError("URL must include a hostname.")

        if parsed.username or parsed.password:
            raise UrlValidationError("URLs with embedded credentials are not supported.")

        hostname = self._normalize_hostname(parsed.hostname)
        port = self._normalize_port(parsed)
        netloc = hostname if port is None else f"{hostname}:{port}"

        path = quote(unquote(parsed.path or "/"), safe="/:@")
        query = quote(unquote(parsed.query), safe="=&?/:;+,%@")

        normalized = urlunparse((scheme, netloc, path, "", query, ""))
        return NormalizedUrl(
            original=raw_url,
            normalized=normalized,
            scheme=scheme,
            hostname=hostname,
            port=port,
        )

    def _normalize_hostname(self, hostname: str) -> str:
        try:
            return hostname.rstrip(".").encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise UrlValidationError("URL hostname is not valid IDNA.") from exc

    def _normalize_port(self, parsed: ParseResult) -> int | None:
        try:
            port = parsed.port
        except ValueError as exc:
            raise UrlValidationError("URL port is invalid.") from exc

        if port is None or DEFAULT_PORTS.get(parsed.scheme.lower()) == port:
            return None
        return port
