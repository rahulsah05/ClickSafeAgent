import pytest

from clicksafe.application.errors import UrlValidationError
from clicksafe.application.services.url_validation import UrlValidationService


def test_normalizes_https_url() -> None:
    service = UrlValidationService()

    result = service.normalize("HTTPS://Example.COM:443/login#section")

    assert result.normalized == "https://example.com/login"
    assert result.hostname == "example.com"


def test_adds_https_to_bare_domain() -> None:
    service = UrlValidationService()

    result = service.normalize("example.com/path")

    assert result.normalized == "https://example.com/path"


def test_rejects_non_http_scheme() -> None:
    service = UrlValidationService()

    with pytest.raises(UrlValidationError, match="Only HTTP and HTTPS"):
        service.normalize("ftp://example.com")


def test_rejects_embedded_credentials() -> None:
    service = UrlValidationService()

    with pytest.raises(UrlValidationError, match="embedded credentials"):
        service.normalize("https://user:pass@example.com")
