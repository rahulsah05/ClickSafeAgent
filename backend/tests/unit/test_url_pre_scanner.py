import pytest

from clicksafe.application.services.url_pre_scanner import FEATURE_KEYS, UrlPreScanner


@pytest.fixture
def scanner() -> UrlPreScanner:
    return UrlPreScanner()


def test_extracts_structural_features(scanner: UrlPreScanner) -> None:
    url = "https://a.b.example.com/path-1/item?q=22"

    features = scanner.extract_features(url)

    assert set(FEATURE_KEYS).issubset(features)
    assert features["url_length"] == len(url)
    assert features["domain_length"] == len("a.b.example.com")
    assert features["path_length"] == len("/path-1/item")
    assert features["query_length"] == len("q=22")
    assert features["subdomain_count"] == 2
    assert features["dot_count"] == url.count(".")
    assert features["hyphen_count"] == url.count("-")
    assert features["digit_count"] == sum(character.isdigit() for character in url)
    assert features["special_character_count"] == sum(
        not character.isalnum() for character in url
    )
    assert features["has_ip_address"] is False
    assert features["has_at_symbol"] is False
    assert features["has_encoded_characters"] is False
    assert features["has_punycode"] is False
    assert features["suspicious_tld"] is False
    assert features["is_url_shortener"] is False
    assert features["brand_domain_mismatch"] is False
    assert features["keyword_score_contribution"] == 0


def test_detects_deceptive_structural_signals(scanner: UrlPreScanner) -> None:
    ip_features = scanner.extract_features("https://192.0.2.10/login")
    at_features = scanner.extract_features("https://user@example.com/")
    encoded_features = scanner.extract_features("https://example.com/%6Cogin")
    punycode_features = scanner.extract_features("https://xn--pple-43d.com/")
    tld_features = scanner.extract_features("https://example.zip/welcome")
    shortener_features = scanner.extract_features("https://bit.ly/abc")

    assert ip_features["has_ip_address"] is True
    assert at_features["has_at_symbol"] is True
    assert encoded_features["has_encoded_characters"] is True
    assert punycode_features["has_punycode"] is True
    assert tld_features["suspicious_tld"] is True
    assert tld_features["tld"] == "zip"
    assert shortener_features["is_url_shortener"] is True


def test_detects_keywords_without_scoring_them(scanner: UrlPreScanner) -> None:
    plain_url = "https://example.com/welcome"
    keyword_url = "https://example.com/login/account/secure/payment"

    keywords = scanner.detect_keywords(keyword_url)
    plain = scanner.scan(plain_url)
    keyworded = scanner.scan(keyword_url)

    assert keywords == ["account", "login", "payment", "secure"]
    assert keyworded["suspicious_keywords"] == keywords
    assert keyworded["features"]["suspicious_keywords"] == keywords
    assert keyworded["risk_score"] == plain["risk_score"] == 0
    assert keyworded["risk_level"] == "low"
    assert keyworded["features"]["keyword_score_contribution"] == 0
    assert any("evidence only" in warning for warning in keyworded["warnings"])


def test_detects_hyphenated_sign_in_phrase(scanner: UrlPreScanner) -> None:
    assert "sign-in" in scanner.detect_keywords("https://example.com/sign-in")


def test_decodes_keywords_but_scores_only_the_encoding(scanner: UrlPreScanner) -> None:
    result = scanner.scan("https://example.com/%6Cogin")

    assert result["suspicious_keywords"] == ["login"]
    assert result["features"]["has_encoded_characters"] is True
    assert result["risk_score"] == 10
    assert result["risk_level"] == "low"


def test_brand_on_its_own_domain_is_not_a_mismatch(scanner: UrlPreScanner) -> None:
    result = scanner.scan("https://www.paypal.com/login")

    assert result["brand_matches"] == ["paypal"]
    assert result["features"]["brand_domain_mismatch"] is False
    assert result["suspicious_keywords"] == ["login"]
    assert result["risk_score"] == 0
    assert result["risk_level"] == "low"


def test_brand_domain_mismatch_is_medium_and_not_a_keyword_verdict(
    scanner: UrlPreScanner,
) -> None:
    keyword_only = scanner.scan("https://shop.example.com/login")
    mismatched = scanner.scan("https://paypal.example.com/login")

    assert keyword_only["risk_score"] == 0
    assert mismatched["brand_matches"] == ["paypal"]
    assert mismatched["features"]["brand_domain_mismatch"] is True
    assert mismatched["risk_score"] == 25
    assert mismatched["risk_level"] == "medium"
    assert mismatched["risk_level"] != "high"


def test_combined_structural_signals_can_reach_high(scanner: UrlPreScanner) -> None:
    result = scanner.scan("http://user@192.0.2.10/")

    assert result["features"]["has_ip_address"] is True
    assert result["features"]["has_at_symbol"] is True
    assert result["suspicious_keywords"] == []
    assert result["risk_score"] == 60
    assert result["risk_level"] == "high"


def test_scan_result_shape(scanner: UrlPreScanner) -> None:
    result = scanner.scan("https://example.com")

    assert set(result) == {
        "risk_score",
        "risk_level",
        "features",
        "suspicious_keywords",
        "brand_matches",
        "warnings",
    }
    assert result["risk_score"] == 0
    assert result["risk_level"] == "low"
    assert result["suspicious_keywords"] == []
    assert result["brand_matches"] == []
    assert result["warnings"] == []
