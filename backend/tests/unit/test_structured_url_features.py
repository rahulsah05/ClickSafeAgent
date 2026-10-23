"""Feature extraction used by the synthetic dataset and by later prediction."""

from __future__ import annotations

import csv
import importlib.util
import sys
from collections import Counter
from pathlib import Path

import pytest

from clicksafe.infrastructure.ml.structured_url_features import (
    DATASET_FEATURE_COLUMNS,
    GENERATOR_ONLY_TAGS,
    IDENTITY_COLUMNS,
    METADATA_COLUMNS,
    MODEL_FEATURE_COLUMNS,
    BrandRecord,
    dataset_path,
    default_brand_catalog,
    edit_distance,
    encode_label,
    extract_url_features,
    freeze_feature,
    is_adjacent_transposition,
    is_single_deletion,
    is_single_insertion,
    measure,
    model_feature_record,
    nn_imitates_m,
    normalize_url,
    parse_public_url,
    parse_url,
    rn_imitates_m,
    substitution_counts,
)

PAYPAL = BrandRecord("PayPal", "paypal", "banking_and_payments", ("paypal.com",))
GOOGLE = BrandRecord("Google", "google", "search_and_technology", ("google.com",))
ROOT = Path(__file__).resolve().parents[3]


def _brand(token: str) -> BrandRecord:
    for brand in default_brand_catalog():
        if brand.token == token:
            return brand
    raise AssertionError(f"Missing brand token {token}")


def test_schema_keeps_metadata_out_of_model_features() -> None:
    assert set(METADATA_COLUMNS).isdisjoint(MODEL_FEATURE_COLUMNS)
    assert set(DATASET_FEATURE_COLUMNS).issubset(MODEL_FEATURE_COLUMNS)
    assert "rn_for_m_indicator" in MODEL_FEATURE_COLUMNS
    assert "rn_for_m_indicator" not in DATASET_FEATURE_COLUMNS
    assert "label" not in MODEL_FEATURE_COLUMNS


def test_catalog_has_diverse_brands() -> None:
    catalog = default_brand_catalog()
    categories = {brand.category for brand in catalog}

    assert len(catalog) >= 100
    assert len(categories) >= 10
    assert len({brand.token for brand in catalog}) == len(catalog)


def test_numeric_substitutions_are_counted_by_letter() -> None:
    paypal = extract_url_features("https://paypa1.example/home", brand=_brand("paypal"))
    google = extract_url_features("https://g00gle.test/home", brand=GOOGLE)
    ebay = extract_url_features("https://38ay.example/claim", brand=_brand("ebay"))
    linkedin = extract_url_features("https://l1nkedin.test/in", brand=_brand("linkedin"))
    instagram = extract_url_features("https://in5tagram.test/", brand=_brand("instagram"))

    assert paypal.features["one_for_l_or_i_count"] == 1
    assert paypal.features["character_substitution_count"] == 1
    assert google.features["zero_for_o_count"] == 2
    assert google.features["character_substitution_count"] == 2
    assert google.features["character_insertion_indicator"] == 0
    assert ebay.features["three_for_e_count"] == 1
    assert ebay.features["character_substitution_count"] == 2
    assert linkedin.features["one_for_l_or_i_count"] == 1
    assert instagram.features["five_for_s_count"] == 1


def test_double_n_imitates_m_only_when_the_pair_rebuilds_the_brand() -> None:
    assert nn_imitates_m("instagrann", "instagram") is True
    assert is_single_insertion("instagrann", "instagram") is False
    assert nn_imitates_m("cnn", "cnn") is False
    assert nn_imitates_m("annual", "amazon") is False
    assert rn_imitates_m("arnazon", "amazon") is True
    assert nn_imitates_m("arnazon", "amazon") is False

    instagram = extract_url_features("https://instagrann.example/item", brand=_brand("instagram"))
    cnn = extract_url_features("https://www.cnn.test/videos", brand=_brand("cnn"))
    amazon = extract_url_features("https://arnazon.test/home", brand=_brand("amazon"))

    assert instagram.features["double_n_for_m_indicator"] == 1
    assert instagram.features["character_insertion_indicator"] == 0
    assert cnn.features["double_n_for_m_indicator"] == 0
    assert amazon.features["rn_for_m_indicator"] == 1
    assert amazon.features["double_n_for_m_indicator"] == 0


def test_insertion_deletion_transposition_and_repeats() -> None:
    assert is_single_insertion("payypal", "paypal") is True
    assert is_single_deletion("paypl", "paypal") is True
    assert is_adjacent_transposition("ogogle", "google") is True
    assert edit_distance("google", "g00gle") == 2

    repeated = extract_url_features("https://www.google.test/", brand=GOOGLE)
    inserted = extract_url_features("https://payypal.test/home", brand=PAYPAL)
    deleted = extract_url_features("https://paypl.test/home", brand=PAYPAL)
    swapped = extract_url_features("https://ogogle.test/home", brand=GOOGLE)

    assert repeated.features["repeated_character_count"] == 3
    assert inserted.features["character_insertion_indicator"] == 1
    assert deleted.features["character_deletion_indicator"] == 1
    assert swapped.features["character_transposition_indicator"] == 1
    assert swapped.features["character_substitution_count"] == 0


def test_unicode_homoglyph_and_punycode_share_a_normalized_host() -> None:
    unicode_host = "g\u043eogle"
    unicode_url = f"https://{unicode_host}.test/login"
    punycode_url = f"https://{encode_label(unicode_host)}.test/login"
    assert encode_label("g\u043e\u043egle") == "xn--ggle-55da"

    raw = extract_url_features(unicode_url, brand=GOOGLE)
    encoded = extract_url_features(punycode_url, brand=GOOGLE)

    assert normalize_url(unicode_url) == normalize_url(punycode_url)
    assert raw.features["homoglyph_indicator"] == 1
    assert raw.features["mixed_script_indicator"] == 1
    assert raw.features["punycode_indicator"] == 0
    assert raw.features["special_character_count"] >= 1
    assert encoded.features["punycode_indicator"] == 1
    assert encoded.features["homoglyph_indicator"] == 1
    assert encoded.features["hyphen_count"] >= 2
    assert raw.normalized_url == encoded.normalized_url


def test_unlisted_confusable_is_not_called_a_homoglyph() -> None:
    mixed = extract_url_features("https://g\u03bfogle.test/", brand=GOOGLE)

    assert mixed.features["homoglyph_indicator"] == 0
    assert mixed.features["mixed_script_indicator"] == 1


def test_misleading_subdomain_differs_from_a_real_registrable_brand() -> None:
    owned = extract_url_features("https://login.paypal.test/account/settings", brand=PAYPAL)
    parked = extract_url_features("https://paypal.news.test/home", brand=PAYPAL)

    assert owned.features["suspicious_keyword_count"] >= 2
    assert owned.features["misleading_domain_structure"] == 0
    assert owned.features["brand_in_subdomain"] == 0
    assert owned.features["brand_similarity_score"] == 1
    assert parked.features["brand_in_subdomain"] == 1
    assert parked.features["misleading_domain_structure"] == 1
    assert parked.match_reason == "supplied"


def test_keyword_host_does_not_select_a_one_edit_brand() -> None:
    features = extract_url_features("http://password.otp-wallet.test/session/37120")

    assert features.brand_name is None
    assert features.features["suspicious_keyword_count"] >= 2
    assert features.features["character_deletion_indicator"] is None


def test_legitimate_keyword_url_keeps_an_exact_brand() -> None:
    features = extract_url_features("https://accounts.google.com/signin")

    assert features.parse_error is None
    assert features.registrable_domain == "google.com"
    assert features.suffix == "com"
    assert features.registrable_label == "google"
    assert features.brand_name == "Google"
    assert features.match_reason == "exact"
    assert features.features["misleading_domain_structure"] == 0
    assert features.features["suspicious_keyword_count"] >= 1
    assert "label" not in features.features


def test_public_suffix_keeps_multi_part_and_private_suffixes() -> None:
    uk = extract_url_features("https://www.google.co.uk/search")
    blog = extract_url_features("https://evilpaypal.blogspot.com/login")
    reserved = parse_public_url("https://a.b.paypal.test/path")

    assert uk.registrable_domain == "google.co.uk"
    assert uk.suffix == "co.uk"
    assert uk.features["subdomain_count"] == 1
    assert uk.brand_name == "Google"
    assert blog.registrable_domain == "evilpaypal.blogspot.com"
    assert blog.suffix == "blogspot.com"
    assert blog.brand_name is None
    assert reserved.registrable_domain == "paypal.test"
    assert reserved.subdomain_labels == ("a", "b")
    assert reserved.suffix == "test"


def test_third_party_mention_selects_the_path_brand() -> None:
    features = extract_url_features("https://classroom.localhost/guide/uber?topic=uber")

    assert features.brand_token == "uber"
    assert features.match_reason == "exact"
    assert features.match_source == "path"
    assert features.features["edit_distance"] == 0
    assert features.features["brand_in_subdomain"] == 0


def test_short_token_matches_only_when_exact() -> None:
    exact = extract_url_features("https://aa.test/tickets")
    nearby = extract_url_features("https://ab.test/tickets")

    assert exact.brand_token == "aa"
    assert nearby.brand_name is None


def test_extraction_is_deterministic_and_keeps_normalization_separate() -> None:
    original = "  https://PayPal.test:443/Login/#frag  "
    left = extract_url_features(original)
    again = extract_url_features(original)
    normalized = extract_url_features("https://paypal.test/Login")

    assert left == again
    assert left.original_url == original.strip()
    assert left.normalized_url == normalized.normalized_url
    assert left.normalized_url == normalize_url("https://paypal.test/Login")
    assert left.features["url_length"] == len(original.strip())
    assert left.features["digit_count"] == 3
    assert normalized.features["url_length"] == len("https://paypal.test/Login")
    assert left.brand_name == normalized.brand_name == "PayPal"
    assert model_feature_record(left) == left.features


def test_malformed_urls_do_not_raise() -> None:
    cases = {
        "": "empty",
        "   ": "empty",
        "not a url": "unusable_url",
        "http://": "unusable_url",
        "ftp://paypal.test/login": "unusable_url",
        "https://paypal..test/": "empty_label",
    }

    for url, code in cases.items():
        features = extract_url_features(url)
        assert features.parse_error == code
        assert features.brand_name is None
        assert features.features["character_substitution_count"] is None
        assert features.features["url_length"] == len(url.strip())

    assert extract_url_features(None).parse_error == "not_a_string"  # type: ignore[arg-type]
    broken = extract_url_features("https://xn--.test/login")
    assert broken.parse_error is None
    assert broken.features["punycode_indicator"] == 1


def test_ip_url_keeps_keyword_counts() -> None:
    features = extract_url_features("https://127.0.0.1/login")

    assert features.parse_error is None
    assert features.registrable_domain == "127.0.0.1"
    assert features.features["suspicious_keyword_count"] == 1
    assert features.features["digit_count"] == 6


def test_generator_calls_this_module() -> None:
    script = ROOT / "scripts" / "generate_synthetic_dataset.py"
    spec = importlib.util.spec_from_file_location("clicksafe_dataset_generator", script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)

    assert module.measure is measure
    assert module.parse_url is parse_url
    assert module.normalize_url is normalize_url
    assert module.COLUMNS[0] == "record_id"
    assert "label" in module.METADATA_COLUMNS


def test_dataset_rows_match_shared_features_and_are_unique() -> None:
    path = dataset_path()
    assert path == ROOT / "ml_data" / "url_dataset.csv"
    catalog = {brand.brand_name: brand for brand in default_brand_catalog()}
    reference_domains = {
        domain for brand in catalog.values() for domain in brand.reference_domains
    }
    with path.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))

    assert len(rows) == 10000
    assert len({row["record_id"] for row in rows}) == 10000
    assert len({row["url"] for row in rows}) == 10000
    assert len({normalize_url(row["url"]) for row in rows}) == 10000
    assert Counter(row["label"] for row in rows) == {
        "legitimate": 4000,
        "suspicious": 3000,
        "malicious": 3000,
    }
    assert len({row["brand_name"] for row in rows if row["brand_name"]}) == len(catalog)
    assert sum(row["brand_name"] == "" for row in rows) == 1660

    collisions: list[tuple[str, str, str]] = []
    for row in rows:
        assert row["url"].count("None") == 0
        assert not any(domain in row["url"] for domain in reference_domains)
        reserved = parse_url(row["url"])
        public = parse_public_url(row["url"])
        assert reserved.suffix in {"test", "example", "invalid", "localhost"}
        assert public.registrable_domain == reserved.registrable_domain
        assert public.subdomain_labels == reserved.subdomain_labels
        brand = catalog.get(row["brand_name"]) if row["brand_name"] else None
        measured = measure(row["url"], brand, "audit", "audit", "audit")
        for column in IDENTITY_COLUMNS + DATASET_FEATURE_COLUMNS:
            assert freeze_feature(measured[column]) == row[column], (row["record_id"], column)
        csv_tags = {
            tag
            for tag in row["transformation_types"].split(";")
            if tag and tag not in GENERATOR_ONLY_TAGS and tag != "none"
        }
        got_tags = {
            tag
            for tag in str(measured["transformation_types"]).split(";")
            if tag and tag != "none"
        }
        assert csv_tags == got_tags
        selected = extract_url_features(row["url"])
        if (selected.brand_name or "") != row["brand_name"]:
            collisions.append(
                (row["generation_method"], row["brand_name"], selected.brand_name or "")
            )

    assert sorted(collisions) == [
        ("combined", "Notion", "Norton"),
        ("deletion_mild", "Notion", "Norton"),
    ]
    supplied = extract_url_features(
        "https://noton.invalid:4443/help-center/articles/82097?q=linen",
        brand=_brand("notion"),
    )
    assert supplied.features["character_deletion_indicator"] == 1
    assert supplied.brand_name == "Notion"


def test_substitution_helper_rejects_a_different_length() -> None:
    assert substitution_counts("payypal", "paypal")["total"] == 0


@pytest.mark.parametrize(
    ("url", "reason"),
    [
        ("https://du0lingo.example/item/56415", "digit_lookalike"),
        ("https://instagrann.example/home", "double_n_for_m"),
        ("https://payypal.test/home", "insertion"),
        ("https://paypl.test/home", "deletion"),
        ("https://ogogle.test/home", "transposition"),
        ("https://paypal.news.test/home", "exact"),
        ("https://paypal-login.example/", "exact"),
        ("https://paypal4821.example/home", "structural"),
    ],
)
def test_automatic_reasons(url: str, reason: str) -> None:
    assert extract_url_features(url).match_reason == reason
