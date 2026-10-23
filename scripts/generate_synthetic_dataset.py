"""Generate a synthetic URL dataset for ClickSafe brand-impersonation experiments.

The generator does not resolve DNS names and does not open the URLs it writes.
Every hostname uses an RFC 2606 reserved suffix: .test, .example, .invalid, or
.localhost. Reference domains from the brand list are metadata and are never
copied into a URL.

Feature measurements are imported from
clicksafe.infrastructure.ml.structured_url_features. That is the same module
a later training or prediction call uses.

Run from the repository root:

    backend\\venv\\Scripts\\python.exe scripts\\generate_synthetic_dataset.py

Default output is ml_data/url_dataset.csv. The data/ directory is
gitignored in this repository, so the dataset lives under ml_data/.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import random
import re
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
from urllib.parse import unquote, urlsplit, urlunsplit

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
BACKEND_SRC = REPO_ROOT / "backend" / "src"
for import_path in (SCRIPT_DIR, BACKEND_SRC):
    if str(import_path) not in sys.path:
        sys.path.insert(0, str(import_path))

from brand_reference import BRAND_ROWS, CATEGORIES  # noqa: E402
from clicksafe.infrastructure.ml.structured_url_features import (  # noqa: E402
    COLUMNS,
    CONFUSABLES,
    EXTRA_DIGITS,
    METADATA_COLUMNS,
    MIN_IMPERSONATION_LENGTH,
    PRIMARY_DIGITS,
    RESERVED_SUFFIXES,
    SUSPICIOUS_KEYWORDS,
    TOKEN_RE,
    ParsedUrl,
    edit_distance,
    encode_label,
    host_components,
    is_adjacent_transposition,
    is_single_deletion,
    is_single_insertion,
    measure,
    nn_imitates_m,
    normalize_url,
    parse_url,
    substitution_counts,
)

GENERATOR_VERSION = "1.0.0"
DEFAULT_SEED = 20261015
DEFAULT_ROWS = 10000
BRAND_USAGE_CAP = 160

LURE_KEYWORDS = (
    "login",
    "verify",
    "account",
    "secure",
    "update",
    "wallet",
    "claim",
    "password",
    "confirm",
    "billing",
    "invoice",
    "unlock",
    "reset",
    "otp",
    "suspend",
    "payment",
    "signin",
    "support",
)

# Top-level scenario sizes for the default 10,000-row dataset.
BASE_QUOTAS = {
    "legit_brand_service": 1600,
    "legit_third_party": 1200,
    "legit_generic_noisy": 1000,
    "legit_innocent_nn": 200,
    "keyword_odd_structure": 400,
    "numeric_mild": 500,
    "double_n_mild": 200,
    "rn_for_m_mild": 120,
    "repeat_mild": 200,
    "insertion_mild": 280,
    "deletion_mild": 280,
    "transposition_mild": 220,
    "unicode_mild": 250,
    "brand_subdomain_neutral": 300,
    "hyphen_or_digit_label": 150,
    "excessive_odd_structure": 100,
    "numeric_strong": 450,
    "double_n_strong": 220,
    "spelling_strong": 400,
    "unicode_strong": 320,
    "punycode_strong": 280,
    "structure_lure": 480,
    "combined": 850,
}

SAFE_WORD_CANDIDATES = (
    "amber",
    "audio",
    "books",
    "cedar",
    "copper",
    "garden",
    "kite",
    "linen",
    "maple",
    "music",
    "north",
    "orchard",
    "pebble",
    "photos",
    "plaza",
    "quartz",
    "river",
    "shoes",
    "silver",
)
PUBLISHER_CANDIDATES = (
    "archive",
    "bulletin",
    "campus",
    "catalog",
    "classroom",
    "digest",
    "gallery",
    "gazette",
    "handbook",
    "herald",
    "journal",
    "library",
    "museum",
    "newsletter",
    "observatory",
    "podcast",
    "reporter",
    "reviews",
    "wire",
)
GENERIC_HOST_CANDIDATES = (
    "calendar",
    "dataset",
    "fileserver",
    "intranet",
    "inventory",
    "kitchen",
    "manual",
    "metrics",
    "notebook",
    "parcel",
    "portal",
    "recipes",
    "reservations",
    "schedule",
    "tickets",
    "toolbox",
    "transit",
    "weather",
    "whiteboard",
)
NEUTRAL_DECOY_CANDIDATES = (
    "center",
    "club",
    "daily",
    "forum",
    "group",
    "guide",
    "home",
    "mail",
    "page",
    "photo",
    "portal",
    "service",
    "shop",
    "site",
    "store",
    "team",
    "video",
    "web",
    "world",
)
NN_WORDS = (
    "annual",
    "banner",
    "channel",
    "connect",
    "funny",
    "inner",
    "planning",
    "running",
    "tennis",
    "winner",
)
DEEP_PREFIXES = ("img", "static", "cdn", "media")
EXCESSIVE_PREFIXES = ("edge", "node", "region", "cache")
SERVICE_LABELS = ("accounts", "api", "app", "docs", "help", "id", "mail", "my", "pay", "store", "www")


@dataclass(frozen=True, slots=True)
class Brand:
    brand_name: str
    token: str
    category: str
    reference_domains: tuple[str, ...]
    allow_impersonation: bool

    @property
    def reference_domain(self) -> str:
        return "|".join(self.reference_domains)


def load_brands() -> list[Brand]:
    brands: list[Brand] = []
    seen_names: set[str] = set()
    seen_tokens: set[str] = set()
    for brand_name, token, category, domains in BRAND_ROWS:
        if brand_name in seen_names:
            raise ValueError(f"Duplicate brand name: {brand_name}")
        if token in seen_tokens:
            raise ValueError(f"Duplicate brand token: {token}")
        if category not in CATEGORIES:
            raise ValueError(f"Unknown category for {brand_name}: {category}")
        if token != token.casefold() or not token.isalnum() or not token.isascii():
            raise ValueError(f"Token must be lowercase ASCII alphanumerics: {token}")
        if len(domains) < 1:
            raise ValueError(f"Missing reference domain for {brand_name}")
        cleaned: list[str] = []
        for domain in domains:
            if domain != domain.casefold() or "." not in domain:
                raise ValueError(f"Bad reference domain for {brand_name}: {domain}")
            if not re.fullmatch(r"[a-z0-9.-]+", domain):
                raise ValueError(f"Bad reference domain for {brand_name}: {domain}")
            if domain.split(".")[-1] in RESERVED_SUFFIXES:
                raise ValueError(f"Reference domain uses a reserved suffix: {domain}")
            cleaned.append(domain)
        seen_names.add(brand_name)
        seen_tokens.add(token)
        brands.append(
            Brand(
                brand_name=brand_name,
                token=token,
                category=category,
                reference_domains=tuple(cleaned),
                allow_impersonation=len(token) >= MIN_IMPERSONATION_LENGTH,
            )
        )
    if len(brands) < 100:
        raise ValueError(f"Brand list has {len(brands)} entries; at least 100 are required.")
    per_category = Counter(brand.category for brand in brands)
    for category in CATEGORIES:
        if per_category[category] < 8:
            raise ValueError(f"Category {category} has only {per_category[category]} brands.")
    return brands


def hostname_uses_reference(url: str, domains: set[str]) -> bool:
    hostname = urlsplit(url).hostname
    if hostname is None:
        return True
    host = hostname.rstrip(".").casefold()
    return any(host == domain or host.endswith("." + domain) for domain in domains)


def assemble(
    scheme: str,
    labels: list[str],
    suffix: str,
    path: str,
    query: str,
    port: int | None,
    *,
    punycode: bool,
) -> str:
    rendered: list[str] = []
    for label in labels:
        text = label.casefold()
        if any(separator in text for separator in (".", "/", "?", "#", " ")):
            raise ValueError(f"Illegal label: {label}")
        if punycode:
            text = encode_label(text)
        if not text or len(text) > 63 or text.startswith("-") or text.endswith("-"):
            raise ValueError(f"Illegal label: {label}")
        rendered.append(text)
    rendered.append(suffix)
    host = ".".join(rendered)
    netloc = f"{host}:{port}" if port else host
    if not path.startswith("/"):
        path = "/" + path
    url = f"{scheme}://{netloc}{path}"
    if query:
        url = f"{url}?{query}"
    return url


class WordLists:
    def __init__(self, brands: list[Brand]) -> None:
        tokens = {brand.token for brand in brands}

        def usable(words: tuple[str, ...]) -> tuple[str, ...]:
            kept = []
            for word in words:
                if word in tokens or word in SUSPICIOUS_KEYWORDS:
                    continue
                if any(edit_distance(word, token) <= 2 for token in tokens):
                    continue
                kept.append(word)
            if not kept:
                raise ValueError("No usable host words remained after brand filtering.")
            return tuple(kept)

        self.safe_words = usable(SAFE_WORD_CANDIDATES)
        self.publishers = usable(PUBLISHER_CANDIDATES)
        self.generic_hosts = usable(GENERIC_HOST_CANDIDATES)
        self.decoys = usable(NEUTRAL_DECOY_CANDIDATES)
        self.nn_words = usable(NN_WORDS)
        self.tokens = tokens


class BrandPicker:
    def __init__(self, brands: list[Brand], rng: random.Random) -> None:
        self._brands = list(brands)
        rng.shuffle(self._brands)
        self._index = 0
        self.usage = {brand.token: 0 for brand in brands}

    def next_brand(self, predicate: Callable[[Brand], bool]) -> Brand | None:
        count = len(self._brands)
        for _ in range(count):
            brand = self._brands[self._index % count]
            self._index += 1
            if self.usage[brand.token] >= BRAND_USAGE_CAP:
                continue
            if predicate(brand):
                return brand
        return None

    def mark(self, brand: Brand) -> None:
        self.usage[brand.token] += 1


def can_impersonate(brand: Brand) -> bool:
    return brand.allow_impersonation


def scheme_for(rng: random.Random) -> str:
    return "http" if rng.random() < 0.20 else "https"


def port_for(rng: random.Random) -> int | None:
    if rng.random() < 0.08:
        return rng.choice((8080, 8443, 4443))
    return None


def suffix_for(rng: random.Random) -> str:
    return rng.choice(RESERVED_SUFFIXES)


def benign_query(rng: random.Random, words: WordLists) -> str:
    if rng.random() < 0.45:
        return ""
    number = rng.randrange(10, 90000)
    word = rng.choice(words.safe_words)
    return rng.choice(
        (
            f"id={number}",
            f"ref={word}",
            "lang=en",
            f"page={rng.randrange(1, 30)}",
            "utm_source=newsletter&utm_campaign=digest",
            f"item={number}",
            f"q={word}",
        )
    )


def neutral_path(rng: random.Random, words: WordLists) -> str:
    number = rng.randrange(100, 90000)
    other = rng.randrange(100, 90000)
    word = rng.choice(words.safe_words)
    second = rng.choice(words.safe_words)
    return rng.choice(
        (
            "/",
            "/home",
            "/about",
            "/search",
            "/privacy",
            "/terms",
            "/careers",
            "/newsroom",
            "/contact",
            "/download",
            "/explore",
            "/feed",
            "/watch",
            "/inbox",
            "/help/faq",
            "/company/about",
            "/settings/profile",
            f"/orders/{number}",
            f"/item/{number}",
            f"/products/{number}",
            f"/p/{number}/reviews",
            f"/category/{word}",
            f"/store/item/{number}",
            f"/help-center/articles/{number}",
            f"/documents/policy-{number}",
            f"/channels/{word}/archive",
            f"/users/{number}/posts/{other}",
            f"/a/{word}/b/{second}/c/{number}",
            f"/catalog/{word}/sku-{number}",
        )
    )


def long_hyphen_path(rng: random.Random, words: WordLists) -> str:
    number = rng.randrange(1000, 90000)
    other = rng.randrange(10, 900)
    word = rng.choice(words.safe_words)
    return rng.choice(
        (
            f"/help-center/order-history/{number}/item-{other}",
            f"/catalog/{word}/sku-{number}/color-{word}",
            f"/documents/annual-report-{rng.randrange(2014, 2026)}/section-{other}",
            f"/a/{word}/b/{word}-notes/c/{number}/d/{other}",
        )
    )


def lure_path(rng: random.Random) -> str:
    keyword = rng.choice(LURE_KEYWORDS)
    number = rng.randrange(1000, 99999)
    return rng.choice(
        (
            f"/{keyword}",
            f"/{keyword}/session/{number}",
            f"/{keyword}/continue",
            f"/user/{keyword}/{number}",
        )
    )


def substitution_pool(token: str, count: int) -> list[int] | None:
    primary = [index for index, character in enumerate(token) if character in PRIMARY_DIGITS]
    extra = [index for index, character in enumerate(token) if character in EXTRA_DIGITS]
    pool = primary if len(primary) >= count else primary + extra
    if len(set(pool)) < count:
        return None
    return pool


def apply_substitutions(token: str, count: int, rng: random.Random) -> str | None:
    pool = substitution_pool(token, count)
    if pool is None:
        return None
    chosen = rng.sample(sorted(set(pool)), count)
    chars = list(token)
    for index in chosen:
        character = chars[index]
        if character in PRIMARY_DIGITS:
            chars[index] = PRIMARY_DIGITS[character]
        else:
            chars[index] = EXTRA_DIGITS[character]
    return "".join(chars)


def apply_homoglyphs(token: str, count: int, rng: random.Random) -> str | None:
    indexes = [index for index, character in enumerate(token) if character in CONFUSABLES]
    if len(indexes) < count:
        return None
    chars = list(token)
    for index in rng.sample(indexes, count):
        chars[index] = CONFUSABLES[chars[index]]
    return "".join(chars)


def apply_nn(token: str, rng: random.Random) -> str | None:
    indexes = [index for index, character in enumerate(token) if character == "m"]
    if not indexes:
        return None
    index = rng.choice(indexes)
    return token[:index] + "nn" + token[index + 1 :]


def apply_rn(token: str, rng: random.Random) -> str | None:
    indexes = [index for index, character in enumerate(token) if character == "m"]
    if not indexes:
        return None
    index = rng.choice(indexes)
    return token[:index] + "rn" + token[index + 1 :]


def apply_repeat(token: str, rng: random.Random) -> str:
    index = rng.randrange(len(token))
    return token[:index] + token[index] + token[index:]


def apply_insert(token: str, rng: random.Random) -> str:
    index = rng.randrange(len(token) + 1)
    character = rng.choice("abcdefghijklmnopqrstuvwxyz")
    return token[:index] + character + token[index:]


def apply_delete(token: str, rng: random.Random) -> str | None:
    if len(token) < 5:
        return None
    index = rng.randrange(len(token))
    return token[:index] + token[index + 1 :]


def apply_transpose(token: str, rng: random.Random) -> str | None:
    if len(token) < 4:
        return None
    pairs = [index for index in range(len(token) - 1) if token[index] != token[index + 1]]
    if not pairs:
        return None
    index = rng.choice(pairs)
    chars = list(token)
    chars[index], chars[index + 1] = chars[index + 1], chars[index]
    return "".join(chars)


def acceptable(text: str, brand: Brand, tokens: set[str]) -> bool:
    return bool(text) and text != brand.token and text not in tokens and len(text) <= 63


class DatasetBuilder:
    def __init__(self, brands: list[Brand], rng: random.Random) -> None:
        self.brands = brands
        self.by_token = {brand.token: brand for brand in brands}
        self.rng = rng
        self.words = WordLists(brands)
        self.picker = BrandPicker(brands, rng)
        self.reference_domains = {domain for brand in brands for domain in brand.reference_domains}
        self.seen: set[str] = set()
        self.rows: list[dict[str, object]] = []

    def _decorate(self) -> tuple[str, str, int | None]:
        return scheme_for(self.rng), suffix_for(self.rng), port_for(self.rng)

    def _blocked(self, url: str) -> bool:
        if hostname_uses_reference(url, self.reference_domains):
            return True
        return any(domain in url for domain in self.reference_domains)

    def _finish(
        self,
        url: str,
        brand: Brand | None,
        method: str,
        source: str,
        label: str,
        extra_tags: list[str] | None = None,
    ) -> dict[str, object] | None:
        if self._blocked(url):
            return None
        try:
            key = normalize_url(url)
            row = measure(url, brand, method, source, label, extra_tags)
        except (ValueError, idna.IDNAError):
            return None
        if key in self.seen:
            return None
        row["_key"] = key
        return row

    def accept(self, count: int, method: str, factory: Callable[[], dict[str, object] | None], expect: Callable[[dict[str, object]], str | None]) -> None:
        made = 0
        attempts = 0
        rejects: Counter[str] = Counter()
        limit = count * 120 + 400
        while made < count:
            attempts += 1
            if attempts > limit:
                raise RuntimeError(f"{method} stalled at {made}/{count}; rejects={rejects.most_common(12)}")
            row = factory()
            if row is None:
                rejects["unbuilt"] += 1
                continue
            reason = expect(row)
            if reason is not None:
                rejects[reason] += 1
                continue
            self.seen.add(str(row["_key"]))
            brand = row["brand_obj"]
            if isinstance(brand, Brand):
                self.picker.mark(brand)
            self.rows.append(row)
            made += 1
        print(f"built {method}: {made}", flush=True)

    def take_brand(self, predicate: Callable[[Brand], bool]) -> Brand | None:
        return self.picker.next_brand(predicate)

    def build_service(self, brand: Brand, labels: list[str], path: str, query: str) -> dict[str, object] | None:
        scheme, suffix, port = self._decorate()
        url = assemble(scheme, labels, suffix, path, query, port, punycode=False)
        return self._finish(url, brand, "legit_brand_service", "reserved_brand_service", "legitimate")

    def coverage_row(self, brand: Brand) -> dict[str, object] | None:
        path = neutral_path(self.rng, self.words)
        query = benign_query(self.rng, self.words)
        return self.build_service(brand, [brand.token], path, query)

    def deep_row(self) -> dict[str, object] | None:
        brand = self.take_brand(lambda _brand: True)
        if brand is None:
            return None
        path = long_hyphen_path(self.rng, self.words)
        query = benign_query(self.rng, self.words)
        return self.build_service(brand, [*DEEP_PREFIXES, brand.token], path, query)

    def lure_path_row(self) -> dict[str, object] | None:
        brand = self.take_brand(lambda _brand: True)
        if brand is None:
            return None
        label = self.rng.choice(SERVICE_LABELS)
        if label in self.words.tokens:
            label = "www"
        return self.build_service(brand, [label, brand.token], lure_path(self.rng), benign_query(self.rng, self.words))

    def lure_host_row(self) -> dict[str, object] | None:
        brand = self.take_brand(lambda _brand: True)
        if brand is None:
            return None
        keyword = self.rng.choice(LURE_KEYWORDS)
        return self.build_service(
            brand,
            [keyword, brand.token],
            neutral_path(self.rng, self.words),
            benign_query(self.rng, self.words),
        )

    def plain_service_row(self) -> dict[str, object] | None:
        brand = self.take_brand(lambda _brand: True)
        if brand is None:
            return None
        roll = self.rng.random()
        if roll < 0.35:
            labels = [brand.token]
        elif roll < 0.7:
            labels = ["www", brand.token]
        else:
            labels = [self.rng.choice(("mail", "api", "docs", "help", "store")), brand.token]
        return self.build_service(brand, labels, neutral_path(self.rng, self.words), benign_query(self.rng, self.words))

    def third_party_row(self, with_keyword: bool) -> dict[str, object] | None:
        brand = self.take_brand(lambda _brand: True)
        if brand is None:
            return None
        scheme, suffix, port = self._decorate()
        host = self.rng.choice(self.words.publishers)
        number = self.rng.randrange(100, 90000)
        if with_keyword:
            keyword = self.rng.choice(LURE_KEYWORDS)
            path = self.rng.choice(
                (
                    f"/stories/{brand.token}/{keyword}-notes/{number}",
                    f"/guide/{brand.token}/{keyword}",
                    f"/compare/{brand.token}-fees/{keyword}",
                )
            )
        else:
            path = self.rng.choice(
                (
                    f"/stories/{brand.token}-update-{number}",
                    f"/guide/{brand.token}",
                    f"/archive/{self.rng.choice(self.words.safe_words)}/{brand.token}",
                )
            )
        query = benign_query(self.rng, self.words)
        if self.rng.random() < 0.35:
            query = f"topic={brand.token}" if not query else query + f"&topic={brand.token}"
        url = assemble(scheme, [host], suffix, path, query, port, punycode=False)
        return self._finish(url, brand, "legit_third_party", "reserved_third_party_mention", "legitimate")

    def generic_row(self, kind: str) -> dict[str, object] | None:
        scheme, suffix, port = self._decorate()
        host = self.rng.choice(self.words.generic_hosts)
        labels = [host]
        if kind == "long" and self.rng.random() < 0.5:
            labels = [self.rng.choice(("edge", "static")), host]
        if kind == "keyword":
            path = lure_path(self.rng)
            query = benign_query(self.rng, self.words)
        elif kind == "hyphen":
            path = long_hyphen_path(self.rng, self.words)
            query = f"id={self.rng.randrange(10000, 999999)}&ref={self.rng.choice(self.words.safe_words)}"
        else:
            path = f"/a/{self.rng.choice(self.words.safe_words)}/b/{self.rng.randrange(10, 99)}/c/{self.rng.choice(self.words.safe_words)}/d/{self.rng.randrange(1000, 99999)}"
            query = benign_query(self.rng, self.words)
        url = assemble(scheme, labels, suffix, path, query, port, punycode=False)
        return self._finish(url, None, "legit_generic_noisy", "reserved_generic", "legitimate")

    def innocent_nn_row(self, brand: Brand | None) -> dict[str, object] | None:
        scheme, suffix, port = self._decorate()
        if brand is not None:
            url = assemble(
                scheme,
                [brand.token],
                suffix,
                f"/videos/annual-review-{self.rng.randrange(2012, 2026)}",
                benign_query(self.rng, self.words),
                port,
                punycode=False,
            )
            return self._finish(url, brand, "legit_innocent_nn", "reserved_brand_service", "legitimate")
        word = self.rng.choice(self.words.nn_words)
        path = self.rng.choice(
            (
                f"/{word}",
                f"/{word}/notes-{self.rng.randrange(10, 999)}",
                f"/documents/{word}-report-{self.rng.randrange(2010, 2026)}",
            )
        )
        url = assemble(scheme, [word], suffix, path, benign_query(self.rng, self.words), port, punycode=False)
        return self._finish(url, None, "legit_innocent_nn", "reserved_generic", "legitimate")

    def keyword_odd_row(self) -> dict[str, object] | None:
        scheme, suffix, port = self._decorate()
        first, second, third = self.rng.sample(LURE_KEYWORDS, 3)
        labels = [first, f"{second}-{third}"]
        url = assemble(scheme, labels, suffix, f"/session/{self.rng.randrange(1000, 99999)}", "", port, punycode=False)
        return self._finish(url, None, "keyword_odd_structure", "reserved_generic", "suspicious")

    def lookalike_row(
        self,
        method: str,
        label: str,
        mutate: Callable[[str], str | None],
        *,
        lure: bool,
        extra_tags: list[str] | None = None,
        punycode: bool = False,
        predicate: Callable[[Brand], bool] | None = None,
    ) -> dict[str, object] | None:
        brand = self.take_brand(predicate or can_impersonate)
        if brand is None:
            return None
        mutated = mutate(brand.token)
        if mutated is None or not acceptable(mutated, brand, self.words.tokens):
            return None
        scheme, suffix, port = self._decorate()
        path = lure_path(self.rng) if lure else neutral_path(self.rng, self.words)
        query = "" if lure else benign_query(self.rng, self.words)
        url = assemble(scheme, [mutated], suffix, path, query, port, punycode=punycode)
        source = "reserved_impersonation"
        return self._finish(url, brand, method, source, label, extra_tags)

    def subdomain_neutral_row(self) -> dict[str, object] | None:
        brand = self.take_brand(can_impersonate)
        if brand is None:
            return None
        scheme, suffix, port = self._decorate()
        decoy = self.rng.choice(self.words.decoys)
        url = assemble(
            scheme,
            [brand.token, decoy],
            suffix,
            neutral_path(self.rng, self.words),
            benign_query(self.rng, self.words),
            port,
            punycode=False,
        )
        return self._finish(url, brand, "brand_subdomain_neutral", "reserved_impersonation", "suspicious")

    def hyphen_or_digit_row(self) -> dict[str, object] | None:
        brand = self.take_brand(can_impersonate)
        if brand is None:
            return None
        if self.rng.random() < 0.5:
            label = f"{brand.token}{self.rng.randrange(10, 9999)}"
            tags = ["digits_glued_to_brand"]
        else:
            label = f"{brand.token}-{self.rng.choice(('hq', 'global', 'world', 'plus'))}"
            tags = ["hyphen_glued_to_brand"]
        scheme, suffix, port = self._decorate()
        url = assemble(scheme, [label], suffix, neutral_path(self.rng, self.words), "", port, punycode=False)
        return self._finish(url, brand, "hyphen_or_digit_label", "reserved_impersonation", "suspicious", tags)

    def excessive_row(self) -> dict[str, object] | None:
        scheme, suffix, port = self._decorate()
        tail = f"{self.rng.choice(('static', 'blue', 'cold'))}-{self.rng.choice(('harbor', 'files', 'lane'))}"
        if tail.split("-")[0] in self.words.tokens or tail in self.words.tokens:
            return None
        labels = [*EXCESSIVE_PREFIXES, tail]
        url = assemble(scheme, labels, suffix, neutral_path(self.rng, self.words), "", port, punycode=False)
        return self._finish(url, None, "excessive_odd_structure", "reserved_generic", "suspicious")

    def spelling_strong_row(self) -> dict[str, object] | None:
        def mutate(token: str) -> str | None:
            operation = self.rng.choice(("insert", "delete", "transpose", "repeat"))
            if operation == "insert":
                return apply_insert(token, self.rng)
            if operation == "delete":
                return apply_delete(token, self.rng)
            if operation == "transpose":
                return apply_transpose(token, self.rng)
            return apply_repeat(token, self.rng)

        return self.lookalike_row("spelling_strong", "malicious", mutate, lure=True)

    def structure_lure_row(self) -> dict[str, object] | None:
        brand = self.take_brand(can_impersonate)
        if brand is None:
            return None
        keyword = self.rng.choice(LURE_KEYWORDS)
        scheme, suffix, port = self._decorate()
        if self.rng.random() < 0.5:
            labels = [brand.token, keyword]
            path = f"/session/{self.rng.randrange(1000, 99999)}"
        else:
            labels = [f"{brand.token}-{keyword}"]
            path = "/"
        url = assemble(scheme, labels, suffix, path, "", port, punycode=False)
        return self._finish(url, brand, "structure_lure", "reserved_impersonation", "malicious")

    def combined_row(self) -> dict[str, object] | None:
        brand = self.take_brand(can_impersonate)
        if brand is None:
            return None
        modes = (self._combined_numeric_homoglyph, self._combined_spelling_hyphen, self._combined_nn_hyphen, self._combined_repeat_hyphen)
        order = list(modes)
        self.rng.shuffle(order)
        for mode in order:
            row = mode(brand)
            if row is not None:
                return row
        return None

    def _combined_numeric_homoglyph(self, brand: Brand) -> dict[str, object] | None:
        digit_indexes = substitution_pool(brand.token, 1)
        homo_indexes = [index for index, character in enumerate(brand.token) if character in CONFUSABLES]
        if not digit_indexes or not homo_indexes:
            return None
        digit_index = self.rng.choice(sorted(set(digit_indexes)))
        homo_choices = [index for index in homo_indexes if index != digit_index]
        if not homo_choices:
            return None
        homo_index = self.rng.choice(homo_choices)
        chars = list(brand.token)
        source = chars[digit_index]
        if source in PRIMARY_DIGITS:
            chars[digit_index] = PRIMARY_DIGITS[source]
        else:
            chars[digit_index] = EXTRA_DIGITS[source]
        chars[homo_index] = CONFUSABLES[brand.token[homo_index]]
        mutated = "".join(chars)
        if not acceptable(mutated, brand, self.words.tokens):
            return None
        scheme, suffix, port = self._decorate()
        punycode = self.rng.random() < 0.45
        url = assemble(scheme, [mutated], suffix, lure_path(self.rng), "", port, punycode=punycode)
        return self._finish(url, brand, "combined", "reserved_impersonation", "malicious")

    def _hyphen_lure(self, brand: Brand, mutated: str) -> dict[str, object] | None:
        if not acceptable(mutated, brand, self.words.tokens):
            return None
        keyword = self.rng.choice(LURE_KEYWORDS)
        scheme, suffix, port = self._decorate()
        url = assemble(scheme, [f"{mutated}-{keyword}"], suffix, "/", "", port, punycode=False)
        return self._finish(url, brand, "combined", "reserved_impersonation", "malicious")

    def _combined_spelling_hyphen(self, brand: Brand) -> dict[str, object] | None:
        operation = self.rng.choice(("insert", "delete", "transpose"))
        if operation == "insert":
            mutated = apply_insert(brand.token, self.rng)
        elif operation == "delete":
            mutated = apply_delete(brand.token, self.rng)
        else:
            mutated = apply_transpose(brand.token, self.rng)
        if mutated is None:
            return None
        return self._hyphen_lure(brand, mutated)

    def _combined_nn_hyphen(self, brand: Brand) -> dict[str, object] | None:
        mutated = apply_nn(brand.token, self.rng)
        if mutated is None:
            return None
        return self._hyphen_lure(brand, mutated)

    def _combined_repeat_hyphen(self, brand: Brand) -> dict[str, object] | None:
        return self._hyphen_lure(brand, apply_repeat(brand.token, self.rng))


def _int(row: dict[str, object], key: str) -> int | None:
    value = row[key]
    if value is None:
        return None
    return int(value)


def signal_groups(row: dict[str, object]) -> int:
    parsed = row["_parsed"]
    assert isinstance(parsed, ParsedUrl)
    groups = 0
    if (_int(row, "character_substitution_count") or 0) > 0:
        groups += 1
    if any(
        (_int(row, name) or 0) > 0
        for name in (
            "character_insertion_indicator",
            "character_deletion_indicator",
            "character_transposition_indicator",
        )
    ):
        groups += 1
    if (_int(row, "homoglyph_indicator") or 0) > 0:
        groups += 1
    if (_int(row, "double_n_for_m_indicator") or 0) > 0:
        groups += 1
    structure = (
        (_int(row, "brand_in_subdomain") or 0) > 0
        or (_int(row, "misleading_domain_structure") or 0) > 0
        or "-" in parsed.registrable_label
        or any(character.isdigit() for character in parsed.registrable_label)
    )
    if structure:
        groups += 1
    return groups


def expect_clean_lookalike(row: dict[str, object], *, substitution: int | None = None, keyword: int | None = None) -> str | None:
    if row["homoglyph_indicator"] or row["punycode_indicator"]:
        return "unexpected-script-signal"
    if _int(row, "brand_in_subdomain") or _int(row, "misleading_domain_structure"):
        return "unexpected-structure"
    if keyword is not None and _int(row, "suspicious_keyword_count") != keyword and not (
        keyword == 1 and (_int(row, "suspicious_keyword_count") or 0) >= 1
    ):
        return "keyword-count"
    if substitution is not None and _int(row, "character_substitution_count") != substitution:
        return "substitution-count"
    return None


def expect_row(method: str, row: dict[str, object]) -> str | None:
    label = str(row["label"])
    keywords = _int(row, "suspicious_keyword_count") or 0
    if method == "legit_brand_service":
        parsed = row["_parsed"]
        assert isinstance(parsed, ParsedUrl)
        brand = row["brand_obj"]
        assert isinstance(brand, Brand)
        if parsed.registrable_label != brand.token:
            return "registrable-not-token"
        if any(
            _int(row, name)
            for name in (
                "character_substitution_count",
                "double_n_for_m_indicator",
                "character_insertion_indicator",
                "character_deletion_indicator",
                "character_transposition_indicator",
                "homoglyph_indicator",
                "punycode_indicator",
                "brand_in_subdomain",
                "misleading_domain_structure",
            )
        ):
            return "legit-brand-has-impersonation-signal"
        return None
    if method == "legit_third_party":
        brand = row["brand_obj"]
        parsed = row["_parsed"]
        assert isinstance(brand, Brand) and isinstance(parsed, ParsedUrl)
        host_parts = host_components(parsed.decoded_labels[:-1])
        if brand.token in host_parts:
            return "brand-leaked-into-host"
        tokens = set(TOKEN_RE.findall(row["url"].casefold()))  # type: ignore[union-attr]
        if brand.token not in tokens:
            return "brand-missing-from-url"
        if row["homoglyph_indicator"] or _int(row, "character_substitution_count"):
            return "third-party-mutated"
        return None
    if method in {"legit_generic_noisy", "keyword_odd_structure", "excessive_odd_structure"}:
        if row["brand_name"] is not None:
            return "unexpected-brand"
        if method == "keyword_odd_structure" and (keywords < 2 or not row["misleading_domain_structure"]):
            return "odd-keyword-shape"
        if method == "excessive_odd_structure" and (
            (_int(row, "subdomain_count") or 0) < 4 or keywords != 0
        ):
            return "excessive-shape"
        return None
    if method == "legit_innocent_nn":
        if "nn" not in str(row["url"]):
            return "missing-nn"
        if _int(row, "double_n_for_m_indicator") == 1:
            return "innocent-nn-flagged"
        return None
    if method == "numeric_mild":
        return expect_clean_lookalike(row, substitution=1, keyword=0)
    if method == "numeric_strong":
        if (_int(row, "character_substitution_count") or 0) < 2 or keywords < 1:
            return "numeric-strong-shape"
        if row["homoglyph_indicator"]:
            return "unexpected-homoglyph"
        return None
    if method == "double_n_mild":
        if _int(row, "double_n_for_m_indicator") != 1 or keywords != 0:
            return "double-n-mild-shape"
        if _int(row, "character_insertion_indicator"):
            return "nn-counted-as-insertion"
        return expect_clean_lookalike(row, substitution=0, keyword=0)
    if method == "double_n_strong":
        if _int(row, "double_n_for_m_indicator") != 1 or keywords < 1:
            return "double-n-strong-shape"
        return None
    if method == "rn_for_m_mild":
        if "rn_for_m" not in str(row["transformation_types"]) or keywords != 0:
            return "rn-shape"
        if _int(row, "double_n_for_m_indicator") == 1:
            return "rn-flagged-as-nn"
        return expect_clean_lookalike(row, substitution=0, keyword=0)
    if method == "repeat_mild":
        if _int(row, "character_insertion_indicator") != 1 or keywords != 0:
            return "repeat-shape"
        return expect_clean_lookalike(row, substitution=0, keyword=0)
    if method == "insertion_mild":
        if _int(row, "character_insertion_indicator") != 1 or keywords != 0:
            return "insertion-shape"
        return expect_clean_lookalike(row, substitution=0, keyword=0)
    if method == "deletion_mild":
        if _int(row, "character_deletion_indicator") != 1 or keywords != 0:
            return "deletion-shape"
        return expect_clean_lookalike(row, substitution=0, keyword=0)
    if method == "transposition_mild":
        if _int(row, "character_transposition_indicator") != 1 or keywords != 0:
            return "transposition-shape"
        return expect_clean_lookalike(row, substitution=0, keyword=0)
    if method == "unicode_mild":
        if not row["homoglyph_indicator"] or row["punycode_indicator"] or not row["mixed_script_indicator"]:
            return "unicode-mild-shape"
        if keywords != 0 or (_int(row, "character_substitution_count") or 0) != 0:
            return "unicode-mild-extra"
        return None
    if method == "unicode_strong":
        if not row["homoglyph_indicator"] or row["punycode_indicator"] or keywords < 1:
            return "unicode-strong-shape"
        return None
    if method == "punycode_strong":
        if not row["punycode_indicator"] or not row["homoglyph_indicator"] or keywords < 1:
            return "punycode-shape"
        return None
    if method == "brand_subdomain_neutral":
        if _int(row, "brand_in_subdomain") != 1 or keywords != 0:
            return "subdomain-shape"
        if _int(row, "character_substitution_count") or row["homoglyph_indicator"]:
            return "subdomain-mutated"
        return None
    if method == "hyphen_or_digit_label":
        parsed = row["_parsed"]
        assert isinstance(parsed, ParsedUrl)
        changed = "-" in parsed.registrable_label or any(character.isdigit() for character in parsed.registrable_label)
        if not changed or keywords != 0 or _int(row, "character_substitution_count"):
            return "hyphen-digit-shape"
        return None
    if method == "spelling_strong":
        spelling = any(
            _int(row, name)
            for name in (
                "character_insertion_indicator",
                "character_deletion_indicator",
                "character_transposition_indicator",
            )
        )
        if not spelling or keywords < 1 or row["homoglyph_indicator"]:
            return "spelling-strong-shape"
        return None
    if method == "structure_lure":
        if keywords < 1 or signal_groups(row) < 1:
            return "structure-lure-shape"
        if _int(row, "character_substitution_count") or row["homoglyph_indicator"] or _int(row, "double_n_for_m_indicator"):
            return "structure-lure-mutated"
        if not (_int(row, "brand_in_subdomain") or _int(row, "misleading_domain_structure")):
            return "structure-lure-position"
        return None
    if method == "combined":
        if keywords < 1 or signal_groups(row) < 2:
            return "combined-shape"
        return None
    if label not in {"legitimate", "suspicious", "malicious"}:
        return "bad-label"
    return None


def scale_quotas(row_count: int) -> dict[str, int]:
    if sum(BASE_QUOTAS.values()) != DEFAULT_ROWS:
        raise RuntimeError("Base quotas must sum to 10000.")
    if row_count == DEFAULT_ROWS:
        return dict(BASE_QUOTAS)
    raw = {name: quota * row_count / DEFAULT_ROWS for name, quota in BASE_QUOTAS.items()}
    scaled = {name: int(value) for name, value in raw.items()}
    remainder = row_count - sum(scaled.values())
    order = sorted(BASE_QUOTAS, key=lambda name: (raw[name] - scaled[name], BASE_QUOTAS[name]), reverse=True)
    for name in order[:remainder]:
        scaled[name] += 1
    return scaled


def generate_rows(brands: list[Brand], rng: random.Random, row_count: int) -> list[dict[str, object]]:
    quotas = scale_quotas(row_count)
    builder = DatasetBuilder(brands, rng)
    service_total = quotas["legit_brand_service"]
    coverage = len(brands)
    deep = max(1, round(service_total * 200 / 1600))
    lure_paths = max(1, round(service_total * 450 / 1600))
    lure_hosts = max(1, round(service_total * 250 / 1600))
    plain = service_total - coverage - deep - lure_paths - lure_hosts
    if plain < 1:
        raise RuntimeError("Not enough legitimate brand-service rows for one example per brand.")

    for brand in brands:
        placed = False
        for _ in range(30):
            row = builder.coverage_row(brand)
            if row is None:
                continue
            reason = expect_row("legit_brand_service", row)
            if reason is not None:
                continue
            builder.seen.add(str(row["_key"]))
            builder.picker.mark(brand)
            builder.rows.append(row)
            placed = True
            break
        if not placed:
            raise RuntimeError(f"Could not place a legitimate coverage row for {brand.brand_name}.")
    print(f"built legit_brand_service coverage: {coverage}", flush=True)

    builder.accept(deep, "legit_brand_service", builder.deep_row, lambda row: expect_row("legit_brand_service", row))
    builder.accept(lure_paths, "legit_brand_service", builder.lure_path_row, lambda row: expect_row("legit_brand_service", row))
    builder.accept(lure_hosts, "legit_brand_service", builder.lure_host_row, lambda row: expect_row("legit_brand_service", row))
    builder.accept(plain, "legit_brand_service", builder.plain_service_row, lambda row: expect_row("legit_brand_service", row))

    third = quotas["legit_third_party"]
    keyword_mentions = max(1, round(third * 400 / 1200))
    plain_mentions = third - keyword_mentions
    builder.accept(plain_mentions, "legit_third_party", lambda: builder.third_party_row(False), lambda row: expect_row("legit_third_party", row))
    builder.accept(keyword_mentions, "legit_third_party", lambda: builder.third_party_row(True), lambda row: expect_row("legit_third_party", row))

    generic = quotas["legit_generic_noisy"]
    generic_keyword = max(1, round(generic * 350 / 1000))
    generic_hyphen = max(1, round(generic * 350 / 1000))
    generic_long = generic - generic_keyword - generic_hyphen
    builder.accept(generic_keyword, "legit_generic_noisy", lambda: builder.generic_row("keyword"), lambda row: expect_row("legit_generic_noisy", row))
    builder.accept(generic_hyphen, "legit_generic_noisy", lambda: builder.generic_row("hyphen"), lambda row: expect_row("legit_generic_noisy", row))
    builder.accept(generic_long, "legit_generic_noisy", lambda: builder.generic_row("long"), lambda row: expect_row("legit_generic_noisy", row))

    cnn = builder.by_token.get("cnn")
    innocent = quotas["legit_innocent_nn"]
    cnn_rows = min(40, innocent) if cnn is not None else 0
    if cnn is not None:
        builder.accept(cnn_rows, "legit_innocent_nn", lambda: builder.innocent_nn_row(cnn), lambda row: expect_row("legit_innocent_nn", row))
    builder.accept(innocent - cnn_rows, "legit_innocent_nn", lambda: builder.innocent_nn_row(None), lambda row: expect_row("legit_innocent_nn", row))

    def mild(method: str, mutate: Callable[[str], str | None], tags: list[str] | None = None, predicate: Callable[[Brand], bool] | None = None) -> None:
        builder.accept(
            quotas[method],
            method,
            lambda: builder.lookalike_row(method, "suspicious", mutate, lure=False, extra_tags=tags, predicate=predicate),
            lambda row: expect_row(method, row),
        )

    mild("numeric_mild", lambda token: apply_substitutions(token, 1, builder.rng))
    mild("double_n_mild", lambda token: apply_nn(token, builder.rng), predicate=lambda brand: can_impersonate(brand) and "m" in brand.token and "nn" not in brand.token)
    mild("rn_for_m_mild", lambda token: apply_rn(token, builder.rng), ["rn_for_m"], predicate=lambda brand: can_impersonate(brand) and "m" in brand.token)
    mild("repeat_mild", lambda token: apply_repeat(token, builder.rng))
    mild("insertion_mild", lambda token: apply_insert(token, builder.rng))
    mild("deletion_mild", lambda token: apply_delete(token, builder.rng), predicate=lambda brand: can_impersonate(brand) and len(brand.token) >= 5)
    mild("transposition_mild", lambda token: apply_transpose(token, builder.rng))
    mild("unicode_mild", lambda token: apply_homoglyphs(token, 1, builder.rng), predicate=lambda brand: can_impersonate(brand) and any(character in CONFUSABLES for character in brand.token))

    builder.accept(quotas["brand_subdomain_neutral"], "brand_subdomain_neutral", builder.subdomain_neutral_row, lambda row: expect_row("brand_subdomain_neutral", row))
    builder.accept(quotas["hyphen_or_digit_label"], "hyphen_or_digit_label", builder.hyphen_or_digit_row, lambda row: expect_row("hyphen_or_digit_label", row))
    builder.accept(quotas["excessive_odd_structure"], "excessive_odd_structure", builder.excessive_row, lambda row: expect_row("excessive_odd_structure", row))
    builder.accept(quotas["keyword_odd_structure"], "keyword_odd_structure", builder.keyword_odd_row, lambda row: expect_row("keyword_odd_structure", row))

    def strong(method: str, mutate: Callable[[str], str | None], punycode: bool = False, predicate: Callable[[Brand], bool] | None = None) -> None:
        builder.accept(
            quotas[method],
            method,
            lambda: builder.lookalike_row(method, "malicious", mutate, lure=True, punycode=punycode, predicate=predicate),
            lambda row: expect_row(method, row),
        )

    strong("numeric_strong", lambda token: apply_substitutions(token, 2, builder.rng) or apply_substitutions(token, 3, builder.rng))
    strong("double_n_strong", lambda token: apply_nn(token, builder.rng), predicate=lambda brand: can_impersonate(brand) and "m" in brand.token and "nn" not in brand.token)
    builder.accept(quotas["spelling_strong"], "spelling_strong", builder.spelling_strong_row, lambda row: expect_row("spelling_strong", row))
    strong(
        "unicode_strong",
        lambda token: apply_homoglyphs(token, 2, builder.rng) or apply_homoglyphs(token, 1, builder.rng),
        predicate=lambda brand: can_impersonate(brand) and any(character in CONFUSABLES for character in brand.token),
    )
    strong(
        "punycode_strong",
        lambda token: apply_homoglyphs(token, 2, builder.rng) or apply_homoglyphs(token, 1, builder.rng),
        punycode=True,
        predicate=lambda brand: can_impersonate(brand) and any(character in CONFUSABLES for character in brand.token),
    )
    builder.accept(quotas["structure_lure"], "structure_lure", builder.structure_lure_row, lambda row: expect_row("structure_lure", row))
    builder.accept(quotas["combined"], "combined", builder.combined_row, lambda row: expect_row("combined", row))

    if len(builder.rows) != row_count:
        raise RuntimeError(f"Generated {len(builder.rows)} rows, expected {row_count}.")
    rng.shuffle(builder.rows)
    return builder.rows


def assign_ids(rows: list[dict[str, object]], seed: int) -> None:
    for index, row in enumerate(rows, start=1):
        row["record_id"] = f"syn-{seed}-{index:05d}"


def freeze_row(row: dict[str, object]) -> dict[str, str]:
    frozen: dict[str, str] = {}
    for column in COLUMNS:
        value = row.get(column)
        if value is None:
            frozen[column] = ""
        elif isinstance(value, float):
            frozen[column] = f"{value:.4f}"
        else:
            frozen[column] = str(value)
    return frozen


def validate_rows(rows: list[dict[str, object]], brands: list[Brand], seed: int) -> dict[str, object]:
    if any("record_id" not in row for row in rows):
        raise RuntimeError("record_id was not assigned.")
    frozen = [freeze_row(row) for row in rows]
    ids = [item["record_id"] for item in frozen]
    urls = [item["url"] for item in frozen]
    keys = [normalize_url(url) for url in urls]
    if len(ids) != len(set(ids)):
        raise RuntimeError("Duplicate record_id values.")
    if len(urls) != len(set(urls)) or len(keys) != len(set(keys)):
        raise RuntimeError("Duplicate URLs under the normalization procedure.")
    signatures = [tuple(item[column] for column in COLUMNS) for item in frozen]
    if len(signatures) != len(set(signatures)):
        raise RuntimeError("Duplicate dataset rows.")
    labels = Counter(item["label"] for item in frozen)
    methods = Counter(item["generation_method"] for item in frozen)
    for label_name in ("legitimate", "suspicious", "malicious"):
        if labels[label_name] < max(100, len(rows) // 5):
            raise RuntimeError(f"Label {label_name} is too small: {labels[label_name]}")
    used_names = {item["brand_name"] for item in frozen if item["brand_name"]}
    if used_names != {brand.brand_name for brand in brands}:
        missing = {brand.brand_name for brand in brands} - used_names
        raise RuntimeError(f"Brands missing from the dataset: {sorted(missing)[:12]}")
    brand_counts = Counter(item["brand_name"] for item in frozen if item["brand_name"])
    if max(brand_counts.values()) > BRAND_USAGE_CAP:
        raise RuntimeError("One brand exceeds the usage cap.")
    impersonation_min = min(brand_counts[brand.brand_name] for brand in brands if brand.allow_impersonation)
    if impersonation_min < 5:
        raise RuntimeError(f"An impersonation-capable brand appears only {impersonation_min} times.")
    categories = Counter(item["brand_category"] for item in frozen if item["brand_category"])
    if set(categories) != set(CATEGORIES):
        raise RuntimeError(f"Missing categories: {set(CATEGORIES) - set(categories)}")
    domains = {domain for brand in brands for domain in brand.reference_domains}
    for item in frozen:
        if any(domain in item["url"] for domain in domains):
            raise RuntimeError(f"Reference domain leaked into URL: {item['url']}")
        parsed = parse_url(item["url"])
        if parsed.suffix not in RESERVED_SUFFIXES:
            raise RuntimeError(f"Non-reserved suffix: {item['url']}")
        if item["brand_name"] == "" and any(item[name] != "" for name in (
            "brand_category",
            "character_substitution_count",
            "edit_distance",
            "brand_similarity_score",
            "brand_in_subdomain",
            "double_n_for_m_indicator",
            "reference_domain",
        )):
            raise RuntimeError(f"Generic row invented brand measurements: {item['record_id']}")
    by_label: dict[str, list[dict[str, str]]] = {name: [] for name in labels}
    for item in frozen:
        by_label[item["label"]].append(item)
    for label_name, group in by_label.items():
        schemes = Counter(urlsplit(item["url"]).scheme for item in group)
        if schemes["http"] < 20 or schemes["https"] < 20:
            raise RuntimeError(f"Label {label_name} does not contain both schemes: {schemes}")
    legitimate = by_label["legitimate"]
    if sum(1 for item in legitimate if int(item["suspicious_keyword_count"]) > 0) < 800:
        raise RuntimeError("Too few legitimate rows contain suspicious keywords.")
    if sum(1 for item in legitimate if int(item["url_length"]) >= 80) < 400:
        raise RuntimeError("Too few long legitimate URLs.")
    if sum(1 for item in legitimate if int(item["hyphen_count"]) >= 2) < 300:
        raise RuntimeError("Too few hyphenated legitimate URLs.")
    if sum(1 for item in legitimate if int(item["subdomain_count"]) >= 4) < 50:
        raise RuntimeError("Legitimate rows do not include deep subdomains.")
    malicious = by_label["malicious"]
    login_share = sum(1 for item in malicious if "login" in TOKEN_RE.findall(item["url"].casefold())) / len(malicious)
    if login_share > 0.40:
        raise RuntimeError(f"login appears in {login_share:.2%} of malicious rows.")
    lure_kinds = {token for item in malicious for token in TOKEN_RE.findall(item["url"].casefold()) if token in SUSPICIOUS_KEYWORDS}
    if len(lure_kinds) < 10:
        raise RuntimeError(f"Malicious rows use only {len(lure_kinds)} suspicious keywords.")
    nn_not_flagged = [
        item
        for item in frozen
        if "nn" in item["url"].casefold() and item["double_n_for_m_indicator"] != "1"
    ]
    if len(nn_not_flagged) < 100:
        raise RuntimeError("Not enough nn examples that are not an m lookalike.")
    if not any(item["double_n_for_m_indicator"] == "1" for item in frozen):
        raise RuntimeError("Missing nn-for-m examples.")
    if not any(item["punycode_indicator"] == "1" for item in frozen):
        raise RuntimeError("Missing punycode examples.")
    if not any(item["homoglyph_indicator"] == "1" and item["punycode_indicator"] == "0" for item in frozen):
        raise RuntimeError("Missing raw Unicode homoglyph examples.")
    if not any(item["brand_in_subdomain"] == "1" for item in frozen):
        raise RuntimeError("Missing brand-in-subdomain examples.")
    if len({item["registrable_domain"] for item in frozen}) < 80:
        raise RuntimeError("Registrable domains are not diverse enough.")
    method_label = Counter((item["generation_method"], item["label"]) for item in frozen)
    for method, quota_label in (
        ("numeric_mild", "suspicious"),
        ("combined", "malicious"),
        ("legit_generic_noisy", "legitimate"),
    ):
        if method_label[(method, quota_label)] <= 0:
            raise RuntimeError(f"Missing method {method}.")
    return {
        "generator_version": GENERATOR_VERSION,
        "seed": seed,
        "rows": len(frozen),
        "unique_record_ids": len(set(ids)),
        "unique_urls": len(set(urls)),
        "unique_normalized_urls": len(set(keys)),
        "duplicate_normalized_urls": len(keys) - len(set(keys)),
        "reference_brand_count": len(brands),
        "brands_used": len(used_names),
        "impersonation_capable_brands": sum(1 for brand in brands if brand.allow_impersonation),
        "min_rows_for_impersonation_brand": impersonation_min,
        "max_rows_for_one_brand": max(brand_counts.values()),
        "label_counts": dict(labels),
        "generation_method_counts": dict(methods),
        "category_counts": dict(categories),
        "unique_registrable_domains": len({item["registrable_domain"] for item in frozen}),
        "punycode_rows": sum(item["punycode_indicator"] == "1" for item in frozen),
        "unicode_homoglyph_rows": sum(item["homoglyph_indicator"] == "1" and item["punycode_indicator"] == "0" for item in frozen),
        "double_n_for_m_rows": sum(item["double_n_for_m_indicator"] == "1" for item in frozen),
        "nn_rows_not_flagged_as_m": len(nn_not_flagged),
        "malicious_login_share": round(login_share, 4),
        "legitimate_rows_with_keyword": sum(int(item["suspicious_keyword_count"]) > 0 for item in legitimate),
        "reserved_suffixes": list(RESERVED_SUFFIXES),
        "metadata_columns_excluded_from_model_input": list(METADATA_COLUMNS),
    }


def write_dataset(rows: list[dict[str, object]], output: Path, summary: dict[str, object]) -> str:
    output.parent.mkdir(parents=True, exist_ok=True)
    temp_path = output.with_suffix(output.suffix + ".tmp")
    with temp_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=COLUMNS, lineterminator="\n")
        writer.writeheader()
        for row in rows:
            writer.writerow(freeze_row(row))
    digest = hashlib.sha256(temp_path.read_bytes()).hexdigest()
    temp_path.replace(output)
    summary["sha256"] = digest
    summary["output"] = str(output)
    meta_path = output.with_suffix(".meta.json")
    meta_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return digest


def run_self_tests(brands: list[Brand]) -> None:
    assert len(brands) >= 100
    assert edit_distance("paypal", "paypal") == 0
    assert edit_distance("google", "g00gle") == 2
    assert nn_imitates_m("instagrann", "instagram") is True
    assert is_single_insertion("instagrann", "instagram") is False
    assert nn_imitates_m("cnn", "cnn") is False
    assert nn_imitates_m("annual", "amazon") is False
    assert is_single_insertion("payypal", "paypal") is True
    assert is_single_deletion("paypl", "paypal") is True
    assert is_adjacent_transposition("ogogle", "google") is True
    assert substitution_counts("g00gle", "google")["zero"] == 2
    assert substitution_counts("g00gle", "google")["total"] == 2

    paypal = next(brand for brand in brands if brand.token == "paypal")
    legit = measure(
        "https://login.paypal.test/account/settings",
        paypal,
        "self-test",
        "reserved_brand_service",
        "legitimate",
    )
    assert legit["suspicious_keyword_count"] >= 2
    assert legit["misleading_domain_structure"] == 0
    assert legit["brand_in_subdomain"] == 0
    assert legit["edit_distance"] == 0

    lookalike = measure(
        "http://g00gle.test/home",
        next(brand for brand in brands if brand.token == "google"),
        "self-test",
        "reserved_impersonation",
        "suspicious",
    )
    assert lookalike["zero_for_o_count"] == 2
    assert lookalike["character_substitution_count"] == 2

    subdomain = measure(
        "https://paypal.news.test/home",
        paypal,
        "self-test",
        "reserved_impersonation",
        "suspicious",
    )
    assert subdomain["brand_in_subdomain"] == 1
    assert subdomain["misleading_domain_structure"] == 1
    assert subdomain["edit_distance"] == 0

    parsed = parse_url("https://a.b.paypal.test/path")
    assert parsed.registrable_domain == "paypal.test"
    assert parsed.subdomain_labels == ("a", "b")
    unicode_url = "https://g\u043eogle.test/login"
    punycode_url = "https://" + encode_label("g\u043eogle") + ".test/login"
    assert normalize_url(unicode_url) == normalize_url(punycode_url)
    assert normalize_url("https://PayPal.test:443/Login/#frag") == normalize_url("https://paypal.test/Login")
    cnn = measure("https://www.cnn.test/videos", next(brand for brand in brands if brand.token == "cnn"), "self-test", "reserved_brand_service", "legitimate")
    assert cnn["double_n_for_m_indicator"] == 0
    print(f"self-tests passed ({len(brands)} reference brands)", flush=True)


def default_output() -> Path:
    return SCRIPT_DIR.parent / "ml_data" / "url_dataset.csv"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate the ClickSafe synthetic URL dataset.")
    parser.add_argument("--rows", type=int, default=DEFAULT_ROWS)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--output", type=Path, default=default_output())
    parser.add_argument("--self-test-only", action="store_true")
    args = parser.parse_args(argv)
    if args.rows < 1000:
        print("Refusing to generate fewer than 1000 rows.", file=sys.stderr)
        return 2
    brands = load_brands()
    run_self_tests(brands)
    if args.self_test_only:
        return 0
    rng = random.Random(args.seed)
    rows = generate_rows(brands, rng, args.rows)
    # generate_rows stamps a placeholder id before the seeded id is assigned.
    assign_ids(rows, args.seed)
    summary = validate_rows(rows, brands, args.seed)
    digest = write_dataset(rows, args.output, summary)
    print(json.dumps({"rows": summary["rows"], "sha256": digest, "labels": summary["label_counts"], "brands": summary["brands_used"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
