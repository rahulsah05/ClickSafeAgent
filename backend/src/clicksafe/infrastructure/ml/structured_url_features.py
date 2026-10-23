"""Prediction-time features for structured URL brand impersonation.

The synthetic dataset generator and any later training or scan path must call
this module. It does not read labels, record ids, or generation metadata, and
it does not score risk or load a model.

Registrable domains use the Public Suffix List through tldextract, including
private suffixes such as blogspot.com. RFC 2606 names (.test, .example,
.invalid, .localhost) are not public suffixes, so those hosts use the same
two-label rule as the dataset generator. The bundled suffix snapshot is used
and this module does not fetch an updated list.

Missing brand measurements stay None. They are not filled with zero.
"""

from __future__ import annotations

import importlib.util
import ipaddress
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Protocol, Sequence
from urllib.parse import unquote, urlsplit, urlunsplit

import idna
import tldextract

FEATURE_SCHEMA_VERSION = "1.0.0"
MIN_IMPERSONATION_LENGTH = 4
RESERVED_SUFFIXES = ("test", "example", "invalid", "localhost")

METADATA_COLUMNS = (
    "record_id",
    "generation_method",
    "source_type",
    "label",
    "reference_domain",
    "split_group",
    "transformation_types",
)

# Columns stored on dataset rows. rn_for_m_indicator is computed for train and
# predict but is not a column in the already generated CSV.
DATASET_FEATURE_COLUMNS = (
    "character_substitution_count",
    "zero_for_o_count",
    "one_for_l_or_i_count",
    "three_for_e_count",
    "five_for_s_count",
    "double_n_for_m_indicator",
    "repeated_character_count",
    "character_insertion_indicator",
    "character_deletion_indicator",
    "character_transposition_indicator",
    "homoglyph_indicator",
    "mixed_script_indicator",
    "punycode_indicator",
    "edit_distance",
    "brand_similarity_score",
    "digit_count",
    "hyphen_count",
    "special_character_count",
    "subdomain_count",
    "suspicious_keyword_count",
    "brand_in_subdomain",
    "misleading_domain_structure",
    "url_length",
)

MODEL_FEATURE_COLUMNS = DATASET_FEATURE_COLUMNS + ("rn_for_m_indicator",)

IDENTITY_COLUMNS = (
    "hostname",
    "registrable_domain",
    "brand_name",
    "brand_category",
)

COLUMNS = (
    "record_id",
    "url",
    "hostname",
    "registrable_domain",
    "brand_name",
    "brand_category",
    *DATASET_FEATURE_COLUMNS,
    "transformation_types",
    "generation_method",
    "source_type",
    "label",
    "reference_domain",
    "split_group",
)

PRIMARY_DIGITS = {"o": "0", "l": "1", "i": "1", "e": "3", "s": "5"}
EXTRA_DIGITS = {"a": "4", "t": "7", "b": "8", "g": "9"}
CONFUSABLES = {
    "a": "\u0430",
    "c": "\u0441",
    "e": "\u0435",
    "i": "\u0456",
    "j": "\u0458",
    "o": "\u043e",
    "p": "\u0440",
    "s": "\u0455",
    "x": "\u0445",
    "y": "\u0443",
}
CONFUSABLE_CHARS = frozenset(CONFUSABLES.values())
CONFUSABLE_FOLD = {confusable: latin for latin, confusable in CONFUSABLES.items()}
SUSPICIOUS_KEYWORDS = frozenset(
    {
        "account",
        "billing",
        "claim",
        "confirm",
        "credential",
        "credentials",
        "invoice",
        "login",
        "otp",
        "password",
        "payment",
        "reset",
        "secure",
        "signin",
        "support",
        "suspend",
        "suspended",
        "unlock",
        "update",
        "verify",
        "wallet",
        "webscr",
    }
)
KEYWORD_PHRASES = ("sign-in", "log-in", "sign_in", "log_in")
STRUCTURAL_CHARACTERS = set(":/?#[]!$&'()*+,;=._~%")
TOKEN_RE = re.compile(r"[a-z0-9]+")
GENERATOR_ONLY_TAGS = frozenset(
    {"rn_for_m", "digits_glued_to_brand", "hyphen_glued_to_brand"}
)

_EXTRACTOR = tldextract.TLDExtract(
    cache_dir=None,
    suffix_list_urls=(),
    fallback_to_snapshot=True,
    include_psl_private_domains=True,
)


class BrandLike(Protocol):
    brand_name: str
    token: str
    category: str

    @property
    def reference_domain(self) -> str: ...


@dataclass(frozen=True, slots=True)
class BrandRecord:
    brand_name: str
    token: str
    category: str
    reference_domains: tuple[str, ...]

    @property
    def reference_domain(self) -> str:
        return "|".join(self.reference_domains)


@dataclass(frozen=True, slots=True)
class ParsedUrl:
    url: str
    hostname: str
    raw_labels: tuple[str, ...]
    decoded_labels: tuple[str, ...]
    suffix: str
    registrable_domain: str
    registrable_label: str
    subdomain_labels: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class UrlFeatures:
    """One URL measured with the shared feature definitions.

    `features` contains only MODEL_FEATURE_COLUMNS. Identity and match fields
    sit beside it so a later model can ignore them.
    """

    original_url: str
    normalized_url: str | None
    parse_error: str | None
    hostname: str | None
    registrable_domain: str | None
    registrable_label: str | None
    suffix: str | None
    brand_name: str | None
    brand_category: str | None
    brand_token: str | None
    matched_component: str | None
    match_source: str | None
    match_reason: str | None
    reference_domain: str | None
    split_group: str | None
    transformation_types: str | None
    features: dict[str, int | float | None]


def edit_distance(left: str, right: str) -> int:
    if left == right:
        return 0
    if not left:
        return len(right)
    if not right:
        return len(left)
    previous = list(range(len(right) + 1))
    for index, left_char in enumerate(left, start=1):
        current = [index]
        for right_index, right_char in enumerate(right, start=1):
            insert_cost = current[right_index - 1] + 1
            delete_cost = previous[right_index] + 1
            replace_cost = previous[right_index - 1] + (left_char != right_char)
            current.append(min(insert_cost, delete_cost, replace_cost))
        previous = current
    return previous[-1]


def decode_label(label: str) -> str:
    if label.startswith("xn--"):
        try:
            return idna.decode(label)
        except idna.IDNAError:
            return label
    return label


def encode_label(label: str) -> str:
    try:
        return idna.encode(label).decode("ascii")
    except idna.IDNAError:
        return label


def normalize_url(url: str) -> str:
    """Uniqueness key.

    Lowercase the scheme and host, encode the host as punycode, drop the
    fragment, drop a default port, and strip a trailing slash from a non-root
    path. The query string is kept in its original order.
    """

    parts = urlsplit(url.strip())
    if not parts.scheme or parts.hostname is None:
        raise ValueError(f"Cannot normalize URL: {url}")
    labels = parts.hostname.rstrip(".").casefold().split(".")
    if any(label == "" for label in labels):
        raise ValueError(f"Empty hostname label: {url}")
    host = ".".join(encode_label(label) for label in labels)
    port = parts.port
    netloc = host
    if port and not (
        (parts.scheme == "http" and port == 80) or (parts.scheme == "https" and port == 443)
    ):
        netloc = f"{host}:{port}"
    path = parts.path or "/"
    if not path.startswith("/"):
        path = "/" + path
    if len(path) > 1 and path.endswith("/"):
        path = path[:-1]
    return urlunsplit((parts.scheme.casefold(), netloc, path, parts.query, ""))


def is_ip_hostname(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        return False
    return True


def _reserved_parsed(url: str, hostname: str, raw_labels: tuple[str, ...]) -> ParsedUrl:
    decoded = tuple(decode_label(label) for label in raw_labels)
    return ParsedUrl(
        url=url,
        hostname=hostname,
        raw_labels=raw_labels,
        decoded_labels=decoded,
        suffix=raw_labels[-1],
        registrable_domain=".".join(raw_labels[-2:]),
        registrable_label=decoded[-2],
        subdomain_labels=decoded[:-2],
    )


def parse_url(url: str) -> ParsedUrl:
    """Parse a dataset URL. The host must use an RFC 2606 suffix."""

    parts = urlsplit(url.strip())
    if parts.hostname is None or parts.scheme not in {"http", "https"}:
        raise ValueError(f"Unusable URL: {url}")
    hostname = parts.hostname.rstrip(".").casefold()
    raw_labels = tuple(hostname.split("."))
    if len(raw_labels) < 2 or raw_labels[-1] not in RESERVED_SUFFIXES:
        raise ValueError(f"URL is not under a reserved suffix: {url}")
    if any(label == "" for label in raw_labels):
        raise ValueError(f"Empty hostname label: {url}")
    return _reserved_parsed(url.strip(), hostname, raw_labels)


def parse_public_url(url: str) -> ParsedUrl:
    """Parse an http(s) URL with public-suffix rules.

    Reserved suffixes keep the dataset's two-label registrable domain so a
    synthetic row and a live call measure the same host.
    """

    parts = urlsplit(url.strip())
    if parts.hostname is None or parts.scheme not in {"http", "https"}:
        raise ValueError(f"Unusable URL: {url}")
    hostname = parts.hostname.rstrip(".").casefold()
    if is_ip_hostname(hostname):
        return ParsedUrl(
            url=url.strip(),
            hostname=hostname,
            raw_labels=(hostname,),
            decoded_labels=(hostname,),
            suffix="",
            registrable_domain=hostname,
            registrable_label=hostname,
            subdomain_labels=(),
        )
    raw_labels = tuple(hostname.split("."))
    if any(label == "" for label in raw_labels):
        raise ValueError(f"Empty hostname label: {url}")
    if raw_labels[-1] in RESERVED_SUFFIXES and len(raw_labels) >= 2:
        return _reserved_parsed(url.strip(), hostname, raw_labels)
    if raw_labels[-1] in RESERVED_SUFFIXES:
        return ParsedUrl(
            url=url.strip(),
            hostname=hostname,
            raw_labels=raw_labels,
            decoded_labels=tuple(decode_label(label) for label in raw_labels),
            suffix=raw_labels[-1],
            registrable_domain=hostname,
            registrable_label="",
            subdomain_labels=(),
        )
    extracted = _EXTRACTOR(hostname)
    domain = extracted.domain.casefold()
    suffix = extracted.suffix.casefold()
    if not domain and not suffix:
        raise ValueError(f"Unusable URL: {url}")
    registrable_label = decode_label(domain) if domain else ""
    if domain and suffix:
        registrable_domain = f"{domain}.{suffix}"
    else:
        registrable_domain = domain or suffix
    subdomain_labels = tuple(
        decode_label(label) for label in extracted.subdomain.casefold().split(".") if label
    )
    return ParsedUrl(
        url=url.strip(),
        hostname=hostname,
        raw_labels=raw_labels,
        decoded_labels=tuple(decode_label(label) for label in raw_labels),
        suffix=suffix,
        registrable_domain=registrable_domain,
        registrable_label=registrable_label,
        subdomain_labels=subdomain_labels,
    )


def repeated_character_count(text: str) -> int:
    flat = text.replace(".", "")
    return sum(1 for left, right in zip(flat, flat[1:]) if left == right)


def keyword_count(url: str) -> int:
    decoded = unquote(url).casefold()
    found = set(TOKEN_RE.findall(decoded)) & SUSPICIOUS_KEYWORDS
    for phrase in KEYWORD_PHRASES:
        if phrase in decoded:
            found.add(phrase)
    return len(found)


def special_character_count(url: str) -> int:
    count = 0
    for character in url:
        if character.isascii() and (
            character.isalnum() or character == "-" or character in STRUCTURAL_CHARACTERS
        ):
            continue
        count += 1
    return count


def scripts_in(text: str) -> set[str]:
    found: set[str] = set()
    for character in text:
        if not character.isalpha():
            continue
        code = ord(character)
        if "a" <= character <= "z" or "A" <= character <= "Z":
            found.add("latin")
        elif 0x0400 <= code <= 0x04FF:
            found.add("cyrillic")
        elif 0x0370 <= code <= 0x03FF:
            found.add("greek")
        elif 0xFF00 <= code <= 0xFFEF:
            found.add("fullwidth")
        else:
            found.add("other")
    return found


def _pair_collapses_to_brand(candidate: str, brand: str, pair: str, replacement: str) -> bool:
    if pair not in candidate or replacement not in brand or pair in brand:
        return False
    start = 0
    while True:
        index = candidate.find(pair, start)
        if index < 0:
            return False
        collapsed = candidate[:index] + replacement + candidate[index + len(pair) :]
        if collapsed == brand:
            return True
        start = index + 1


def nn_imitates_m(candidate: str, brand: str) -> bool:
    """True only when replacing an nn pair with m reproduces the brand token.

    An nn that already belongs to the brand, or an nn that does not collapse
    back to that brand, stays false.
    """

    return _pair_collapses_to_brand(candidate, brand, "nn", "m")


def rn_imitates_m(candidate: str, brand: str) -> bool:
    """True only when replacing an rn pair with m reproduces the brand token."""

    return _pair_collapses_to_brand(candidate, brand, "rn", "m")


def is_single_insertion(candidate: str, brand: str) -> bool:
    if nn_imitates_m(candidate, brand) or len(candidate) != len(brand) + 1:
        return False
    return any(
        candidate[:index] + candidate[index + 1 :] == brand for index in range(len(candidate))
    )


def is_single_deletion(candidate: str, brand: str) -> bool:
    if len(brand) != len(candidate) + 1:
        return False
    return any(brand[:index] + brand[index + 1 :] == candidate for index in range(len(brand)))


def is_adjacent_transposition(candidate: str, brand: str) -> bool:
    if len(candidate) != len(brand) or candidate == brand:
        return False
    diffs = [index for index, (left, right) in enumerate(zip(candidate, brand)) if left != right]
    if len(diffs) != 2 or diffs[1] != diffs[0] + 1:
        return False
    left, right = diffs
    return candidate[left] == brand[right] and candidate[right] == brand[left]


def substitution_counts(candidate: str, brand: str) -> dict[str, int]:
    counts = {"total": 0, "zero": 0, "one": 0, "three": 0, "five": 0, "other": 0}
    if len(candidate) != len(brand):
        return counts
    for brand_char, candidate_char in zip(brand, candidate):
        if brand_char == candidate_char:
            continue
        if brand_char == "o" and candidate_char == "0":
            counts["zero"] += 1
        elif brand_char in {"l", "i"} and candidate_char == "1":
            counts["one"] += 1
        elif brand_char == "e" and candidate_char == "3":
            counts["three"] += 1
        elif brand_char == "s" and candidate_char == "5":
            counts["five"] += 1
        elif brand_char in EXTRA_DIGITS and candidate_char == EXTRA_DIGITS[brand_char]:
            counts["other"] += 1
    counts["total"] = (
        counts["zero"] + counts["one"] + counts["three"] + counts["five"] + counts["other"]
    )
    return counts


def is_digit_lookalike(candidate: str, brand: str) -> bool:
    if len(candidate) != len(brand) or candidate == brand:
        return False
    counts = substitution_counts(candidate, brand)
    differences = sum(left != right for left, right in zip(candidate, brand))
    return differences > 0 and counts["total"] == differences


def fold_confusables(text: str) -> str:
    return "".join(CONFUSABLE_FOLD.get(character, character) for character in text)


def host_components(labels: tuple[str, ...] | list[str]) -> list[str]:
    parts: list[str] = []
    for label in labels:
        if not label:
            continue
        parts.append(label)
        parts.extend(piece for piece in label.split("-") if piece and piece != label)
    return parts


def brand_host_labels(parsed: ParsedUrl) -> tuple[str, ...]:
    """Labels that can carry a brand, after the public suffix is removed."""

    labels = list(parsed.subdomain_labels)
    if parsed.registrable_label:
        labels.append(parsed.registrable_label)
    return tuple(labels)


def choose_component(parsed: ParsedUrl, path: str, query: str, token: str) -> str:
    host_parts = host_components(brand_host_labels(parsed))
    host_scored = [
        (edit_distance(token, part), abs(len(part) - len(token)), part) for part in host_parts
    ]
    path_tokens = TOKEN_RE.findall(f"{path}?{query}".casefold())
    path_scored = [
        (edit_distance(token, part), abs(len(part) - len(token)), part) for part in path_tokens
    ]
    best_host = min(host_scored) if host_scored else (99, 99, "")
    best_path = min(path_scored) if path_scored else None
    if best_path is None or best_host[0] <= best_path[0]:
        return best_host[2]
    return best_path[2]


def component_source(parsed: ParsedUrl, path: str, query: str, token: str) -> str:
    component = choose_component(parsed, path, query, token)
    if not component:
        return "none"
    if component in host_components(brand_host_labels(parsed)):
        return "host"
    return "path"


def brand_in_subdomain(parsed: ParsedUrl, token: str) -> bool:
    for label in parsed.subdomain_labels:
        if token == label or token in label.split("-"):
            return True
    return False


def misleading_structure(parsed: ParsedUrl, token: str | None) -> int:
    registrable = parsed.registrable_label
    if token:
        if registrable == token:
            return 0
        parts = [part for part in registrable.split("-") if part]
        if token in parts or token in registrable:
            return 1
        for label in parsed.subdomain_labels:
            if token == label or token in label.split("-"):
                return 1
        return 0
    registrable_tokens = set(registrable.split("-"))
    if registrable_tokens & SUSPICIOUS_KEYWORDS and (
        "-" in registrable or len(parsed.subdomain_labels) >= 1
    ):
        return 1
    return 0


def similarity(distance: int, left: str, right: str) -> float:
    denominator = max(len(left), len(right))
    if denominator == 0:
        return 0.0
    return max(0.0, 1.0 - (distance / denominator))


def derived_tags(row: dict[str, object], parsed: ParsedUrl, extra_tags: list[str]) -> str:
    tags = set(extra_tags)
    if row["character_substitution_count"]:
        tags.add("numeric_substitution")
    if row["zero_for_o_count"]:
        tags.add("zero_for_o")
    if row["one_for_l_or_i_count"]:
        tags.add("one_for_l_or_i")
    if row["three_for_e_count"]:
        tags.add("three_for_e")
    if row["five_for_s_count"]:
        tags.add("five_for_s")
    if int(row["character_substitution_count"] or 0) > (
        int(row["zero_for_o_count"] or 0)
        + int(row["one_for_l_or_i_count"] or 0)
        + int(row["three_for_e_count"] or 0)
        + int(row["five_for_s_count"] or 0)
    ):
        tags.add("other_numeric_substitution")
    if row["double_n_for_m_indicator"]:
        tags.add("double_n_for_m")
    if row["character_insertion_indicator"]:
        tags.add("character_insertion")
    if row["character_deletion_indicator"]:
        tags.add("character_deletion")
    if row["character_transposition_indicator"]:
        tags.add("character_transposition")
    if row["homoglyph_indicator"]:
        tags.add("homoglyph")
    if row["mixed_script_indicator"]:
        tags.add("mixed_script")
    if row["punycode_indicator"]:
        tags.add("punycode")
    if row["brand_in_subdomain"]:
        tags.add("brand_in_subdomain")
    if row["misleading_domain_structure"]:
        tags.add("misleading_domain_structure")
    if row["suspicious_keyword_count"]:
        tags.add("suspicious_keyword")
    if int(row["subdomain_count"]) >= 4:
        tags.add("excessive_subdomains")
    if "-" in parsed.registrable_label:
        tags.add("hyphenated_registrable_label")
    if any(character.isdigit() for character in parsed.registrable_label):
        tags.add("digits_in_registrable_label")
    if not tags:
        return "none"
    return ";".join(sorted(tags))


def _measure_parsed(
    url: str,
    parsed: ParsedUrl,
    brand: BrandLike | None,
    extra_tags: list[str] | None = None,
) -> dict[str, object]:
    parts = urlsplit(parsed.url)
    path = parts.path or "/"
    query = parts.query
    token = brand.token if brand is not None else None
    component = choose_component(parsed, path, query, token) if token else ""
    counts = substitution_counts(component, token) if token else None
    distance = edit_distance(token, component) if token else None
    insertion = int(is_single_insertion(component, token)) if token else None
    deletion = int(is_single_deletion(component, token)) if token else None
    transposition = int(is_adjacent_transposition(component, token)) if token else None
    double_n = int(nn_imitates_m(component, token)) if token else None
    rn_for_m = int(rn_imitates_m(component, token)) if token else None
    decoded_host = ".".join(parsed.decoded_labels)
    homoglyph = int(any(character in CONFUSABLE_CHARS for character in decoded_host))
    mixed = int(len(scripts_in(decoded_host)) >= 2)
    punycode = int(any(label.startswith("xn--") for label in parsed.raw_labels))
    row: dict[str, object] = {
        "url": parsed.url,
        "hostname": parsed.hostname,
        "registrable_domain": parsed.registrable_domain,
        "brand_name": brand.brand_name if brand else None,
        "brand_category": brand.category if brand else None,
        "character_substitution_count": None if counts is None else counts["total"],
        "zero_for_o_count": None if counts is None else counts["zero"],
        "one_for_l_or_i_count": None if counts is None else counts["one"],
        "three_for_e_count": None if counts is None else counts["three"],
        "five_for_s_count": None if counts is None else counts["five"],
        "double_n_for_m_indicator": double_n,
        "rn_for_m_indicator": rn_for_m,
        "repeated_character_count": repeated_character_count(decoded_host),
        "character_insertion_indicator": insertion,
        "character_deletion_indicator": deletion,
        "character_transposition_indicator": transposition,
        "homoglyph_indicator": homoglyph,
        "mixed_script_indicator": mixed,
        "punycode_indicator": punycode,
        "edit_distance": distance,
        "brand_similarity_score": None
        if distance is None
        else round(similarity(distance, token or "", component), 4),
        "digit_count": sum(character.isdigit() and character.isascii() for character in url),
        "hyphen_count": url.count("-"),
        "special_character_count": special_character_count(url),
        "subdomain_count": len(parsed.subdomain_labels),
        "suspicious_keyword_count": keyword_count(url),
        "brand_in_subdomain": None if token is None else int(brand_in_subdomain(parsed, token)),
        "misleading_domain_structure": misleading_structure(parsed, token),
        "url_length": len(url.strip()),
        "reference_domain": brand.reference_domain if brand else None,
        "split_group": (
            f"brand:{token}" if token else f"generic:{parsed.registrable_label}"
        ),
        "_component": component,
        "_parsed": parsed,
    }
    row["transformation_types"] = derived_tags(row, parsed, extra_tags or [])
    return row


def measure(
    url: str,
    brand: BrandLike | None,
    generation_method: str,
    source_type: str,
    label: str,
    extra_tags: list[str] | None = None,
) -> dict[str, object]:
    """Measure one reserved-suffix URL the way the dataset generator does."""

    parsed = parse_url(url)
    row = _measure_parsed(url, parsed, brand, extra_tags)
    row["generation_method"] = generation_method
    row["source_type"] = source_type
    row["label"] = label
    row["brand_obj"] = brand
    return row


def _token_glued(registrable: str, token: str) -> bool:
    if not token or registrable == token:
        return False
    parts = [part for part in registrable.split("-") if part]
    if token in parts:
        return True
    if registrable.startswith(token) and registrable[len(token) :].isdigit():
        return True
    return registrable.endswith(token) and registrable[: -len(token)].isdigit()


def atomic_host_parts(parsed: ParsedUrl) -> list[str]:
    """Host labels split on hyphens. The public suffix is already removed."""

    parts: list[str] = []
    for label in brand_host_labels(parsed):
        parts.extend(piece for piece in label.split("-") if piece)
    return parts


_REASON_RANK = {
    "exact": 0,
    "digit_lookalike": 1,
    "homoglyph": 1,
    "double_n_for_m": 1,
    "rn_for_m": 1,
    "transposition": 1,
    "insertion": 1,
    "deletion": 1,
    "structural": 2,
    "edit_distance": 3,
}


def _component_reason(part: str, token: str) -> str | None:
    """Recognize one host piece as a lookalike of one token.

    A piece that is itself a suspicious keyword is not a lookalike. That keeps
    a host such as password.example from being read as a deletion of 1password.
    """

    if not part or part == token or part in SUSPICIOUS_KEYWORDS:
        return None
    if len(token) < MIN_IMPERSONATION_LENGTH:
        return None
    folded = fold_confusables(part)
    if folded == token and folded != part:
        return "homoglyph"
    if is_digit_lookalike(folded, token):
        return "digit_lookalike"
    if nn_imitates_m(part, token):
        return "double_n_for_m"
    if rn_imitates_m(part, token):
        return "rn_for_m"
    if is_adjacent_transposition(part, token):
        return "transposition"
    if is_single_insertion(part, token):
        return "insertion"
    if is_single_deletion(part, token):
        return "deletion"
    if edit_distance(part, token) == 1:
        return "edit_distance"
    return None


def select_brand(
    parsed: ParsedUrl,
    path: str,
    query: str,
    catalog: Sequence[BrandLike],
) -> tuple[BrandLike | None, str | None]:
    """Pick one catalog brand for an arbitrary URL.

    Exact tokens match on the host or in the path. Lookalikes match only on
    host pieces, so a path word such as user does not become Uber. A recognized
    transform outranks a raw one-edit difference. Ties then prefer the longer
    token and a stable brand name.
    """

    by_token = {brand.token: brand for brand in catalog}
    host_parts = atomic_host_parts(parsed)
    exact: list[tuple[int, int, str, BrandLike]] = []
    for part in host_parts:
        brand = by_token.get(part)
        if brand is not None:
            exact.append((0, -len(brand.token), brand.brand_name, brand))
    path_tokens = TOKEN_RE.findall(f"{path}?{query}".casefold())
    for part in path_tokens:
        brand = by_token.get(part)
        if brand is not None:
            exact.append((1, -len(brand.token), brand.brand_name, brand))
    if exact:
        exact.sort()
        return exact[0][3], "exact"

    by_length: dict[int, list[BrandLike]] = {}
    for brand in catalog:
        if len(brand.token) < MIN_IMPERSONATION_LENGTH:
            continue
        by_length.setdefault(len(brand.token), []).append(brand)

    scored: list[tuple[int, int, int, str, BrandLike, str]] = []
    for part in host_parts:
        if part in SUSPICIOUS_KEYWORDS:
            continue
        for token_length in (len(part) - 1, len(part), len(part) + 1):
            for brand in by_length.get(token_length, []):
                reason = _component_reason(part, brand.token)
                if reason is None:
                    continue
                scored.append(
                    (
                        _REASON_RANK[reason],
                        edit_distance(brand.token, part),
                        -len(brand.token),
                        brand.brand_name,
                        brand,
                        reason,
                    )
                )
    for label in brand_host_labels(parsed):
        if "-" not in label and not any(character.isdigit() for character in label):
            continue
        for brand in catalog:
            if len(brand.token) < MIN_IMPERSONATION_LENGTH:
                continue
            if not _token_glued(label, brand.token):
                continue
            scored.append(
                (
                    _REASON_RANK["structural"],
                    edit_distance(brand.token, label),
                    -len(brand.token),
                    brand.brand_name,
                    brand,
                    "structural",
                )
            )
    if not scored:
        return None, None
    scored.sort()
    return scored[0][4], scored[0][5]


def match_reason(parsed: ParsedUrl, path: str, query: str, brand: BrandLike) -> str | None:
    """Whether this one brand would be selected from a catalog containing only it."""

    _chosen, reason = select_brand(parsed, path, query, (brand,))
    return reason


def _string_features(url: str) -> dict[str, int | float | None]:
    features: dict[str, int | float | None] = {column: None for column in MODEL_FEATURE_COLUMNS}
    features["digit_count"] = sum(character.isdigit() and character.isascii() for character in url)
    features["hyphen_count"] = url.count("-")
    features["special_character_count"] = special_character_count(url)
    features["suspicious_keyword_count"] = keyword_count(url)
    features["url_length"] = len(url)
    return features


def _feature_dict(row: dict[str, object]) -> dict[str, int | float | None]:
    features: dict[str, int | float | None] = {}
    for column in MODEL_FEATURE_COLUMNS:
        value = row[column]
        if value is None or isinstance(value, (int, float)):
            features[column] = value
        else:
            raise TypeError(f"Feature {column} has unsupported type {type(value).__name__}")
    return features


def extract_url_features(
    url: object,
    brand: BrandLike | None = None,
    *,
    catalog: Sequence[BrandLike] | None = None,
    select: bool = True,
) -> UrlFeatures:
    """Extract features for an arbitrary URL.

    Pass `brand` to reproduce a dataset row. Omit it to select a brand from
    the reference catalog. The same measurement function runs either way.
    """

    if not isinstance(url, str):
        return _unparsed("", "not_a_string")
    stripped = url.strip()
    if not stripped:
        return _unparsed(url, "empty")
    try:
        normalized = normalize_url(stripped)
    except ValueError:
        normalized = None
    try:
        parsed = parse_public_url(stripped)
    except ValueError as exc:
        message = str(exc)
        if "Empty hostname label" in message:
            code = "empty_label"
        elif "Unusable URL" in message:
            code = "unusable_url"
        else:
            code = "unparsed"
        result = _unparsed(stripped, code)
        return UrlFeatures(
            original_url=stripped,
            normalized_url=normalized,
            parse_error=result.parse_error,
            hostname=None,
            registrable_domain=None,
            registrable_label=None,
            suffix=None,
            brand_name=None,
            brand_category=None,
            brand_token=None,
            matched_component=None,
            match_source=None,
            match_reason=None,
            reference_domain=None,
            split_group=None,
            transformation_types=None,
            features=result.features,
        )

    parts = urlsplit(parsed.url)
    path = parts.path or "/"
    query = parts.query
    reason: str | None
    if brand is not None:
        chosen: BrandLike | None = brand
        reason = "supplied"
    elif select:
        chosen, reason = select_brand(parsed, path, query, catalog or default_brand_catalog())
    else:
        chosen = None
        reason = None
    row = _measure_parsed(stripped, parsed, chosen)
    component = str(row["_component"])
    source = component_source(parsed, path, query, chosen.token) if chosen is not None else "none"
    return UrlFeatures(
        original_url=stripped,
        normalized_url=normalized,
        parse_error=None,
        hostname=parsed.hostname,
        registrable_domain=parsed.registrable_domain,
        registrable_label=parsed.registrable_label,
        suffix=parsed.suffix,
        brand_name=chosen.brand_name if chosen else None,
        brand_category=chosen.category if chosen else None,
        brand_token=chosen.token if chosen else None,
        matched_component=component or None,
        match_source=source,
        match_reason=reason,
        reference_domain=str(row["reference_domain"]) if row["reference_domain"] else None,
        split_group=str(row["split_group"]),
        transformation_types=str(row["transformation_types"]),
        features=_feature_dict(row),
    )


def _unparsed(url: str, code: str) -> UrlFeatures:
    text = url.strip() if isinstance(url, str) else ""
    return UrlFeatures(
        original_url=text,
        normalized_url=None,
        parse_error=code,
        hostname=None,
        registrable_domain=None,
        registrable_label=None,
        suffix=None,
        brand_name=None,
        brand_category=None,
        brand_token=None,
        matched_component=None,
        match_source=None,
        match_reason=None,
        reference_domain=None,
        split_group=None,
        transformation_types=None,
        features=_string_features(text),
    )


def freeze_feature(value: object) -> str:
    """CSV cell for a measurement. None is an empty cell, not the word None."""

    if value is None:
        return ""
    if isinstance(value, float):
        return f"{value:.4f}"
    return str(value)


def dataset_path() -> Path:
    return brand_reference_path().parents[1] / "ml_data" / "url_dataset.csv"


def brand_reference_path() -> Path:
    for parent in Path(__file__).resolve().parents:
        candidate = parent / "scripts" / "brand_reference.py"
        if candidate.is_file():
            return candidate
    raise FileNotFoundError("scripts/brand_reference.py was not found")


def load_brand_catalog(path: Path | None = None) -> tuple[BrandRecord, ...]:
    brand_path = path or brand_reference_path()
    spec = importlib.util.spec_from_file_location("clicksafe_brand_reference", brand_path)
    if spec is None or spec.loader is None:
        raise FileNotFoundError(brand_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    records: list[BrandRecord] = []
    seen_tokens: set[str] = set()
    for brand_name, token, category, domains in module.BRAND_ROWS:
        if token in seen_tokens:
            raise ValueError(f"Duplicate brand token: {token}")
        seen_tokens.add(token)
        records.append(
            BrandRecord(
                brand_name=brand_name,
                token=token,
                category=category,
                reference_domains=tuple(domains),
            )
        )
    return tuple(records)


@lru_cache(maxsize=1)
def default_brand_catalog() -> tuple[BrandRecord, ...]:
    return load_brand_catalog()


def model_feature_record(features: UrlFeatures) -> dict[str, int | float | None]:
    """The only fields a later model may read from an extraction result."""

    return {column: features.features[column] for column in MODEL_FEATURE_COLUMNS}
