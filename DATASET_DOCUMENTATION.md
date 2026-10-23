# Synthetic URL dataset

This dataset is a controlled synthetic test set for ClickSafe. Every row is generated locally. Nothing in it is a real phishing report, and no generated URL was resolved or opened.

The labels describe the expected class inside this test environment. They do not say anything about the real-world reputation of a domain.

The scan uses the structured model trained from this file. This file does not by itself change a verdict. The previous TF-IDF model file remains in the package and is not the active prediction call.

## Files

| File | Role |
| --- | --- |
| `scripts/brand_reference.py` | Configurable list of brand names, tokens, categories, and reference domains |
| `scripts/generate_synthetic_dataset.py` | Reproducible generator |
| `ml_data/url_dataset.csv` | Generated dataset |
| `ml_data/url_dataset.meta.json` | Counts and SHA-256 for this run |
| `archive/previous_ml/` | Copies of the previous dataset, model, and scripts |

The CSV is under `ml_data/` because the repository gitignore ignores `data/`. Copies of the older training files are in `archive/previous_ml/`.

## Regenerate

From the repository root, using the backend environment (Python 3.12, no network, no pandas):

```powershell
backend\venv\Scripts\python.exe scripts\generate_synthetic_dataset.py --rows 10000 --seed 20261015
```

Self-checks only:

```powershell
backend\venv\Scripts\python.exe scripts\generate_synthetic_dataset.py --self-test-only
```

The default seed is `20261015`. The same seed and brand list produce the same file. Generator version for this run is `1.0.0`.

## This run

| Measure | Value |
| --- | --- |
| Rows | 10,000 |
| Unique record IDs | 10,000 |
| Unique URLs | 10,000 |
| Unique URLs after normalization | 10,000 |
| Duplicate normalized URLs | 0 |
| Reference brands | 168 |
| Brands used | 168 |
| Brands eligible for lookalikes | 155 |
| Rows with no brand | 1,660 |
| Unique registrable domains | 5,713 |
| Largest brand share | 72 rows |
| Smallest lookalike-capable brand | 38 rows |
| SHA-256 | `5e6ee554700e1c686a90469b5f096fce78f43a8fb9c6920405555b6195b9dd89` |
| File size | 2,949,221 bytes |

Label counts: legitimate 4,000, suspicious 3,000, malicious 3,000.

Reserved-suffix counts: `.test` 2,522, `.example` 2,501, `.invalid` 2,456, `.localhost` 2,521.

A second generation with the same command produced the same SHA-256.

## Brand reference

`scripts/brand_reference.py` is the source of the brand list. Edit that file to add or remove a brand. A brand needs a display name, a lowercase ASCII token, a category, and at least one reference domain.

Reference domains are widely published hostnames for that organization. They were not re-checked with WHOIS or live DNS for this run. The generator refuses to put any reference domain into a URL. An independent read of the CSV found no reference-domain string in any URL.

The token is the string used for synthetic hosts and lookalikes. It is not always the label of the reference domain:

| Brand | Token | Reference domains | Note |
| --- | --- | --- | --- |
| Steam | `steam` | `steampowered.com`, `steamcommunity.com` | Does not claim `steam.com` |
| Square | `square` | `squareup.com` | Does not claim `square.com` |
| Microsoft Azure | `azure` | `azure.microsoft.com` | Does not claim `azure.com` |
| npm | `npm` | `npmjs.com` | Does not claim `npm.com` |
| GOV.UK | `govuk` | `gov.uk` | Service name used as the synthetic token |
| USA.gov | `usagov` | `usa.gov` | Service name used as the synthetic token |
| Twitter / X | `twitter` | `twitter.com`, `x.com` | Lookalikes use `twitter` |
| American Airlines | `aa` | `aa.com` | Token is too short to impersonate |

Tokens shorter than 4 characters are kept as reference brands for legitimate and third-party rows only. They are IBM, AMD, HP, Box, CNN, npm, edX, MIT, IRS, NHS, American Airlines, UPS, and DHL. That is 13 brands. The other 155 can be used for lookalikes.

The generator does not apply every transform to every brand. Brand use is round-robin with a cap of 160 rows. In this run the busiest brand has 72 rows.

### Reference brands by category

| Category | Brands in the reference list | Rows that name the category |
| --- | --- | --- |
| search_and_technology | 22 | 1,033 |
| email_and_productivity | 21 | 1,031 |
| social_and_communication | 19 | 1,030 |
| banking_and_payments | 19 | 1,027 |
| shopping_and_marketplaces | 18 | 944 |
| streaming_and_entertainment | 16 | 858 |
| cloud_and_developer_tools | 14 | 680 |
| cryptocurrency_and_wallets | 10 | 517 |
| education_and_government | 13 | 549 |
| travel_food_and_services | 16 | 671 |

The row counts do not add to 10,000 because 1,660 rows have no brand.

## Labels

`legitimate` is a controlled benign example. The host uses the exact brand token under a reserved suffix, a third-party page mentions the brand only in the path or query, or the URL is a generic reserved host with no brand. These rows include long paths, digits, hyphens, deep subdomains, the letter pair `nn`, and words such as login, account, secure, and payment. In this run, 1,704 legitimate rows contain at least one suspicious keyword.

`suspicious` is one mild deceptive cue that should be investigated, not treated as a finished phishing page. Examples are a single digit substitution, one insertion, deletion, or transposition, `nn` standing in for `m` with a plain path, a single homoglyph, the exact brand placed in a subdomain, or extra digits or a hyphen glued to the brand. Keyword piles on a generic host, with no brand impersonation, are also suspicious rather than malicious.

`malicious` is a synthetic example with stronger phishing indicators. Typical rows combine a lookalike with a lure word, put the exact brand on a misleading host that also contains a lure, or stack two impersonation families with a lure. The word `login` is a token in 5.27% of malicious rows. Malicious rows in this run use at least 10 different suspicious keywords.

Real examples from this file:

- Legitimate `syn-20261015-00004`: `https://classroom.localhost/guide/uber?topic=uber`
- Suspicious `syn-20261015-00001`: `https://du0lingo.example/item/56415`
- Malicious `syn-20261015-00006`: `https://38ay.example/claim` (digit lookalike of the eBay token plus a lure path)

## Scenario counts

| generation_method | Rows | Label |
| --- | --- | --- |
| legit_brand_service | 1,600 | legitimate |
| legit_third_party | 1,200 | legitimate |
| legit_generic_noisy | 1,000 | legitimate |
| legit_innocent_nn | 200 | legitimate |
| numeric_mild | 500 | suspicious |
| keyword_odd_structure | 400 | suspicious |
| brand_subdomain_neutral | 300 | suspicious |
| insertion_mild | 280 | suspicious |
| deletion_mild | 280 | suspicious |
| unicode_mild | 250 | suspicious |
| transposition_mild | 220 | suspicious |
| double_n_mild | 200 | suspicious |
| repeat_mild | 200 | suspicious |
| hyphen_or_digit_label | 150 | suspicious |
| rn_for_m_mild | 120 | suspicious |
| excessive_odd_structure | 100 | suspicious |
| combined | 850 | malicious |
| structure_lure | 480 | malicious |
| numeric_strong | 450 | malicious |
| spelling_strong | 400 | malicious |
| unicode_strong | 320 | malicious |
| punycode_strong | 280 | malicious |
| double_n_strong | 220 | malicious |

`generation_method` is assigned with the label. It must not be a model input. The same is true of `record_id`, `source_type`, `label`, `reference_domain`, `split_group`, and `transformation_types`.

`source_type` is one of `reserved_brand_service`, `reserved_third_party_mention`, `reserved_generic`, and `reserved_impersonation`.

`split_group` is `brand:{token}` or `generic:{registrable label}`. Later training should use it for grouped splits so lookalikes of the same brand do not leak across train and test.

About 20% of rows in every class use `http`, and the rest use `https`. About 8% include a non-default port (`8080`, `8443`, or `4443`). Scheme and port are not class markers.

## Normalization

Two URLs are the same under this key:

1. Trim whitespace.
2. Drop the fragment.
3. Lowercase the scheme.
4. Casefold the host, strip a trailing dot, and encode each label with IDNA.
5. Drop port 80 for `http` and port 443 for `https`.
6. Ensure the path starts with `/`.
7. Strip a trailing slash when the path is longer than `/`.
8. Keep the query string in its original order.

Unicode and punycode forms of the same host share a key. The stored `url` stays in the form that was generated.

## Host parsing

`.test`, `.example`, `.invalid`, and `.localhost` are RFC 2606 reserved suffixes. The public suffix list used by `tldextract` does not treat them as suffixes, so the generator does not use `tldextract` for these hosts. The registrable domain is the last two hostname labels, and the subdomain count is the number of labels to the left of that.

`https://a.b.paypal.test/path` has registrable domain `paypal.test` and subdomain count 2.

## Empty cells

An empty cell means the measurement does not apply. It is not a zero that was filled in. Zero means the measurement was made and the count or flag is zero.

Brand-relative fields are empty when `brand_name` is empty. URL measurements such as length, digits, hyphens, keywords, homoglyphs, and punycode are always filled.

## Columns

`record_id`. Unique id `syn-20261015-#####`, assigned after the rows are shuffled.

`url`. Original synthetic URL.

`hostname`. Host without a port, casefolded. Unicode hosts stay in Unicode. Punycode hosts stay in punycode.

`registrable_domain`. Last two labels of `hostname`.

`brand_name`. Display name from the reference list, or empty.

`brand_category`. Category id, or empty.

`character_substitution_count`. On the chosen component, how many brand letters were replaced by a mapped digit while the length stayed the same. Mapped pairs are `o→0`, `l→1`, `i→1`, `e→3`, `s→5`, and the less common `a→4`, `t→7`, `b→8`, `g→9`. Homoglyphs are not counted here. Empty when there is no brand.

`zero_for_o_count`, `one_for_l_or_i_count`, `three_for_e_count`, `five_for_s_count`. The `o`, `l`/`i`, `e`, and `s` parts of that count. The extra `a/t/b/g` replacements are only in the total.

`double_n_for_m_indicator`. `1` only when some `nn` in the chosen component, replaced by one `m`, equals the brand token, the brand contains `m`, and the brand itself does not contain `nn`. `cnn` stays `0`. A word such as `annual` does not become `1` just because it contains `nn`. `rn` used as a visual stand-in for `m` stays `0` and is tagged `rn_for_m` instead. Empty when there is no brand. This run has 462 rows flagged `1`, and 538 rows that contain `nn` but are not flagged.

`repeated_character_count`. Adjacent identical characters in the IDNA-decoded hostname after dots are removed. This is always measured. `google` contributes 1 because of `oo`. `www` contributes 2. A legitimate `www` host can therefore have a non-zero count without being a lookalike.

`character_insertion_indicator`. `1` when deleting exactly one character from the chosen component produces the brand token. Repeated letters are insertions of this kind. An `nn`-for-`m` match is not counted as an insertion. Empty when there is no brand.

`character_deletion_indicator`. `1` when the brand token is the chosen component plus exactly one character. Empty when there is no brand.

`character_transposition_indicator`. `1` when the chosen component is the brand token with exactly one adjacent swap. Empty when there is no brand.

`homoglyph_indicator`. `1` when the IDNA-decoded hostname contains one of the generator's confusable characters: Cyrillic а, с, е, і, ј, о, р, ѕ, х, у (U+0430, U+0441, U+0435, U+0456, U+0458, U+043E, U+0440, U+0455, U+0445, U+0443). This is a small deliberate set, not every Unicode confusable. This run has 702 Unicode homoglyph rows and 412 punycode rows. A punycode row is also a homoglyph after decoding.

`mixed_script_indicator`. `1` when the decoded hostname letters use two or more of Latin, Cyrillic, Greek, fullwidth, or another script.

`punycode_indicator`. `1` when any hostname label in the stored URL starts with `xn--`.

`edit_distance`. Levenshtein distance between the brand token and the chosen component. Empty when there is no brand.

`brand_similarity_score`. `max(0, 1 - edit_distance / max(length))`, written with four decimal places. An exact token scores `1.0000`. That score also appears on legitimate brand hosts and on third-party mentions, so a perfect score is not itself malicious. Empty when there is no brand.

The chosen component is the hostname label, or hyphen-separated piece of a label, with the smallest edit distance to the token. Equal distances prefer the host. A path or query token is used only when it is strictly closer, which is how a third-party mention such as `/guide/uber` scores distance 0 while the host stays unrelated.

`digit_count`. ASCII digits in the full URL, including ports and path ids.

`hyphen_count`. ASCII `-` characters in the full URL. Punycode labels contain `--`, so a punycode URL has a higher hyphen count even when the decoded name has no hyphen.

`special_character_count`. Characters that are not ASCII letters or digits, not `-`, and not one of `: / ? # [ ] ! $ & ' ( ) * + , ; = . _ ~ %`. `@` counts as special. Non-ASCII homoglyphs count as special. A punycode host is ASCII, so its special count can be 0 while `homoglyph_indicator` is 1.

`subdomain_count`. Labels to the left of the registrable domain. Legitimate CDN-style hosts can have 4 or more. The count is evidence, not a label.

`suspicious_keyword_count`. Distinct tokens from this set, plus the phrases `sign-in`, `log-in`, `sign_in`, and `log_in` when they appear: account, billing, claim, confirm, credential, credentials, invoice, login, otp, password, payment, reset, secure, signin, support, suspend, suspended, unlock, update, verify, wallet, webscr. Matching is by token, so `linkedin` does not count as `login`, and `accounts` does not count as `account`.

`brand_in_subdomain`. `1` when a subdomain label, or a hyphen piece of one, equals the brand token. `login.paypal.test` is 0 because `paypal` is the registrable label. `paypal.news.test` is 1. Empty when there is no brand.

`misleading_domain_structure`. Always 0 or 1. It is 0 when the registrable label is exactly the brand token, including `secure.paypal.test` and `login.paypal.test`. It is 1 when the exact token sits in a subdomain of a different registrable label, or when the registrable label contains the token plus extra characters (`paypal-global`, `paypal4821`). With no brand, it is 1 only when the registrable label contains a suspicious keyword and also has a hyphen or at least one subdomain.

`url_length`. Character length of the stored URL.

`transformation_types`. Sorted, semicolon-separated audit tags. `none` when there is no tag. Tags are derived from the measurements above, plus `rn_for_m`, `digits_glued_to_brand`, and `hyphen_glued_to_brand` where the generator applied those specific shapes. A digit lookalike such as `du0lingo` also receives `digits_in_registrable_label` because the stored label really contains a digit. This column is an audit trail, not a model input.

`generation_method`. Scenario name from the table above.

`source_type`. Which synthetic family produced the row.

`label`. `legitimate`, `suspicious`, or `malicious`.

`reference_domain`. Reference hostnames joined with `|`, or empty. Not used inside the URL.

`split_group`. Grouping key for later train, validation, and test splits.

## What the generator varies

Numeric substitutions use one changed letter for suspicious rows and at least two for malicious rows. `rn` for `m` is included so a double letter is not always treated as `nn` for `m`. Spelling changes cover insertion, deletion, transposition, and a repeated letter. Unicode rows use the confusable table above, either as raw Unicode or as punycode. Domain-structure rows move the brand into a subdomain, glue digits or a hyphen onto it, or build a deep hyphenated generic host. Keyword rows use the lure list in the path, the query, or the hostname. Combined rows use at least two of those families plus a lure. Benign rows include exact brand hosts, third-party mentions, and noisy generic URLs.

## Archive of the previous project

`archive/previous_ml/` holds byte-for-byte copies of:

- `synthetic_dataset.csv` (the old 100,000-row `good`/`bad` file)
- `model.joblib` (the TF-IDF plus logistic regression pipeline)
- `generate_dataset.py`
- `train_model.py`

`archive/previous_ml/SHA256SUMS.txt` records the hashes. The previous model file at `backend/src/clicksafe/infrastructure/ml/models/model.joblib` was not changed. Its hash matches the archived `model.joblib` (`717888c0c9216e3c…`). The scan uses the structured bundle instead.

## Prediction-time features

`backend/src/clicksafe/infrastructure/ml/structured_url_features.py` is the shared measurement code. The dataset generator, the trainer, and the live scan all import it, so the feature definitions stay the same.

`extract_url_features(url)` parses one arbitrary URL. It does not read `label`, `record_id`, `generation_method`, `source_type`, `reference_domain`, `split_group`, or `transformation_types`.

Registrable domains for real hosts come from the Public Suffix List through `tldextract`, including private suffixes such as `blogspot.com`. The call uses the package's bundled snapshot and does not download a new list. Reserved suffixes still use the two-label rule in the host-parsing section above, because the public suffix list does not list them.

Pass the row's brand to reproduce a CSV measurement. Omit it and the extractor selects a brand:

- An exact token matches on a host label, a hyphen piece, or a path or query token. Host matches win over path matches.
- Lookalikes are host-only. A path word such as `user` is not treated as Uber.
- A suspicious keyword used as a host piece is not treated as a lookalike, so `password.example` is not read as a deletion of 1Password.
- Recognized transforms are digit maps (including the extra `a/t/b/g` maps), the curated homoglyph fold, `nn` or `rn` standing in for `m`, one insertion, one deletion, one adjacent transposition, a token glued to digits, or a token as a hyphen piece.
- One unexplained host edit of distance 1 is also accepted. A recognized transform outranks that raw edit.

`rn_for_m_indicator` is part of the model feature list and is computed for every URL. It is not a column in the CSV. The other model features are the numeric and indicator columns already in the CSV. Empty brand measurements stay empty. They are not filled with zero. No imputer is fit in this module. Fitting one, if a model needs it, has to happen on the training split only.

On this 10,000-row file, automatic selection returns the recorded brand for 9,998 rows. The two exceptions are both the host piece `noton`. That string is one deletion from Notion and one deletion from Norton. The selector's tie break chooses Norton. The CSV records Notion, because that is the brand the generator started from. Passing the recorded brand still reproduces the CSV features for those rows.

The scan loads `models/structured_url_model.joblib` through `StructuredUrlClassifier` and calls this module for every URL. This module does not assign a verdict. The previous TF-IDF file remains at `backend/src/clicksafe/infrastructure/ml/models/model.joblib` and is not the active prediction call.

## Limitations

- The class sizes and scenario sizes are chosen by the generator. High accuracy on this file would not show real-world phishing detection performance.
- `generation_method` identifies the label. Training must ignore the metadata columns listed above.
- Many suspicious rows differ from a brand by one controlled edit. A later model can memorize those families. Grouped splits on `split_group` are required before any score is treated as evidence.
- Every host uses a reserved suffix. The suffix itself must not be learned as a sign of phishing or of safety.
- The homoglyph inventory is small. Other Unicode confusables are absent.
- Reference domains were curated from commonly published hostnames and were not freshly verified with WHOIS.
- Some synthetic tokens differ from the organization's real registrable label, as in the table above.
- `www` increases `repeated_character_count`. Punycode increases `hyphen_count`.
- There is no page content, DNS, certificate, or reputation data in these rows.
- The scan scores with these features. The previous `model.joblib` file was not overwritten. Probabilities from the structured model are uncalibrated and do not set the verdict.
- Automatic brand selection and the generator's source brand disagree on two `noton` rows, described above. Training should decide whether to pass the recorded brand or to use automatic selection, and then use that same choice at prediction time.
- Substring containment alone is not an automatic brand match. `evilpaypal.blogspot.com` does not select PayPal. If a caller already knows the brand, `misleading_domain_structure` can still be 1 because the known token occurs inside the label.
