# Structured URL model evaluation

These figures are from one local training run on the synthetic dataset. They do not measure real-world phishing detection.

The saved model is not the live ClickSafe model. Scan verdicts still come from the existing pipeline. This file does not claim calibrated probabilities.

## Dataset

| Measure | Value |
| --- | ---: |
| Rows | 10000 |
| Unique URLs | 10000 |
| Unique normalized URLs | 10000 |
| Duplicate normalized URLs | 0 |
| Unique source brands | 168 |
| Rows with no source brand | 1660 |
| SHA-256 | `5e6ee554700e1c686a90469b5f096fce78f43a8fb9c6920405555b6195b9dd89` |

Class distribution:

| Label | Rows |
| --- | ---: |
| legitimate | 4000 |
| suspicious | 3000 |
| malicious | 3000 |

Scenario distribution (`generation_method` is audit metadata, not a feature):

| generation_method | Rows |
| --- | ---: |
| legit_brand_service | 1600 |
| legit_third_party | 1200 |
| legit_generic_noisy | 1000 |
| combined | 850 |
| numeric_mild | 500 |
| structure_lure | 480 |
| numeric_strong | 450 |
| spelling_strong | 400 |
| keyword_odd_structure | 400 |
| unicode_strong | 320 |
| brand_subdomain_neutral | 300 |
| insertion_mild | 280 |
| punycode_strong | 280 |
| deletion_mild | 280 |
| unicode_mild | 250 |
| transposition_mild | 220 |
| double_n_strong | 220 |
| repeat_mild | 200 |
| legit_innocent_nn | 200 |
| double_n_mild | 200 |
| hyphen_or_digit_label | 150 |
| rn_for_m_mild | 120 |
| excessive_odd_structure | 100 |

Rows where a measured indicator is at least 1:

| Indicator | Rows |
| --- | ---: |
| character_substitution_count | 1214 |
| double_n_for_m_indicator | 462 |
| rn_for_m_indicator | 120 |
| character_insertion_indicator | 1073 |
| character_deletion_indicator | 448 |
| character_transposition_indicator | 403 |
| homoglyph_indicator | 1114 |
| mixed_script_indicator | 1114 |
| punycode_indicator | 412 |
| brand_in_subdomain | 549 |
| misleading_domain_structure | 1512 |

Automatic brand selection disagreed with the source brand on 2 rows.

## Split

Rows are split with `StratifiedGroupKFold` (5 folds, shuffle, seed 20261015). Fold 0 is test, fold 1 is validation, and folds 2–4 are train. A `split_group` stays in one split. Groups that crossed splits: 0.

| Split | Rows | legitimate | suspicious | malicious | Groups |
| --- | ---: | ---: | ---: | ---: | ---: |
| train | 5819 | 2360 | 1729 | 1730 | 251 |
| validation | 2064 | 778 | 639 | 647 | 89 |
| test | 2117 | 862 | 632 | 623 | 94 |

Held-out test groups: 94. Of those, 37 are brand groups.

## Selection

Candidates are a rule baseline, logistic regression, a random forest, and histogram gradient boosting. A most-frequent dummy is reported and is not eligible. Missing brand features stay NaN until a model pipeline fills them with -1 and adds missingness indicators. The imputer and scaler are fit on the training rows only. The rule reads the raw NaN matrix and does not impute.

A model is eligible when its validation legitimate→malicious rate is at most 0.5 percentage points above the rule. The highest validation macro-F1 wins. Candidates within 0.01 macro-F1 of that score tie, and the tie prefers the rule, then logistic regression, then random forest, then boosting.

Selected on validation macro-F1 with the legitimate-to-malicious constraint. Best eligible macro-F1 was 1.0000. Tied models within 0.01 were logistic_regression, random_forest, hist_gradient_boosting.

### Validation

| Model | Accuracy | Macro P | Macro R | Macro F1 | Legit→malicious | Malicious→legit |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| dummy_most_frequent | 0.3769 | 0.1256 | 0.3333 | 0.1825 | 0 (0.0000) | 647 (1.0000) |
| rule_baseline | 0.9588 | 0.9613 | 0.9557 | 0.9557 | 0 (0.0000) | 0 (0.0000) |
| logistic_regression | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0 (0.0000) | 0 (0.0000) |
| random_forest | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0 (0.0000) | 0 (0.0000) |
| hist_gradient_boosting | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0 (0.0000) | 0 (0.0000) |

Selected model: `logistic_regression`.

## Test

Test scores did not choose the model.

| Model | Accuracy | Macro P | Macro R | Macro F1 | Legit→malicious | Malicious→legit |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| dummy_most_frequent | 0.4072 | 0.1357 | 0.3333 | 0.1929 | 0 (0.0000) | 623 (1.0000) |
| rule_baseline | 0.9575 | 0.9579 | 0.9525 | 0.9520 | 0 (0.0000) | 0 (0.0000) |
| logistic_regression | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0 (0.0000) | 0 (0.0000) |
| random_forest | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0 (0.0000) | 0 (0.0000) |
| hist_gradient_boosting | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0 (0.0000) | 0 (0.0000) |

Selected model test accuracy: 1.0000. Macro precision: 1.0000. Macro recall: 1.0000. Macro F1: 1.0000.

### Per class

| Class | Precision | Recall | F1 | Support |
| --- | ---: | ---: | ---: | ---: |
| legitimate | 1.0000 | 1.0000 | 1.0000 | 862 |
| suspicious | 1.0000 | 1.0000 | 1.0000 | 632 |
| malicious | 1.0000 | 1.0000 | 1.0000 | 623 |

### Confusion matrix

| true \ predicted | legitimate | suspicious | malicious |
| --- | ---: | ---: | ---: |
| legitimate | 862 | 0 | 0 |
| suspicious | 0 | 632 | 0 |
| malicious | 0 | 0 | 623 |


### False positives and false negatives

A false positive here is a test URL labeled legitimate and predicted malicious. Count: 0.

A false negative is a test URL labeled malicious and predicted legitimate. Count: 0.

Legitimate URLs predicted suspicious: 0.

#### Legitimate predicted malicious

None in the test split.

#### Malicious predicted legitimate

None in the test split.

#### Legitimate predicted suspicious

None in the test split.


### Test rows by scenario

| generation_method | Support | Correct | Accuracy |
| --- | ---: | ---: | ---: |
| legit_brand_service | 353 | 353 | 1.0000 |
| legit_third_party | 264 | 264 | 1.0000 |
| combined | 182 | 182 | 1.0000 |
| legit_generic_noisy | 170 | 170 | 1.0000 |
| numeric_mild | 105 | 105 | 1.0000 |
| structure_lure | 101 | 101 | 1.0000 |
| numeric_strong | 94 | 94 | 1.0000 |
| keyword_odd_structure | 90 | 90 | 1.0000 |
| spelling_strong | 85 | 85 | 1.0000 |
| legit_innocent_nn | 75 | 75 | 1.0000 |
| unicode_strong | 68 | 68 | 1.0000 |
| brand_subdomain_neutral | 65 | 65 | 1.0000 |
| insertion_mild | 61 | 61 | 1.0000 |
| deletion_mild | 60 | 60 | 1.0000 |
| punycode_strong | 59 | 59 | 1.0000 |
| unicode_mild | 52 | 52 | 1.0000 |
| transposition_mild | 47 | 47 | 1.0000 |
| repeat_mild | 42 | 42 | 1.0000 |
| double_n_strong | 34 | 34 | 1.0000 |
| hyphen_or_digit_label | 33 | 33 | 1.0000 |
| double_n_mild | 31 | 31 | 1.0000 |
| excessive_odd_structure | 28 | 28 | 1.0000 |
| rn_for_m_mild | 18 | 18 | 1.0000 |

## Memorization check

The saved model uses the grouped split. A second, unsaved model of the same type was trained on a stratified random 8000/2000 split that can place one brand's rows on both sides. Its test macro-F1 was 1.0000 and its legitimate→malicious rate was 0.0000. The grouped test macro-F1 for the saved model was 1.0000.

## Learned signal

Top weights (absolute logistic coefficient for malicious, after scaling):

| Feature | Value |
| --- | ---: |
| suspicious_keyword_count | 4.7335 |
| edit_distance | 2.2880 |
| misleading_domain_structure | 1.8302 |
| character_insertion_indicator | 1.3430 |
| character_substitution_count | 1.2560 |
| character_deletion_indicator | 0.9470 |
| subdomain_count | 0.9255 |
| brand_in_subdomain | 0.7651 |
| url_length | 0.7598 |
| special_character_count | 0.6351 |
| punycode_indicator | 0.4782 |
| double_n_for_m_indicator | 0.4542 |

## Saved bundle

| Field | Value |
| --- | --- |
| Path | `C:\Users\rahul\Desktop\clickSafe\models\structured_url_model.joblib` |
| Model version | 2.0.0 |
| Model type | logistic_regression |
| Feature schema | 1.0.0 |
| Features | 24 |
| Brand selection | automatic |
| Null fill | -1 plus missingness indicators for learned models |
| Probabilities calibrated | false |
| SHA-256 | `a8f54ade45caeb0d92cbb3f338be7b9ca23b4a7ea58bae3b26eabeb7808c1be3` |
| scikit-learn | 1.7.2 |

Model features:

- `character_substitution_count`
- `zero_for_o_count`
- `one_for_l_or_i_count`
- `three_for_e_count`
- `five_for_s_count`
- `double_n_for_m_indicator`
- `repeated_character_count`
- `character_insertion_indicator`
- `character_deletion_indicator`
- `character_transposition_indicator`
- `homoglyph_indicator`
- `mixed_script_indicator`
- `punycode_indicator`
- `edit_distance`
- `brand_similarity_score`
- `digit_count`
- `hyphen_count`
- `special_character_count`
- `subdomain_count`
- `suspicious_keyword_count`
- `brand_in_subdomain`
- `misleading_domain_structure`
- `url_length`
- `rn_for_m_indicator`

Excluded metadata: `record_id`, `generation_method`, `source_type`, `label`, `reference_domain`, `split_group`, `transformation_types`.

## Command

```powershell
backend\venv\Scripts\python.exe scripts\train_structured_model.py --seed 20261015
```

## Limitations

- The labels were assigned by the synthetic generator. A high score means those rules are visible in the features. Logistic regression test macro-F1 of 1.0000, including on 37 held-out brand groups, means the three synthetic classes are linearly separable in these features. That result does not establish real-world accuracy.
- Every hostname uses a reserved suffix. The suffix is not evidence about the public web.
- `predict_proba` values, when the saved model has them, are uncalibrated scores. No calibration step was fit or tested.
- Automatic brand selection can differ from the source brand. This run found 2 disagreements. Prediction uses automatic selection, and so does this training matrix.
- The previous file `backend/src/clicksafe/infrastructure/ml/models/model.joblib` stays in the package. The scan loads this structured bundle as evidence and does not let it set the verdict.
