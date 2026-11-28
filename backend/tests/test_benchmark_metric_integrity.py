"""Unit tests for Phase 5.1: Benchmark Metric Integrity Remediation.

Validates:
1. Mathematically sound null handling for precision, recall, specificity, FPR, and F1.
2. Positive-only datasets (undefined specificity and FPR).
3. Negative-only datasets (undefined recall, and undefined precision when no false alarms).
4. Empty evaluation sets (all metrics null).
5. All-positive predictions.
6. All-negative predictions.
7. Mixed positive and negative records.
8. Zero true positives with non-zero predictions (precision=0.0, recall=0.0 -> f1=0.0).
9. JSON serialization producing strict `null` values rather than fabricated 0.0 or 1.0.
10. End-to-end integration across DatasetEvaluator methods (URL, Attachment, Email).
"""

import json
import pytest
from unittest.mock import patch
from app.datasets.contracts import CanonicalThreatLabel, DatasetCategory
from app.datasets.evaluator import (
    compute_binary_classification_metrics,
    DatasetEvaluator,
)


# ==============================================================================
# 1. CORE METRIC CALCULATION TESTS
# ==============================================================================

def test_empty_evaluation_set_all_null():
    """When TP=FP=TN=FN=0, all five metrics are undefined and must evaluate to None (null)."""
    metrics = compute_binary_classification_metrics(tp=0, fp=0, tn=0, fn=0)
    assert metrics["precision"] is None
    assert metrics["recall"] is None
    assert metrics["specificity"] is None
    assert metrics["fpr"] is None
    assert metrics["f1"] is None

    # Verify JSON serialization represents undefined metrics as null
    dumped = json.dumps(metrics)
    assert '"precision": null' in dumped
    assert '"recall": null' in dumped
    assert '"specificity": null' in dumped
    assert '"fpr": null' in dumped
    assert '"f1": null' in dumped


def test_positive_only_dataset_perfect_predictions():
    """Dataset contains only positives (10 positives, 0 negatives) and detector flags all 10."""
    metrics = compute_binary_classification_metrics(tp=10, fp=0, tn=0, fn=0)
    assert metrics["precision"] == 1.0
    assert metrics["recall"] == 1.0
    assert metrics["specificity"] is None  # TN + FP = 0
    assert metrics["fpr"] is None          # TN + FP = 0
    assert metrics["f1"] == 1.0


def test_positive_only_dataset_partial_detection():
    """Dataset contains only positives (10 positives, 0 negatives) and detector flags 6 of 10."""
    metrics = compute_binary_classification_metrics(tp=6, fp=0, tn=0, fn=4)
    assert metrics["precision"] == 1.0
    assert metrics["recall"] == 0.6
    assert metrics["specificity"] is None
    assert metrics["fpr"] is None
    # F1 = 2 * (1.0 * 0.6) / (1.0 + 0.6) = 1.2 / 1.6 = 0.75
    assert metrics["f1"] == 0.75


def test_positive_only_dataset_all_negative_predictions():
    """Dataset contains only positives (10 positives, 0 negatives) and detector flags none."""
    metrics = compute_binary_classification_metrics(tp=0, fp=0, tn=0, fn=10)
    assert metrics["precision"] is None   # TP + FP = 0
    assert metrics["recall"] == 0.0       # TP / (TP + FN) = 0 / 10
    assert metrics["specificity"] is None # TN + FP = 0
    assert metrics["fpr"] is None         # TN + FP = 0
    assert metrics["f1"] is None          # Precision is undefined


def test_negative_only_dataset_perfect_predictions():
    """Dataset contains only negatives (0 positives, 10 negatives) and detector flags none."""
    metrics = compute_binary_classification_metrics(tp=0, fp=0, tn=10, fn=0)
    assert metrics["precision"] is None   # TP + FP = 0
    assert metrics["recall"] is None      # TP + FN = 0
    assert metrics["specificity"] == 1.0  # 10 / 10
    assert metrics["fpr"] == 0.0          # 0 / 10
    assert metrics["f1"] is None          # Precision and Recall undefined


def test_negative_only_dataset_with_false_alarms():
    """Dataset contains only negatives (0 positives, 10 negatives) and detector raises 3 false alarms."""
    metrics = compute_binary_classification_metrics(tp=0, fp=3, tn=7, fn=0)
    assert metrics["precision"] == 0.0    # 0 / 3
    assert metrics["recall"] is None      # TP + FN = 0
    assert metrics["specificity"] == 0.7  # 7 / 10
    assert metrics["fpr"] == 0.3          # 3 / 10
    assert metrics["f1"] is None          # Recall undefined


def test_negative_only_dataset_all_positive_predictions():
    """Dataset contains only negatives (0 positives, 10 negatives) and detector flags all 10 as positive."""
    metrics = compute_binary_classification_metrics(tp=0, fp=10, tn=0, fn=0)
    assert metrics["precision"] == 0.0
    assert metrics["recall"] is None
    assert metrics["specificity"] == 0.0
    assert metrics["fpr"] == 1.0
    assert metrics["f1"] is None


def test_mixed_dataset_all_positive_predictions():
    """Mixed dataset (5 positives, 5 negatives) and detector flags all 10."""
    metrics = compute_binary_classification_metrics(tp=5, fp=5, tn=0, fn=0)
    assert metrics["precision"] == 0.5
    assert metrics["recall"] == 1.0
    assert metrics["specificity"] == 0.0
    assert metrics["fpr"] == 1.0
    # F1 = 2 * 0.5 * 1.0 / (0.5 + 1.0) = 1.0 / 1.5 = 0.6667
    assert metrics["f1"] == 0.6667


def test_mixed_dataset_all_negative_predictions():
    """Mixed dataset (5 positives, 5 negatives) and detector flags none."""
    metrics = compute_binary_classification_metrics(tp=0, fp=0, tn=5, fn=5)
    assert metrics["precision"] is None   # TP + FP = 0
    assert metrics["recall"] == 0.0
    assert metrics["specificity"] == 1.0
    assert metrics["fpr"] == 0.0
    assert metrics["f1"] is None          # Precision undefined


def test_mixed_dataset_balanced_detection():
    """Standard mixed evaluation scenario: TP=8, FP=2, TN=18, FN=2."""
    metrics = compute_binary_classification_metrics(tp=8, fp=2, tn=18, fn=2)
    assert metrics["precision"] == 0.8    # 8 / 10
    assert metrics["recall"] == 0.8       # 8 / 10
    assert metrics["specificity"] == 0.9  # 18 / 20
    assert metrics["fpr"] == 0.1          # 2 / 20
    assert metrics["f1"] == 0.8           # 2 * 0.8 * 0.8 / 1.6 = 0.8


def test_zero_tp_with_defined_zero_precision_and_recall():
    """When TP=0 but FP>0 and FN>0, precision=0.0 and recall=0.0 are defined; F1 evaluates to 0.0."""
    metrics = compute_binary_classification_metrics(tp=0, fp=2, tn=5, fn=3)
    assert metrics["precision"] == 0.0    # 0 / 2
    assert metrics["recall"] == 0.0       # 0 / 3
    assert metrics["specificity"] == 0.7143  # 5 / 7
    assert metrics["fpr"] == 0.2857       # 2 / 7
    assert metrics["f1"] == 0.0           # Both defined, sum is 0, F1 evaluates to 0.0


# ==============================================================================
# 2. EVALUATOR METHOD INTEGRATION TESTS
# ==============================================================================

def test_evaluator_empty_partition_behavior():
    """Evaluates strict empty test partition handling across URL, attachment, and email evaluators."""
    evaluator = DatasetEvaluator(fixture_mode=False)

    # Empty URL partition
    url_res = evaluator.evaluate_url_dataset([])
    assert url_res["status"] == "EMPTY_TEST_PARTITION"
    assert url_res["precision"] is None
    assert url_res["recall"] is None
    assert url_res["specificity"] is None
    assert url_res["fpr"] is None
    assert url_res["f1"] is None

    # Empty Attachment partition
    att_res = evaluator.evaluate_attachment_dataset([])
    assert att_res["status"] == "EMPTY_TEST_PARTITION"
    assert att_res["precision"] is None
    assert att_res["recall"] is None
    assert att_res["specificity"] is None
    assert att_res["fpr"] is None
    assert att_res["f1"] is None

    # Empty Email partition
    email_res = evaluator.evaluate_email_dataset(DatasetCategory.PHISHING_EMAIL, [])
    assert email_res["status"] == "EMPTY_TEST_PARTITION"
    assert email_res["precision"] is None
    assert email_res["recall"] is None
    assert email_res["specificity"] is None
    assert email_res["fpr"] is None
    assert email_res["f1"] is None


def test_evaluator_url_dataset_positive_only():
    """Evaluates URL dataset where test set contains only malicious URLs."""
    evaluator = DatasetEvaluator()
    records = [
        {"url": "http://malicious-portal.xyz/login", "canonical_label": CanonicalThreatLabel.MALICIOUS_URL.value},
        {"url": "http://evil-credential-steal.top/auth", "canonical_label": CanonicalThreatLabel.MALICIOUS_URL.value},
    ]
    # Mock split_records to deliver both records into the evaluation set
    with patch.object(evaluator.pipeline, "split_records", return_value=([], records)):
        res = evaluator.evaluate_url_dataset(records)
        assert res["total_tested"] == 2
        assert res["tp"] == 2
        assert res["fp"] == 0
        assert res["tn"] == 0
        assert res["fn"] == 0
        assert res["precision"] == 1.0
        assert res["recall"] == 1.0
        assert res["specificity"] is None  # Undefined: no negative ground truth
        assert res["fpr"] is None          # Undefined: no negative ground truth
        assert res["f1"] == 1.0


def test_evaluator_url_dataset_negative_only():
    """Evaluates URL dataset where test set contains only benign URLs."""
    evaluator = DatasetEvaluator()
    records = [
        {"url": "https://www.google.com/search", "canonical_label": CanonicalThreatLabel.BENIGN.value},
        {"url": "https://www.microsoft.com/en-us", "canonical_label": CanonicalThreatLabel.BENIGN.value},
    ]
    with patch.object(evaluator.pipeline, "split_records", return_value=([], records)):
        res = evaluator.evaluate_url_dataset(records)
        assert res["total_tested"] == 2
        assert res["tp"] == 0
        assert res["fp"] == 0
        assert res["tn"] == 2
        assert res["fn"] == 0
        assert res["precision"] is None    # Undefined: no positive predictions
        assert res["recall"] is None       # Undefined: no positive ground truth
        assert res["specificity"] == 1.0
        assert res["fpr"] == 0.0
        assert res["f1"] is None


def test_evaluator_url_dataset_mixed():
    """Evaluates URL dataset where test set contains mixed benign and malicious URLs."""
    evaluator = DatasetEvaluator()
    records = [
        {"url": "http://malicious-portal.xyz/login", "canonical_label": CanonicalThreatLabel.MALICIOUS_URL.value},
        {"url": "https://www.google.com/search", "canonical_label": CanonicalThreatLabel.BENIGN.value},
    ]
    with patch.object(evaluator.pipeline, "split_records", return_value=([], records)):
        res = evaluator.evaluate_url_dataset(records)
        assert res["total_tested"] == 2
        assert res["tp"] == 1
        assert res["fp"] == 0
        assert res["tn"] == 1
        assert res["fn"] == 0
        assert res["precision"] == 1.0
        assert res["recall"] == 1.0
        assert res["specificity"] == 1.0
        assert res["fpr"] == 0.0
        assert res["f1"] == 1.0


def test_evaluator_attachment_dataset_metrics():
    """Evaluates attachment dataset metric output with simulated split."""
    evaluator = DatasetEvaluator()
    records = [
        {"filename": "safe.pdf", "canonical_label": CanonicalThreatLabel.BENIGN.value},
        {"filename": "invoice.pdf.exe", "canonical_label": CanonicalThreatLabel.MALWARE_ATTACHMENT.value},
    ]
    with patch.object(evaluator.pipeline, "split_records", return_value=([], records)):
        res = evaluator.evaluate_attachment_dataset(records)
        assert res["total_tested"] == 2
        assert res["tp"] == 1
        assert res["fp"] == 0
        assert res["tn"] == 1
        assert res["fn"] == 0
        assert res["precision"] == 1.0
        assert res["recall"] == 1.0
        assert res["specificity"] == 1.0
        assert res["fpr"] == 0.0
        assert res["f1"] == 1.0
