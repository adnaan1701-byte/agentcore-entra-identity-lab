"""Classification -> label mapping for the Cyera-style module (dspm/classify.py). No AWS calls."""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "dspm"))
import classify  # noqa: E402

sys.path.pop(0)


def det(category, typ, count=3):
    return {"category": category, "type": typ, "count": count}


def test_card_numbers_and_ssns_are_restricted():
    s = {"severity": "High", "detections": [det("FINANCIAL_INFORMATION", "CREDIT_CARD_NUMBER"),
                                             det("PERSONAL_INFORMATION", "USA_SOCIAL_SECURITY_NUMBER")]}
    assert classify.proposed_label(s) == "restr"


def test_custom_employee_ids_alone_are_internal():
    s = {"severity": "Medium", "detections": [det("CUSTOM_IDENTIFIER", "agentlab-employee-id")]}
    assert classify.proposed_label(s) == "internal"


def test_high_severity_is_restricted_even_for_unlisted_types():
    assert classify.proposed_label({"severity": "High", "detections": [det("PERSONAL_INFORMATION", "NAME")]}) == "restr"


def test_labels_only_go_up():
    assert classify.raise_only("public", "restr") == "restr"
    assert classify.raise_only("restr", "internal") == "restr"   # never loosened by automation
    assert classify.raise_only("internal", "internal") == "internal"
    assert classify.raise_only("(none)", "public") == "restr"    # unknown label counts as restricted


def test_summarize_finding_reads_managed_and_custom_detections():
    f = {"type": "SensitiveData:S3Object/Multiple", "severity": {"description": "High"},
         "resourcesAffected": {"s3Object": {"key": "fin/vendor-payments-export.csv"}},
         "classificationDetails": {"result": {
             "sensitiveData": [{"category": "FINANCIAL_INFORMATION",
                                "detections": [{"type": "CREDIT_CARD_NUMBER", "count": 5}]}],
             "customDataIdentifiers": {"detections": [{"name": "agentlab-employee-id", "count": 5}]}}}}
    s = classify.summarize_finding(f)
    assert s["key"] == "fin/vendor-payments-export.csv" and len(s["detections"]) == 2
    assert classify.proposed_label(s) == "restr"
