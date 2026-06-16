"""
Unit tests for the compliance scoring engine.
"""

import unittest
from app.services.scoring import (
    calculate_security_score,
    determine_risk_level,
    calculate_severity_breakdown,
    compute_scan_results
)
from app.constants import (
    S3_PUBLIC_BUCKET,
    SG_SSH_OPEN,
    SG_RDP_OPEN,
    SG_ALL_TRAFFIC_OPEN,
    IAM_NO_MFA,
    IAM_OLD_KEY,
    IAM_ADMIN_ACCESS
)


class TestScoringEngine(unittest.TestCase):

    def test_perfect_score_with_no_findings(self):
        """Test that no findings results in a perfect score of 100."""
        findings = []
        score = calculate_security_score(findings)
        self.assertEqual(score, 100)

        risk_level = determine_risk_level(score)
        self.assertEqual(risk_level, "Low Risk")

        breakdown = calculate_severity_breakdown(findings)
        self.assertEqual(breakdown, {"critical": 0, "high": 0, "medium": 0, "low": 0})

    def test_single_s3_public_bucket(self):
        """Test scoring with a single public S3 bucket finding."""
        findings = [
            {
                "bucket": "test-bucket",
                "issue": S3_PUBLIC_BUCKET,
                "details": "Bucket ACL allows READ access to everyone"
            }
        ]
        score = calculate_security_score(findings)
        # Should be 100 - 15 = 85
        self.assertEqual(score, 85)

        risk_level = determine_risk_level(score)
        self.assertEqual(risk_level, "Medium Risk")

        breakdown = calculate_severity_breakdown(findings)
        self.assertEqual(breakdown, {"critical": 1, "high": 0, "medium": 0, "low": 0})

    def test_multiple_s3_public_buckets_with_cap(self):
        """Test that multiple S3 public buckets apply deductions up to the category cap."""
        findings = [
            {
                "bucket": "bucket-1",
                "issue": S3_PUBLIC_BUCKET,
                "details": "Bucket ACL allows READ access to everyone"
            },
            {
                "bucket": "bucket-2",
                "issue": S3_PUBLIC_BUCKET,
                "details": "Bucket ACL allows WRITE access to everyone"
            },
            {
                "bucket": "bucket-3",
                "issue": S3_PUBLIC_BUCKET,
                "details": "Bucket ACL allows FULL_CONTROL access to everyone"
            },
            {
                "bucket": "bucket-4",
                "issue": S3_PUBLIC_BUCKET,
                "details": "Bucket ACL allows READ access to everyone"
            }
        ]
        score = calculate_security_score(findings)
        # Each S3 bucket deducts 15 points, max penalty is 30
        # So with 4 findings: 15 + 15 + 15 + 15 = 60, but capped at 30
        # Score should be 100 - 30 = 70
        self.assertEqual(score, 70)

        risk_level = determine_risk_level(score)
        self.assertEqual(risk_level, "Medium Risk")

        breakdown = calculate_severity_breakdown(findings)
        # Should count all 4 findings for severity breakdown
        self.assertEqual(breakdown, {"critical": 4, "high": 0, "medium": 0, "low": 0})

    def test_mixed_findings_scoring(self):
        """Test scoring with a mix of different finding types."""
        findings = [
            {
                "bucket": "public-bucket",
                "issue": S3_PUBLIC_BUCKET,
                "details": "Bucket ACL allows READ access to everyone"
            },
            {
                "group_id": "sg-123",
                "group_name": "test-sg",
                "issue": SG_SSH_OPEN,
                "details": "Protocol: tcp, Ports: 22-22, Source: 0.0.0.0/0",
                "direction": "ingress"
            },
            {
                "user": "test-user",
                "issue": IAM_NO_MFA,
                "details": "IAM user 'test-user' has no MFA devices configured"
            },
            {
                "user": "test-user-2",
                "issue": IAM_OLD_KEY,
                "details": "Access key 'EXAMPLEKEYID' created 100 days ago"
            }
        ]
        score = calculate_security_score(findings)
        # S3 Public Bucket: -15
        # SSH Open: -12
        # No MFA: -8
        # Old Key: -4
        # Total: -39
        # Score: 100 - 39 = 61
        self.assertEqual(score, 61)

        risk_level = determine_risk_level(score)
        self.assertEqual(risk_level, "High Risk")

        breakdown = calculate_severity_breakdown(findings)
        expected = {
            "critical": 1,  # S3 bucket
            "high": 1,      # SSH open
            "medium": 1,    # No MFA
            "low": 1        # Old key
        }
        self.assertEqual(breakdown, expected)

    def test_score_never_below_zero(self):
        """Test that score never goes below 0 even with many findings."""
        # Create enough findings to theoretically push score below zero
        findings = []
        # Add 20 S3 public buckets (each -15, max penalty 30 per category)
        for i in range(20):
            findings.append({
                "bucket": f"bucket-{i}",
                "issue": S3_PUBLIC_BUCKET,
                "details": f"Bucket ACL allows READ access to everyone"
            })
        # Add 20 SSH open rules (each -12, max penalty 24 per category)
        for i in range(20):
            findings.append({
                "group_id": f"sg-{i}",
                "group_name": f"test-sg-{i}",
                "issue": SG_SSH_OPEN,
                "details": f"Protocol: tcp, Ports: 22-22, Source: 0.0.0.0/0",
                "direction": "ingress"
            })
        # Add 20 missing MFA (each -8, max penalty 24 per category)
        for i in range(20):
            findings.append({
                "user": f"user-{i}",
                "issue": IAM_NO_MFA,
                "details": f"IAM user 'user-{i}' has no MFA devices configured"
            })

        score = calculate_security_score(findings)
        # With caps:
        # S3: max penalty 30
        # SSH: max penalty 24
        # MFA: max penalty 24
        # Total penalty: 30 + 24 + 24 = 78
        # Score: 100 - 78 = 22 (should not be negative)
        self.assertGreaterEqual(score, 0)
        self.assertEqual(score, 22)

    def test_scanner_error_findings_are_ignored(self):
        """Test that scanner error findings are ignored in scoring."""
        findings = [
            {
                "bucket": "test-bucket",
                "issue": S3_PUBLIC_BUCKET,
                "details": "Bucket ACL allows READ access to everyone"
            },
            {
                "issue": "Scan failed",
                "details": "Some error message"
            },
            {
                "issue": "AWS API error",
                "details": "Another error message"
            },
            {
                "user": "test-user",
                "issue": IAM_NO_MFA,
                "details": "IAM user 'test-user' has no MFA devices configured"
            }
        ]
        score = calculate_security_score(findings)
        # Only count the S3 bucket (-15) and IAM no MFA (-8)
        # Score should be 100 - 15 - 8 = 77
        self.assertEqual(score, 77)

        breakdown = calculate_severity_breakdown(findings)
        # Should only count the real findings, not the error ones
        expected = {
            "critical": 1,  # S3 bucket
            "high": 0,
            "medium": 1,    # No MFA
            "low": 0
        }
        self.assertEqual(breakdown, expected)

    def test_compute_scan_results_integration(self):
        """Test the compute_scan_results function that combines all scoring functions."""
        findings = [
            {
                "bucket": "public-bucket",
                "issue": S3_PUBLIC_BUCKET,
                "details": "Bucket ACL allows READ access to everyone"
            },
            {
                "group_id": "sg-123",
                "group_name": "test-sg",
                "issue": SG_ALL_TRAFFIC_OPEN,
                "details": "Protocol: -1, Source: 0.0.0.0/0",
                "direction": "ingress"
            }
        ]
        results = compute_scan_results(findings)

        # Check that all expected fields are present
        self.assertIn("security_score", results)
        self.assertIn("risk_level", results)
        self.assertIn("severity_breakdown", results)

        # Verify the values
        # S3 Public Bucket: -15
        # All Traffic Open: -18
        # Total: -33
        # Score: 100 - 33 = 67
        self.assertEqual(results["security_score"], 67)

        risk_level = determine_risk_level(67)
        self.assertEqual(results["risk_level"], risk_level)
        self.assertEqual(results["risk_level"], "High Risk")

        breakdown = results["severity_breakdown"]
        expected = {
            "critical": 2,  # Both S3 and All Traffic are critical
            "high": 0,
            "medium": 0,
            "low": 0
        }
        self.assertEqual(breakdown, expected)


if __name__ == '__main__':
    unittest.main()