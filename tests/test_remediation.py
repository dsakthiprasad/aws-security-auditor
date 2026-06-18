"""
Unit tests for the Terraform remediation service.
"""
import json
import re
from unittest.mock import Mock, patch, MagicMock
import pytest
from sqlalchemy.orm import Session

from app.services.remediation import generate_remediation, _extract_and_validate_vars, _is_valid_s3_bucket_name, _is_valid_sg_id, _is_valid_aws_access_key_id
from app import constants


# Mock data for testing
MOCK_SCAN_ID = "test-scan-id-123"

# Valid S3 bucket names (8 chars after sg- for SG IDs)
MOCK_S3_FINDING = {
    "id": 1,
    "issue_type": constants.S3_PUBLIC_BUCKET,
    "finding_data": {
        "bucket_name": "my-test-bucket",
        "region": "us-west-2",
        "account_id": "123456789012"
    }
}

# SG IDs: 8 characters after sg- (total length 10: sg- + 8 hex)
MOCK_SG_SSH_FINDING = {
    "id": 2,
    "issue_type": constants.SG_SSH_OPEN,
    "finding_data": {
        "group_id": "sg-0a1b2c3d",  # 8 hex chars
        "port": 22,
        "protocol": "tcp"
    }
}

MOCK_SG_RDP_FINDING = {
    "id": 3,
    "issue_type": constants.SG_RDP_OPEN,
    "finding_data": {
        "group_id": "sg-0a1b2c3e",  # 8 hex chars
        "port": 3389,
        "protocol": "tcp"
    }
}

# IAM old key: access key ID should be 20 chars (AKIA + 16)
MOCK_IAM_OLD_KEY_FINDING = {
    "id": 4,
    "issue_type": constants.IAM_OLD_KEY,
    "finding_data": {
        "user_name": "test-user",
        "access_key_id": "AKIATEST1234567890AB",  # AKIA + 16 uppercase alphanumeric
        "details": "Access key 'AKIATEST1234567890AB' created 95 days ago (created: 2023-01-01)"
    }
}

MOCK_IAM_NO_MFA_FINDING = {
    "id": 5,
    "issue_type": constants.IAM_NO_MFA,
    "finding_data": {
        "user_name": "test-user-no-mfa",
        "details": "IAM user 'test-user-no-mfa' has no MFA devices configured"
    }
}

MOCK_IAM_ADMIN_ACCESS_FINDING = {
    "id": 6,
    "issue_type": constants.IAM_ADMIN_ACCESS,
    "finding_data": {
        "user_name": "admin-user",
        "details": "IAM user 'admin-user' has AdministratorAccess via direct managed policy"
    }
}

MOCK_SG_ALL_TRAFFIC_FINDING = {
    "id": 7,
    "issue_type": constants.SG_ALL_TRAFFIC_OPEN,
    "finding_data": {
        "group_id": "sg-0a1b2c3f",  # 8 hex chars
        "details": "Security group allows all traffic"
    }
}

# Fallback key name variations
MOCK_S3_FINDING_FALLBACK_BUCKET = {
    "id": 8,
    "issue_type": constants.S3_PUBLIC_BUCKET,
    "finding_data": {
        "bucket": "fallback-bucket-name"
    }
}

MOCK_S3_FINDING_FALLBACK_RESOURCE = {
    "id": 9,
    "issue_type": constants.S3_PUBLIC_BUCKET,
    "finding_data": {
        "resource_name": "resource-bucket-name"
    }
}

MOCK_SG_FINDING_FALLBACK_GROUP_ID = {
    "id": 10,
    "issue_type": constants.SG_SSH_OPEN,
    "finding_data": {
        "security_group_id": "sg-0a1b2c40"  # 8 hex chars
    }
}

MOCK_SG_FINDING_FALLBACK_RESOURCE_ID = {
    "id": 11,
    "issue_type": constants.SG_SSH_OPEN,
    "finding_data": {
        "resource_id": "sg-0a1b2c41"  # 8 hex chars
    }
}

MOCK_IAM_FINDING_FALLBACK_USER = {
    "id": 12,
    "issue_type": constants.IAM_OLD_KEY,
    "finding_data": {
        "user": "fallback-user",
        "access_key_id": "AKIATEST1234567890AB"
    }
}

MOCK_IAM_FINDING_FALLBACK_USERNAME = {
    "id": 13,
    "issue_type": constants.IAM_OLD_KEY,
    "finding_data": {
        "username": "username-fallback",
        "access_key_id": "AKIATEST1234567890AB"
    }
}

# Invalid data for testing
INVALID_S3_BUCKET_NAMES = ["ab", "a" * 64, "BucketWithCAPS", "bucket..name", "-bucket", "bucket_", "bucket."]
VALID_S3_BUCKET_NAMES = ["my-bucket", "mybucket123", "a.b.c", "xn--example"]

INVALID_SG_IDS = ["sg-", "sg-0a1b2c3", "sg-xyz", ""]
# Valid SG IDs: 8 or 17 hex chars after sg-
VALID_SG_IDS = ["sg-0a1b2c3d", "sg-0a1b2c3d4e5f6a7b8"]  # 8 and 17 hex chars (fixed: removed invalid g,h)

INVALID_ACCESS_KEYS = ["AKIA", "AKIAIOSFODNN7EXAM", "AKIATEST1234567890", ""]
# Valid: AKIA or ASIA followed by 16 uppercase alphanumeric
VALID_ACCESS_KEYS = ["AKIATEST1234567890AB", "ASIATEST1234567890AB"]


def test_is_valid_s3_bucket_name():
    """Test S3 bucket name validation."""
    for name in INVALID_S3_BUCKET_NAMES:
        assert _is_valid_s3_bucket_name(name) == False, f"Failed for invalid bucket name: {name}"

    for name in VALID_S3_BUCKET_NAMES:
        assert _is_valid_s3_bucket_name(name) == True, f"Failed for valid bucket name: {name}"


def test_is_valid_sg_id():
    """Test security group ID validation."""
    for sg_id in INVALID_SG_IDS:
        assert _is_valid_sg_id(sg_id) == False, f"Failed for invalid SG ID: {sg_id}"

    for sg_id in VALID_SG_IDS:
        assert _is_valid_sg_id(sg_id) == True, f"Failed for valid SG ID: {sg_id}"


def test_is_valid_aws_access_key_id():
    """Test AWS access key ID validation."""
    for key in INVALID_ACCESS_KEYS:
        assert _is_valid_aws_access_key_id(key) == False, f"Failed for invalid access key: {key}"

    for key in VALID_ACCESS_KEYS:
        assert _is_valid_aws_access_key_id(key) == True, f"Failed for valid access key: {key}"


def test_extract_and_validate_vars_s3():
    """Test variable extraction for S3 findings."""
    # Primary key
    result = _extract_and_validate_vars(MOCK_S3_FINDING, constants.S3_PUBLIC_BUCKET)
    assert result is not None
    assert result["bucket_name"] == "my-test-bucket"
    assert result["region"] == "us-west-2"
    assert result["account_id"] == "123456789012"

    # Fallback bucket
    result = _extract_and_validate_vars(MOCK_S3_FINDING_FALLBACK_BUCKET, constants.S3_PUBLIC_BUCKET)
    assert result is not None
    assert result["bucket_name"] == "fallback-bucket-name"

    # Fallback resource_name
    result = _extract_and_validate_vars(MOCK_S3_FINDING_FALLBACK_RESOURCE, constants.S3_PUBLIC_BUCKET)
    assert result is not None
    assert result["bucket_name"] == "resource-bucket-name"

    # Missing all keys (clear both outer and nested, preserving other fields)
    missing_bucket = {
        **MOCK_S3_FINDING,
        "bucket_name": None,
        "bucket": None,
        "resource_name": None,
        "finding_data": {
            **MOCK_S3_FINDING["finding_data"],
            "bucket_name": None,
            "bucket": None,
            "resource_name": None,
        },
    }
    result = _extract_and_validate_vars(missing_bucket, constants.S3_PUBLIC_BUCKET)
    assert result is None

    # Invalid bucket name
    for invalid_name in INVALID_S3_BUCKET_NAMES:
        invalid_finding = {
            **MOCK_S3_FINDING,
            "bucket_name": invalid_name,
            "finding_data": {
                **MOCK_S3_FINDING["finding_data"],
                "bucket_name": invalid_name,
            },
        }
        result = _extract_and_validate_vars(invalid_finding, constants.S3_PUBLIC_BUCKET)
        assert result is None, f"Should have failed for invalid bucket name: {invalid_name}"


def test_extract_and_validate_vars_sg():
    """Test variable extraction for Security Group findings."""
    # SSH Open
    result = _extract_and_validate_vars(MOCK_SG_SSH_FINDING, constants.SG_SSH_OPEN)
    assert result is not None
    assert result["group_id"] == "sg-0a1b2c3d"
    assert result["port"] == 22
    assert result["protocol"] == "tcp"

    # RDP Open
    result = _extract_and_validate_vars(MOCK_SG_RDP_FINDING, constants.SG_RDP_OPEN)
    assert result is not None
    assert result["group_id"] == "sg-0a1b2c3e"
    assert result["port"] == 3389
    assert result["protocol"] == "tcp"

    # Fallback security_group_id
    result = _extract_and_validate_vars(MOCK_SG_FINDING_FALLBACK_GROUP_ID, constants.SG_SSH_OPEN)
    assert result is not None
    assert result["group_id"] == "sg-0a1b2c40"

    # Fallback resource_id
    result = _extract_and_validate_vars(MOCK_SG_FINDING_FALLBACK_RESOURCE_ID, constants.SG_SSH_OPEN)
    assert result is not None
    assert result["group_id"] == "sg-0a1b2c41"

    # Missing all keys (clear both outer and nested, preserving other fields)
    missing_sg = {
        **MOCK_SG_SSH_FINDING,
        "group_id": None,
        "security_group_id": None,
        "resource_id": None,
        "finding_data": {
            **MOCK_SG_SSH_FINDING["finding_data"],
            "group_id": None,
            "security_group_id": None,
            "resource_id": None,
        },
    }
    result = _extract_and_validate_vars(missing_sg, constants.SG_SSH_OPEN)
    assert result is None

    # Invalid SG ID
    for invalid_id in INVALID_SG_IDS:
        invalid_finding = {
            **MOCK_SG_SSH_FINDING,
            "group_id": invalid_id,
            "finding_data": {
                **MOCK_SG_SSH_FINDING["finding_data"],
                "group_id": invalid_id,
            },
        }
        result = _extract_and_validate_vars(invalid_finding, constants.SG_SSH_OPEN)
        assert result is None, f"Should have failed for invalid SG ID: {invalid_id}"


def test_extract_and_validate_vars_iam_old_key():
    """Test variable extraction for IAM old key findings."""
    # Primary keys
    result = _extract_and_validate_vars(MOCK_IAM_OLD_KEY_FINDING, constants.IAM_OLD_KEY)
    assert result is not None
    assert result["user_name"] == "test-user"
    assert result["access_key_id"] == "AKIATEST1234567890AB"

    # Fallback user
    result = _extract_and_validate_vars(MOCK_IAM_FINDING_FALLBACK_USER, constants.IAM_OLD_KEY)
    assert result is not None
    assert result["user_name"] == "fallback-user"
    assert result["access_key_id"] == "AKIATEST1234567890AB"

    # Fallback username
    result = _extract_and_validate_vars(MOCK_IAM_FINDING_FALLBACK_USERNAME, constants.IAM_OLD_KEY)
    assert result is not None
    assert result["user_name"] == "username-fallback"
    assert result["access_key_id"] == "AKIATEST1234567890AB"

    # Missing user keys (clear both outer and nested, preserving other fields)
    missing_user = {
        **MOCK_IAM_OLD_KEY_FINDING,
        "user_name": None,
        "user": None,
        "username": None,
        "finding_data": {
            **MOCK_IAM_OLD_KEY_FINDING["finding_data"],
            "user_name": None,
            "user": None,
            "username": None,
        },
    }
    result = _extract_and_validate_vars(missing_user, constants.IAM_OLD_KEY)
    assert result is None

    # Missing access key ID
    missing_key = {
        **MOCK_IAM_OLD_KEY_FINDING,
        "access_key_id": None,
        "key_id": None,
        "finding_data": {
            **MOCK_IAM_OLD_KEY_FINDING["finding_data"],
            "access_key_id": None,
            "key_id": None,
            "details": "",  # also clear details so parsing fails
        },
    }
    result = _extract_and_validate_vars(missing_key, constants.IAM_OLD_KEY)
    assert result is None

    # Invalid access key ID
    for invalid_key in INVALID_ACCESS_KEYS:
        invalid_finding = {
            **MOCK_IAM_OLD_KEY_FINDING,
            "access_key_id": invalid_key,
            "finding_data": {
                **MOCK_IAM_OLD_KEY_FINDING["finding_data"],
                "access_key_id": invalid_key,
                "details": "",   # Ensure fallback fails
            },
        }
        result = _extract_and_validate_vars(invalid_finding, constants.IAM_OLD_KEY)
        assert result is None, f"Should have failed for invalid access key: {invalid_key}"


def test_extract_and_validate_vars_unknown_issue():
    """Test variable extraction for unknown issue type."""
    result = _extract_and_validate_vars(MOCK_S3_FINDING, "Unknown Issue Type")
    assert result is None


def test_generate_remediation_scan_not_found():
    """Test generate_remediation with non-existent scan."""
    # Mock database session that returns None for get_scan_by_scan_id
    with patch('app.services.remediation.get_scan_by_scan_id') as mock_get_scan:
        mock_get_scan.return_value = None

        with pytest.raises(ValueError, match=f"Scan with ID {MOCK_SCAN_ID} not found"):
            generate_remediation(Mock(spec=Session), MOCK_SCAN_ID)


def test_generate_remediation_empty_findings():
    """Test generate_remediation with scan that has no findings."""
    # Mock scan with no findings
    mock_scan = Mock()
    mock_scan.findings = []

    with patch('app.services.remediation.get_scan_by_scan_id') as mock_get_scan:
        mock_get_scan.return_value = mock_scan

        result = generate_remediation(Mock(spec=Session), MOCK_SCAN_ID)

        assert result["scan_id"] == MOCK_SCAN_ID
        assert result["findings_total"] == 0
        assert result["findings_remediated"] == 0
        assert result["findings_manual_guidance"] == 0
        assert len(result["remediation"]["terraform"]) == 0
        assert len(result["remediation"]["manual_guidance"]) == 0


def test_generate_remediation_mixed_findings():
    """Test generate_remediation with mixed remediable and non-remediable findings."""
    # Create mock findings
    mock_findings = [
        Mock(to_dict=Mock(return_value=MOCK_S3_FINDING)),
        Mock(to_dict=Mock(return_value=MOCK_SG_SSH_FINDING)),
        Mock(to_dict=Mock(return_value=MOCK_IAM_NO_MFA_FINDING)),  # No template
        Mock(to_dict=Mock(return_value=MOCK_SG_ALL_TRAFFIC_FINDING))  # No template
    ]

    mock_scan = Mock()
    mock_scan.findings = mock_findings

    with patch('app.services.remediation.get_scan_by_scan_id') as mock_get_scan:
        mock_get_scan.return_value = mock_scan

        # Mock Jinja2 template rendering
        with patch('app.services.remediation.template_env.get_template') as mock_get_template:
            mock_template = Mock()
            mock_template.render.return_value = "# Mock Terraform content"
            mock_get_template.return_value = mock_template

            result = generate_remediation(Mock(spec=Session), MOCK_SCAN_ID)

            # Check counts
            assert result["findings_total"] == 4
            assert result["findings_remediated"] == 2  # S3 and SG_SSH
            assert result["findings_manual_guidance"] == 2  # IAM_NO_MFA and SG_ALL_TRAFFIC_OPEN

            # Check Terraform blocks
            assert len(result["remediation"]["terraform"]) == 2
            for block in result["remediation"]["terraform"]:
                assert "filename" in block
                assert "service" in block
                assert "content" in block
                assert block["content"] == "# Mock Terraform content"

            # Check manual guidance
            assert len(result["remediation"]["manual_guidance"]) == 2
            guidance_issue_types = {g["issue_type"] for g in result["remediation"]["manual_guidance"]}
            assert guidance_issue_types == {constants.IAM_NO_MFA, constants.SG_ALL_TRAFFIC_OPEN}
            for guidance in result["remediation"]["manual_guidance"]:
                assert "finding_id" in guidance
                assert "issue_type" in guidance
                assert "guidance" in guidance
                assert "priority" in guidance

            # Check metadata
            assert result["metadata"]["review_required"] == True
            assert result["metadata"]["terraform_version_required"] == ">=1.0.0"
            assert "Always review generated Terraform before applying." in result["metadata"]["warnings"]


def test_generate_remediation_missing_variables():
    """Test generate_remediation when variables cannot be extracted."""
    # Finding with missing bucket name (using the database structure)
    mock_finding = Mock()
    mock_finding.to_dict.return_value = {
        "id": 99,
        "issue_type": constants.S3_PUBLIC_BUCKET,
        "finding_data": {
            "bucket_name": None,
            "bucket": None,
            "resource_name": None,
        },
    }

    mock_scan = Mock()
    mock_scan.findings = [mock_finding]

    with patch('app.services.remediation.get_scan_by_scan_id') as mock_get_scan:
        mock_get_scan.return_value = mock_scan

        result = generate_remediation(Mock(spec=Session), MOCK_SCAN_ID)

        # Should have 0 remediated, 1 manual guidance
        assert result["findings_total"] == 1
        assert result["findings_remediated"] == 0
        assert result["findings_manual_guidance"] == 1

        # Check that the guidance mentions missing variables
        guidance = result["remediation"]["manual_guidance"][0]
        assert "Required variables could not be extracted" in guidance["guidance"]


def test_generate_remediation_template_not_found():
    """Test generate_remediation when template is not found."""
    # This simulates an issue type that's in TEMPLATE_MAP but template file is missing
    # We'll test by temporarily removing a template from TEMPLATE_MAP in the test

    # For this test, we'll use a finding that should have a template but we'll mock TEMPLATE_MAP to not include it
    with patch('app.services.remediation.TEMPLATE_MAP', {}):
        mock_finding = Mock()
        mock_finding.to_dict.return_value = MOCK_S3_FINDING

        mock_scan = Mock()
        mock_scan.findings = [mock_finding]

        with patch('app.services.remediation.get_scan_by_scan_id') as mock_get_scan:
            mock_get_scan.return_value = mock_scan

            result = generate_remediation(Mock(spec=Session), MOCK_SCAN_ID)

            # Should fall back to manual guidance
            assert result["findings_total"] == 1
            assert result["findings_remediated"] == 0
            assert result["findings_manual_guidance"] == 1

            guidance = result["remediation"]["manual_guidance"][0]
            assert "No automated remediation available" in guidance["guidance"]


def test_generate_remediation_rendering_error():
    """Test generate_remediation when template rendering fails."""
    mock_finding = Mock()
    mock_finding.to_dict.return_value = MOCK_S3_FINDING

    mock_scan = Mock()
    mock_scan.findings = [mock_finding]

    with patch('app.services.remediation.get_scan_by_scan_id') as mock_get_scan:
        mock_get_scan.return_value = mock_scan

        # Mock template that raises an exception during render
        with patch('app.services.remediation.template_env.get_template') as mock_get_template:
            mock_template = Mock()
            mock_template.render.side_effect = Exception("Template rendering error")
            mock_get_template.return_value = mock_template

            result = generate_remediation(Mock(spec=Session), MOCK_SCAN_ID)

            # Should fall back to manual guidance
            assert result["findings_total"] == 1
            assert result["findings_remediated"] == 0
            assert result["findings_manual_guidance"] == 1

            guidance = result["remediation"]["manual_guidance"][0]
            assert "Error during Terraform generation" in guidance["guidance"]


def test_get_service_from_issue_type():
    """Test the helper function that maps issue type to service."""
    from app.services.remediation import _get_service_from_issue_type

    assert _get_service_from_issue_type(constants.S3_PUBLIC_BUCKET) == "s3"
    assert _get_service_from_issue_type(constants.SG_SSH_OPEN) == "security_group"
    assert _get_service_from_issue_type(constants.SG_RDP_OPEN) == "security_group"
    assert _get_service_from_issue_type(constants.SG_ALL_TRAFFIC_OPEN) == "security_group"
    assert _get_service_from_issue_type(constants.IAM_NO_MFA) == "iam"
    assert _get_service_from_issue_type(constants.IAM_OLD_KEY) == "iam"
    assert _get_service_from_issue_type(constants.IAM_ADMIN_ACCESS) == "iam"
    assert _get_service_from_issue_type("Random issue") == "unknown"


def test_generate_filename():
    """Test filename generation for different issue types."""
    # We'll test by calling the actual function with mocked findings

    # Since _generate_filename is not exported, we'll test it indirectly through the full flow
    # or we can import it if it's made available. For now, let's test via the full generation.

    # S3 finding
    mock_finding = Mock()
    mock_finding.to_dict.return_value = MOCK_S3_FINDING

    mock_scan = Mock()
    mock_scan.findings = [mock_finding]

    with patch('app.services.remediation.get_scan_by_scan_id') as mock_get_scan:
        mock_get_scan.return_value = mock_scan

        with patch('app.services.remediation.template_env.get_template') as mock_get_template:
            mock_template = Mock()
            mock_template.render.return_value = "# Mock Terraform"
            mock_get_template.return_value = mock_template

            result = generate_remediation(Mock(spec=Session), MOCK_SCAN_ID)

            # Check that filename was generated
            assert len(result["remediation"]["terraform"]) == 1
            filename = result["remediation"]["terraform"][0]["filename"]
            # Should start with s3_ and contain the issue type slug and bucket name
            assert filename.startswith("s3_")
            # The issue type slug should be derived from the issue string
            # "Publicly accessible S3 bucket" -> publicly_accessible_s3_bucket
            assert "publicly_accessible_s3_bucket" in filename
            # Should contain the bucket name or a sanitized version
            assert "my-test-bucket" in filename or "my_test_bucket" in filename


def test_generate_remediation_response_structure():
    """Test that the response structure matches the expected format."""
    mock_finding = Mock()
    mock_finding.to_dict.return_value = MOCK_S3_FINDING

    mock_scan = Mock()
    mock_scan.findings = [mock_finding]

    with patch('app.services.remediation.get_scan_by_scan_id') as mock_get_scan:
        mock_get_scan.return_value = mock_scan

        with patch('app.services.remediation.template_env.get_template') as mock_get_template:
            mock_template = Mock()
            mock_template.render.return_value = "# Mock Terraform"
            mock_get_template.return_value = mock_template

            result = generate_remediation(Mock(spec=Session), MOCK_SCAN_ID)

            # Check top-level keys
            expected_keys = {"scan_id", "generated_at", "findings_total", "findings_remediated",
                           "findings_manual_guidance", "remediation", "metadata"}
            assert set(result.keys()) == expected_keys

            # Check remediation structure
            remediation = result["remediation"]
            assert "terraform" in remediation
            assert "manual_guidance" in remediation
            assert isinstance(remediation["terraform"], list)
            assert isinstance(remediation["manual_guidance"], list)

            # Check terraform block structure
            if remediation["terraform"]:
                block = remediation["terraform"][0]
                assert set(block.keys()) == {"filename", "service", "content"}

            # Check manual guidance structure
            if remediation["manual_guidance"]:
                guidance = remediation["manual_guidance"][0]
                assert set(guidance.keys()) == {"finding_id", "issue_type", "guidance", "priority"}

            # Check metadata structure
            metadata = result["metadata"]
            expected_meta_keys = {"review_required", "terraform_version_required", "generated_resources", "warnings"}
            assert set(metadata.keys()) == expected_meta_keys
            assert isinstance(metadata["warnings"], list)
            assert len(metadata["warnings"]) > 0



if __name__ == "__main__":
    # This allows running the tests directly with python
    pytest.main([__file__, "-v"])