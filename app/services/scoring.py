"""
Compliance Scoring Engine for AWS Security Auditor.

This module implements the scoring algorithm that calculates a security score
based on findings from various scanners (S3, Security Group, IAM, etc.).
"""

from typing import List, Dict, Any, Optional
from app.constants import (
    S3_PUBLIC_BUCKET,
    SG_SSH_OPEN,
    SG_RDP_OPEN,
    SG_ALL_TRAFFIC_OPEN,
    IAM_NO_MFA,
    IAM_OLD_KEY,
    IAM_ADMIN_ACCESS,
    SCANNER_ERROR_FINDINGS
)


def calculate_security_score(findings: List[Dict[str, Any]]) -> int:
    """
    Calculate a security score based on findings.

    Args:
        findings: List of finding dictionaries from scanners

    Returns:
        Integer score between 0 and 100
    """
    # Start with perfect score
    score = 100

    # Define scoring matrix with points per finding and maximum penalty per category
    # Format: {issue_type: {"points_per_finding": int, "max_penalty": int}}
    scoring_matrix = {
        S3_PUBLIC_BUCKET: {"points_per_finding": 15, "max_penalty": 30},
        SG_SSH_OPEN: {"points_per_finding": 12, "max_penalty": 24},
        SG_RDP_OPEN: {"points_per_finding": 12, "max_penalty": 24},
        SG_ALL_TRAFFIC_OPEN: {"points_per_finding": 18, "max_penalty": 36},
        IAM_NO_MFA: {"points_per_finding": 8, "max_penalty": 24},
        IAM_OLD_KEY: {"points_per_finding": 4, "max_penalty": 12},
        IAM_ADMIN_ACCESS: {"points_per_finding": 10, "max_penalty": 20}
    }

    # Track penalties applied per category to enforce maximum penalties
    category_penalties = {issue_type: 0 for issue_type in scoring_matrix}

    # Process each finding
    for finding in findings:
        issue_type = finding.get("issue", "")

        # Skip error findings (scanner failures)
        if issue_type in SCANNER_ERROR_FINDINGS:
            continue

        # Check if we have scoring rules for this issue type
        if issue_type not in scoring_matrix:
            # Ignore unknown issue types rather than failing
            continue

        rule = scoring_matrix[issue_type]
        points_per_finding = rule["points_per_finding"]
        max_penalty = rule["max_penalty"]

        # Apply points per finding, but don't exceed the maximum penalty for this category
        current_penalty = category_penalties[issue_type]
        potential_new_penalty = current_penalty + points_per_finding

        if potential_new_penalty <= max_penalty:
            # We can apply the full penalty for this finding
            score -= points_per_finding
            category_penalties[issue_type] = potential_new_penalty
        # If we've already reached the max penalty, skip additional deductions

    # Ensure score doesn't go below 0
    return max(0, score)


def determine_risk_level(score: int) -> str:
    """
    Determine risk level based on security score.

    Args:
        score: Security score (0-100)

    Returns:
        Risk level string
    """
    if score >= 90:
        return "Low Risk"
    elif score >= 70:
        return "Medium Risk"
    elif score >= 40:
        return "High Risk"
    else:
        return "Critical Risk"


def calculate_severity_breakdown(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    """
    Calculate severity breakdown from findings.

    Args:
        findings: List of finding dictionaries from scanners

    Returns:
        Dictionary with counts for each severity level
    """
    # Initialize breakdown
    breakdown = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0
    }

    # Define severity mapping
    severity_mapping = {
        S3_PUBLIC_BUCKET: "critical",
        SG_SSH_OPEN: "high",
        SG_RDP_OPEN: "high",
        SG_ALL_TRAFFIC_OPEN: "critical",
        IAM_NO_MFA: "medium",
        IAM_OLD_KEY: "low",
        IAM_ADMIN_ACCESS: "high"
    }

    # Count each finding by severity
    for finding in findings:
        issue_type = finding.get("issue", "")

        # Skip error findings
        if issue_type in SCANNER_ERROR_FINDINGS:
            continue

        # Map to severity if we know it
        if issue_type in severity_mapping:
            severity = severity_mapping[issue_type]
            breakdown[severity] += 1

    return breakdown


def compute_scan_results(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Compute all scoring-related results for a scan.

    Args:
        findings: List of finding dictionaries from scanners

    Returns:
        Dictionary containing security_score, risk_level, and severity_breakdown
    """
    security_score = calculate_security_score(findings)
    risk_level = determine_risk_level(security_score)
    severity_breakdown = calculate_severity_breakdown(findings)

    return {
        "security_score": security_score,
        "risk_level": risk_level,
        "severity_breakdown": severity_breakdown
    }