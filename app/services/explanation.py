"""
AI Explanation service using local Ollama LLM.
"""
import json
import logging
from functools import lru_cache
from pathlib import Path
from typing import Optional

import requests

from app import constants

logger = logging.getLogger(__name__)

# Fallback explanations for when Ollama is unavailable
FALLBACK_EXPLANATIONS = {
    constants.S3_PUBLIC_BUCKET: (
        "This S3 bucket is publicly accessible, allowing anyone on the internet to read or write "
        "depending on the permissions. Attackers could exploit this to leak sensitive data, host "
        "malicious content, or use the bucket as a launch point for further attacks."
    ),
    constants.SG_SSH_OPEN: (
        "The security group allows inbound SSH (port 22) from any IP address (0.0.0.0/0). "
        "This exposes the instance to brute-force attacks and unauthorized access attempts. "
        "An attacker could try to guess credentials or exploit SSH vulnerabilities to gain control."
    ),
    constants.SG_RDP_OPEN: (
        "The security group allows inbound RDP (port 3389) from any IP address (0.0.0.0/0). "
        "This makes the instance vulnerable to remote desktop attacks, including credential "
        "guessing and exploitation of RDP vulnerabilities. Attackers could gain full control of "
        "the Windows instance."
    ),
    constants.SG_ALL_TRAFFIC_OPEN: (
        "The security group allows all traffic (all ports and protocols) from any IP address. "
        "This completely exposes the instance to the internet, eliminating any network-based "
        "protection. Attackers can reach any service running on the instance and exploit any "
        "vulnerabilities they find."
    ),
    constants.IAM_NO_MFA: (
        "The IAM user does not have multi-factor authentication enabled, relying only on a "
        "password for authentication. If the password is compromised through phishing, leakage, "
        "or brute force, the attacker gains full access to the user's permissions. "
        "Enabling MFA adds a critical second factor that significantly increases security."
    ),
    constants.IAM_OLD_KEY: (
        "The access key is older than 90 days, increasing the risk of compromise if the key "
        "has been leaked or stolen without rotation. Long-lived keys are more likely to be "
        "exposed in code repositories, logs, or adversary collections. Regular key rotation "
        "limits the window of opportunity for attackers to use a stolen key."
    ),
    constants.IAM_ADMIN_ACCESS: (
        "The IAM user has AdministratorAccess privileges, granting full control over all AWS "
        "resources in the account. If the user's credentials are compromised, an attacker could "
        "perform any action, including deleting data, launching expensive instances, or creating "
        "backdoors for persistent access."
    ),
}


def _load_prompt_template() -> str:
    """
    Load the prompt template from app/prompts/explanation.txt.
    """
    template_path = Path(__file__).parent.parent / "prompts" / "explanation.txt"
    return template_path.read_text(encoding="utf-8")


def _format_prompt(issue_type: str, details: str = "") -> str:
    """
    Format the prompt template with the given issue type and details.
    """
    template = _load_prompt_template()
    return template.format(issue_type=issue_type, details=details)


@lru_cache(maxsize=128)
def _get_explanation_from_llm(issue_type: str, details: str) -> str:
    """
    Get explanation from the local Ollama LLM.
    Raises requests.exceptions.RequestException on failure.
    """
    prompt = _format_prompt(issue_type, details)
    payload = {
        "model": "qwen2.5:1.5b",
        "prompt": prompt,
        "stream": False,
    }
    response = requests.post(
        "http://localhost:11434/api/generate",
        json=payload,
        timeout=10,
    )
    response.raise_for_status()
    result = response.json()
    # The Ollama API returns a JSON with a "response" field containing the generated text.
    explanation = result.get("response", "").strip()
    if not explanation:
        raise ValueError("Empty response from Ollama")
    return explanation


def get_security_explanation(issue_type: str, details: str = "") -> str:
    """
    Get a concise security explanation for the given AWS issue type.
    Uses local Ollama LLM with fallback to hardcoded explanations on failure.
    Results are cached for performance.

    Args:
        issue_type: The type of AWS vulnerability (e.g., "S3_PUBLIC_BUCKET")
        details: Additional context about the finding (optional)

    Returns:
        A 2-3 sentence explanation of the security risk and potential exploit.
    """
    try:
        return _get_explanation_from_llm(issue_type, details)
    except (requests.exceptions.Timeout, requests.exceptions.ConnectionError,
            requests.exceptions.RequestException, ValueError) as e:
        logger.warning(f"Failed to get explanation from Ollama for {issue_type}: {e}. Using fallback.")
        # Return fallback explanation if available, otherwise a generic message.
        return FALLBACK_EXPLANATIONS.get(
            issue_type,
            f"Security issue detected: {issue_type}. Please review AWS security best practices "
            f"to mitigate potential risks associated with this finding."
        )