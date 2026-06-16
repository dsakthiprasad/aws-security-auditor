import boto3
from botocore.exceptions import ClientError
import uuid
from datetime import datetime, timezone


def scan_iam(request):
    """
    Scan IAM for security issues:
    - Users without MFA
    - Active access keys older than 90 days
    - Users with AdministratorAccess (via direct managed, group managed, inline user, or inline group policies)

    Args:
        request: The incoming request object (ScanRequest)

    Returns:
        A dictionary containing:
            - scan_id: A unique identifier for this scan (UUID string).
            - status: Either 'completed' or 'failed'.
            - findings_count: The number of findings.
            - findings: A list of finding dictionaries, each containing:
                - user: The IAM username.
                - issue: A description of the issue.
                - details: Additional details about the issue.
    """
    findings = []
    scan_id = str(uuid.uuid4())

    try:
        # Create an IAM client (IAM is a global service)
        iam_client = boto3.client('iam')

        # Use a paginator to handle potentially large numbers of users
        paginator = iam_client.get_paginator('list_users')
        for page in paginator.paginate():
            for user in page['Users']:
                username = user['UserName']

                # Check 1: MFA status
                mfa_response = iam_client.list_mfa_devices(UserName=username)
                if len(mfa_response['MFADevices']) == 0:
                    findings.append({
                        "user": username,
                        "issue": "User does not have MFA enabled",
                        "details": f"IAM user '{username}' has no MFA devices configured"
                    })

                # Check 2: Active access keys older than 90 days
                keys_response = iam_client.list_access_keys(UserName=username)
                for key in keys_response['AccessKeyMetadata']:
                    # We only care about active keys
                    if key['Status'] == 'Active':
                        key_age_days = (datetime.now(timezone.utc) - key['CreateDate']).days
                        if key_age_days > 90:
                            findings.append({
                                "user": username,
                                "issue": "Access key older than 90 days",
                                "details": (
                                    f"Access key '{key['AccessKeyId']}' "
                                    f"created {key_age_days} days ago "
                                    f"(created: {key['CreateDate'].strftime('%Y-%m-%d')})"
                                )
                            })

                # Check 3: AdministratorAccess (4-way check)
                has_admin, admin_reason = _check_administrator_access(iam_client, username)
                if has_admin:
                    findings.append({
                        "user": username,
                        "issue": "User has AdministratorAccess privileges",
                        "details": f"IAM user '{username}' has AdministratorAccess via {admin_reason}"
                    })

        return {
            "scan_id": scan_id,
            "status": "completed",
            "findings_count": len(findings),
            "findings": findings
        }

    except ClientError as e:
        # Handle AWS service errors
        return {
            "scan_id": scan_id,
            "status": "failed",
            "findings_count": 0,
            "findings": [{
                "issue": "IAM scan failed due to AWS API error",
                "details": str(e)
            }]
        }
    except Exception as e:
        # Handle unexpected errors
        return {
            "scan_id": scan_id,
            "status": "failed",
            "findings_count": 0,
            "findings": [{
                "issue": "Unexpected error during IAM scan",
                "details": str(e)
            }]
        }


def _check_administrator_access(iam_client, username):
    """
    Check if a user has AdministratorAccess via any of four methods:
    1. Directly attached managed policy
    2. Group-attached managed policy
    3. Inline user policy
    4. Inline group policy

    Returns:
        tuple: (boolean, reason_string)
               reason_string describes how AdministratorAccess was found (or None if not found)
    """
    # 1. Directly attached managed policies
    attached_user_policies = iam_client.list_attached_user_policies(UserName=username)
    for policy in attached_user_policies['AttachedPolicies']:
        if policy['PolicyArn'] == 'arn:aws:iam::aws:policy/AdministratorAccess':
            return True, "direct managed policy"

    # 2. Group-attached managed policies
    groups_for_user = iam_client.list_groups_for_user(UserName=username)
    for group in groups_for_user['Groups']:
        group_name = group['GroupName']
        attached_group_policies = iam_client.list_attached_group_policies(GroupName=group_name)
        for policy in attached_group_policies['AttachedPolicies']:
            if policy['PolicyArn'] == 'arn:aws:iam::aws:policy/AdministratorAccess':
                return True, f"group '{group_name}' managed policy"

    # 3. Inline user policies
    user_policy_names = iam_client.list_user_policies(UserName=username)['PolicyNames']
    for policy_name in user_policy_names:
        user_policy = iam_client.get_user_policy(UserName=username, PolicyName=policy_name)
        if _policy_grants_admin_access(user_policy['PolicyDocument']):
            return True, f"inline user policy '{policy_name}'"

    # 4. Inline group policies (check each group the user belongs to)
    for group in groups_for_user['Groups']:
        group_name = group['GroupName']
        group_policy_names = iam_client.list_group_policies(GroupName=group_name)['PolicyNames']
        for policy_name in group_policy_names:
            group_policy = iam_client.get_group_policy(GroupName=group_name, PolicyName=policy_name)
            if _policy_grants_admin_access(group_policy['PolicyDocument']):
                return True, f"inline group policy '{policy_name}' in group '{group_name}'"

    return False, None


def _policy_grants_admin_access(policy_doc):
    """
    Determine if a policy document grants AdministratorAccess equivalent.
    We consider a policy to grant AdministratorAccess if it contains at least one
    statement that allows all actions (*) on all resources (*).

    Args:
        policy_doc: The policy document dictionary (from get_user_policy or get_group_policy)

    Returns:
        bool: True if the policy grants AdministratorAccess equivalent, False otherwise.
    """
    # Policy document structure: {"Version": "...", "Statement": [ {...}, {...} ]}
    statements = policy_doc.get('Statement', [])
    # Ensure we are working with a list
    if not isinstance(statements, list):
        statements = [statements]

    for statement in statements:
        # We only care about Allow statements
        if statement.get('Effect') != 'Allow':
            continue

        action = statement.get('Action')
        resource = statement.get('Resource')

        # Normalize action and resource to lists for comparison
        if isinstance(action, str):
            action = [action]
        if isinstance(resource, str):
            resource = [resource]

        # Check for the wildcard: Action=["*"] and Resource=["*"]
        # Also allow if action list contains "*" and resource list contains "*"
        if ("*" in action) and ("*" in resource):
            return True

    return False