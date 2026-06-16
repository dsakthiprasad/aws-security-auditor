import boto3
from botocore.exceptions import ClientError
import uuid


def scan_aws_account(request):
    """
    Scan an AWS account for publicly accessible S3 buckets.

    This function lists all S3 buckets in the account and checks each bucket's
    Access Control List (ACL) for grants that allow public read, write, or full
    control access to 'AllUsers' (everyone on the internet) or
    'AuthenticatedUsers' (any AWS account holder).

    Args:
        request: The incoming request object (not used in this function,
                 kept for API compatibility).

    Returns:
        A dictionary containing:
            - scan_id: A unique identifier for this scan (UUID string).
            - status: Either 'completed' or 'failed'.
            - findings_count: The number of findings (publicly accessible buckets or errors).
            - findings: A list of finding dictionaries, each containing:
                - bucket: The name of the S3 bucket.
                - issue: A description of the issue (e.g., "Publicly accessible S3 bucket").
                - details: Additional details about the issue.
    """
    findings = []

    try:
        # Create an S3 client to interact with AWS S3 service
        s3_client = boto3.client('s3')

        # Retrieve a list of all S3 buckets in the account
        response = s3_client.list_buckets()
        buckets = response.get('Buckets', [])

        # Iterate over each bucket to check its ACL for public access
        for bucket in buckets:
            bucket_name = bucket['Name']

            try:
                # Get the Access Control List (ACL) for the current bucket
                acl = s3_client.get_bucket_acl(Bucket=bucket_name)

                # Examine each grant in the ACL
                for grant in acl['Grants']:
                    grantee = grant.get('Grantee', {})
                    uri = grantee.get('URI', '')
                    permission = grant.get('Permission', '')

                    # Check if the grant is for AllUsers or AuthenticatedUsers
                    # and if the permission is READ, WRITE, or FULL_CONTROL
                    if (
                        uri == 'http://acs.amazonaws.com/groups/global/AllUsers'
                        or uri == 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'
                    ) and permission in ['READ', 'WRITE', 'FULL_CONTROL']:

                        # If a public access grant is found, record it as a finding
                        findings.append({
                            "bucket": bucket_name,
                            "issue": "Publicly accessible S3 bucket",
                            "details": (
                                f"Bucket ACL allows {permission} access to "
                                f"{'everyone' if 'AllUsers' in uri else 'authenticated AWS users'}"
                            )
                        })
                        # No need to check further grants for this bucket
                        break

            except ClientError as e:
                # If there's an error checking the bucket's ACL, record it as a finding
                findings.append({
                    "bucket": bucket_name,
                    "issue": "Unable to check bucket ACL",
                    "details": str(e)
                })

        # Return the scan results
        return {
            "scan_id": str(uuid.uuid4()),
            "status": "completed",
            "findings_count": len(findings),
            "findings": findings
        }

    except Exception as e:
        # If an unexpected error occurs during the scan, return a failed status
        return {
            "scan_id": str(uuid.uuid4()),
            "status": "failed",
            "findings_count": 0,
            "findings": [{
                "issue": "Scan failed",
                "details": str(e)
            }]
        }