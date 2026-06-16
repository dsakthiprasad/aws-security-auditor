import boto3
from botocore.exceptions import ClientError
import uuid


def scan_security_groups(request):
    """
    Scan EC2 Security Groups for insecure inbound rules.

    This function checks all EC2 Security Groups in the account for inbound rules
    that allow SSH (port 22) or RDP (port 3389) from the entire internet (0.0.0.0/0).
    It also detects "All Traffic" rules (IpProtocol = "-1") open to 0.0.0.0/0,
    and port ranges that include the sensitive ports.

    Args:
        request: The incoming request object (not used in this function,
                 kept for API compatibility).

    Returns:
        A dictionary containing:
            - scan_id: A unique identifier for this scan (UUID string).
            - status: Either 'completed' or 'failed'.
            - findings_count: The number of findings (insecure rules found).
            - findings: A list of finding dictionaries, each containing:
                - group_id: The ID of the Security Group (e.g., 'sg-0123456789abcdef0').
                - group_name: The name of the Security Group.
                - issue: A description of the issue (e.g., "SSH open to 0.0.0.0/0",
                         "RDP open to 0.0.0.0/0", or "All Traffic open to 0.0.0.0/0").
                - details: Additional details about the issue (protocol, port, source).
                - direction: Always 'ingress' for this scanner.
    """
    findings = []

    try:
        # Create an EC2 client to interact with AWS EC2 service
        ec2_client = boto3.client('ec2')

        # Retrieve all Security Groups in the account
        response = ec2_client.describe_security_groups()
        security_groups = response.get('SecurityGroups', [])

        # Iterate over each Security Group
        for sg in security_groups:
            group_id = sg['GroupId']
            group_name = sg['GroupName']

            # Check the inbound rules (IpPermissions) of the Security Group
            for permission in sg.get('IpPermissions', []):
                # Get protocol and port range from the permission
                ip_protocol = permission.get('IpProtocol')
                # Use .get to avoid KeyError if FromPort/ToPort are missing (e.g., for "-1")
                from_port = permission.get('FromPort')
                to_port = permission.get('ToPort')

                # Check each IP range in the permission
                for ip_range in permission.get('IpRanges', []):
                    cidr = ip_range.get('CidrIp')
                    # We are only concerned with 0.0.0.0/0 (open to the internet)
                    if cidr == '0.0.0.0/0':
                        # Check for "All Traffic" rule (all protocols, all ports)
                        if ip_protocol == '-1':
                            findings.append({
                                "group_id": group_id,
                                "group_name": group_name,
                                "issue": "All Traffic open to 0.0.0.0/0",
                                "details": f"Protocol: {ip_protocol}, Source: {cidr}",
                                "direction": "ingress"
                            })
                            # No need to check ports for this rule
                            continue

                        # For TCP rules, check if the port range includes SSH or RDP
                        if ip_protocol == 'tcp' and from_port is not None and to_port is not None:
                            # Check for SSH (port 22) in the range
                            if from_port <= 22 <= to_port:
                                findings.append({
                                    "group_id": group_id,
                                    "group_name": group_name,
                                    "issue": "SSH open to 0.0.0.0/0",
                                    "details": f"Protocol: {ip_protocol}, Ports: {from_port}-{to_port}, Source: {cidr}",
                                    "direction": "ingress"
                                })
                            # Check for RDP (port 3389) in the range
                            if from_port <= 3389 <= to_port:
                                findings.append({
                                    "group_id": group_id,
                                    "group_name": group_name,
                                    "issue": "RDP open to 0.0.0.0/0",
                                    "details": f"Protocol: {ip_protocol}, Ports: {from_port}-{to_port}, Source: {cidr}",
                                    "direction": "ingress"
                                })

        # Return the scan results
        return {
            "scan_id": str(uuid.uuid4()),
            "status": "completed",
            "findings_count": len(findings),
            "findings": findings
        }

    except ClientError as e:
        # If there's an error communicating with AWS, return a failed status
        return {
            "scan_id": str(uuid.uuid4()),
            "status": "failed",
            "findings_count": 0,
            "findings": [{
                "issue": "AWS API error",
                "details": str(e)
            }]
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