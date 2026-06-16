"""
Unit tests for the security group scanner.
These tests use mocking to avoid requiring actual AWS credentials or resources.
"""

import unittest
from unittest.mock import patch, MagicMock

# Import the function to test
from app.services.security_group_scanner import scan_security_groups


class TestSecurityGroupScanner(unittest.TestCase):

    @patch('app.services.security_group_scanner.boto3.client')
    def test_no_insecure_rules(self, mock_boto_client):
        """Test when no security groups have insecure rules."""
        # Mock the EC2 client and its describe_security_groups method
        mock_ec2 = MagicMock()
        mock_boto_client.return_value = mock_ec2

        # Return a security group with no inbound rules to 0.0.0.0/0 on ports 22 or 3389
        mock_ec2.describe_security_groups.return_value = {
            'SecurityGroups': [
                {
                    'GroupId': 'sg-0123456789abcdef0',
                    'GroupName': 'test-sg',
                    'IpPermissions': []  # No inbound rules
                }
            ]
        }

        # Call the function
        result = scan_security_groups(None)

        # Assertions
        self.assertEqual(result['status'], 'completed')
        self.assertEqual(result['findings_count'], 0)
        self.assertEqual(len(result['findings']), 0)

    @patch('app.services.security_group_scanner.boto3.client')
    def test_ssh_open_to_world(self, mock_boto_client):
        """Test detection of SSH open to 0.0.0.0/0."""
        # Mock the EC2 client
        mock_ec2 = MagicMock()
        mock_boto_client.return_value = mock_ec2

        # Return a security group with SSH open to the world
        mock_ec2.describe_security_groups.return_value = {
            'SecurityGroups': [
                {
                    'GroupId': 'sg-0123456789abcdef0',
                    'GroupName': 'test-sg',
                    'IpPermissions': [
                        {
                            'IpProtocol': 'tcp',
                            'FromPort': 22,
                            'ToPort': 22,
                            'IpRanges': [
                                {'CidrIp': '0.0.0.0/0'}
                            ]
                        }
                    ]
                }
            ]
        }

        # Call the function
        result = scan_security_groups(None)

        # Assertions
        self.assertEqual(result['status'], 'completed')
        self.assertEqual(result['findings_count'], 1)
        self.assertEqual(len(result['findings']), 1)

        finding = result['findings'][0]
        self.assertEqual(finding['group_id'], 'sg-0123456789abcdef0')
        self.assertEqual(finding['group_name'], 'test-sg')
        self.assertEqual(finding['issue'], 'SSH open to 0.0.0.0/0')
        self.assertIn('Protocol: tcp', finding['details'])
        self.assertIn('Ports: 22-22', finding['details'])
        self.assertIn('Source: 0.0.0.0/0', finding['details'])
        self.assertEqual(finding['direction'], 'ingress')

    @patch('app.services.security_group_scanner.boto3.client')
    def test_rdp_open_to_world(self, mock_boto_client):
        """Test detection of RDP open to 0.0.0.0/0."""
        # Mock the EC2 client
        mock_ec2 = MagicMock()
        mock_boto_client.return_value = mock_ec2

        # Return a security group with RDP open to the world
        mock_ec2.describe_security_groups.return_value = {
            'SecurityGroups': [
                {
                    'GroupId': 'sg-0123456789abcdef1',
                    'GroupName': 'another-sg',
                    'IpPermissions': [
                        {
                            'IpProtocol': 'tcp',
                            'FromPort': 3389,
                            'ToPort': 3389,
                            'IpRanges': [
                                {'CidrIp': '0.0.0.0/0'}
                            ]
                        }
                    ]
                }
            ]
        }

        # Call the function
        result = scan_security_groups(None)

        # Assertions
        self.assertEqual(result['status'], 'completed')
        self.assertEqual(result['findings_count'], 1)
        self.assertEqual(len(result['findings']), 1)

        finding = result['findings'][0]
        self.assertEqual(finding['group_id'], 'sg-0123456789abcdef1')
        self.assertEqual(finding['group_name'], 'another-sg')
        self.assertEqual(finding['issue'], 'RDP open to 0.0.0.0/0')
        self.assertIn('Protocol: tcp', finding['details'])
        self.assertIn('Ports: 3389-3389', finding['details'])
        self.assertIn('Source: 0.0.0.0/0', finding['details'])
        self.assertEqual(finding['direction'], 'ingress')

    @patch('app.services.security_group_scanner.boto3.client')
    def test_multiple_violations_same_sg(self, mock_boto_client):
        """Test a security group with both SSH and RDP open to world."""
        # Mock the EC2 client
        mock_ec2 = MagicMock()
        mock_boto_client.return_value = mock_ec2

        # Return a security group with both issues
        mock_ec2.describe_security_groups.return_value = {
            'SecurityGroups': [
                {
                    'GroupId': 'sg-0123456789abcdef2',
                    'GroupName': 'violating-sg',
                    'IpPermissions': [
                        {
                            'IpProtocol': 'tcp',
                            'FromPort': 22,
                            'ToPort': 22,
                            'IpRanges': [
                                {'CidrIp': '0.0.0.0/0'}
                            ]
                        },
                        {
                            'IpProtocol': 'tcp',
                            'FromPort': 3389,
                            'ToPort': 3389,
                            'IpRanges': [
                                {'CidrIp': '0.0.0.0/0'}
                            ]
                        }
                    ]
                }
            ]
        }

        # Call the function
        result = scan_security_groups(None)

        # Assertions
        self.assertEqual(result['status'], 'completed')
        self.assertEqual(result['findings_count'], 2)
        self.assertEqual(len(result['findings']), 2)

        # Check that we have one finding for SSH and one for RDP
        issues = [f['issue'] for f in result['findings']]
        self.assertIn('SSH open to 0.0.0.0/0', issues)
        self.assertIn('RDP open to 0.0.0.0/0', issues)

    @patch('app.services.security_group_scanner.boto3.client')
    def test_aws_api_error(self, mock_boto_client):
        """Test handling of AWS API errors."""
        # Mock the EC2 client to raise an exception
        mock_ec2 = MagicMock()
        mock_boto_client.return_value = mock_ec2
        mock_ec2.describe_security_groups.side_effect = Exception('AccessDenied')

        # Call the function
        result = scan_security_groups(None)

        # Assertions
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(result['findings_count'], 0)
        self.assertEqual(len(result['findings']), 1)
        self.assertEqual(result['findings'][0]['issue'], 'Scan failed')
        self.assertIn('AccessDenied', result['findings'][0]['details'])

    # NEW TESTS FOR THE UPDATED LOGIC

    @patch('app.services.security_group_scanner.boto3.client')
    def test_ssh_detected_in_port_range(self, mock_boto_client):
        """Test that SSH is detected when a port range includes port 22."""
        # Mock the EC2 client
        mock_ec2 = MagicMock()
        mock_boto_client.return_value = mock_ec2

        # Return a security group with a TCP port range 20-30 open to the world
        mock_ec2.describe_security_groups.return_value = {
            'SecurityGroups': [
                {
                    'GroupId': 'sg-0123456789abcdef3',
                    'GroupName': 'range-sg',
                    'IpPermissions': [
                        {
                            'IpProtocol': 'tcp',
                            'FromPort': 20,
                            'ToPort': 30,
                            'IpRanges': [
                                {'CidrIp': '0.0.0.0/0'}
                            ]
                        }
                    ]
                }
            ]
        }

        # Call the function
        result = scan_security_groups(None)

        # Assertions
        self.assertEqual(result['status'], 'completed')
        self.assertEqual(result['findings_count'], 1)
        self.assertEqual(len(result['findings']), 1)

        finding = result['findings'][0]
        self.assertEqual(finding['group_id'], 'sg-0123456789abcdef3')
        self.assertEqual(finding['group_name'], 'range-sg')
        self.assertEqual(finding['issue'], 'SSH open to 0.0.0.0/0')
        # Details should show the port range
        self.assertIn('Protocol: tcp', finding['details'])
        self.assertIn('Ports: 20-30', finding['details'])
        self.assertIn('Source: 0.0.0.0/0', finding['details'])
        self.assertEqual(finding['direction'], 'ingress')

    @patch('app.services.security_group_scanner.boto3.client')
    def test_all_traffic_rule_detected(self, mock_boto_client):
        """Test that an \"All Traffic\" rule (IpProtocol = '-1') is detected."""
        # Mock the EC2 client
        mock_ec2 = MagicMock()
        mock_boto_client.return_value = mock_ec2

        # Return a security group with IpProtocol: '-1' open to the world
        mock_ec2.describe_security_groups.return_value = {
            'SecurityGroups': [
                {
                    'GroupId': 'sg-0123456789abcdef4',
                    'GroupName': 'all-traffic-sg',
                    'IpPermissions': [
                        {
                            'IpProtocol': '-1',
                            # FromPort and ToPort may be absent for '-1'
                            'IpRanges': [
                                {'CidrIp': '0.0.0.0/0'}
                            ]
                        }
                    ]
                }
            ]
        }

        # Call the function
        result = scan_security_groups(None)

        # Assertions
        self.assertEqual(result['status'], 'completed')
        self.assertEqual(result['findings_count'], 1)
        self.assertEqual(len(result['findings']), 1)

        finding = result['findings'][0]
        self.assertEqual(finding['group_id'], 'sg-0123456789abcdef4')
        self.assertEqual(finding['group_name'], 'all-traffic-sg')
        self.assertEqual(finding['issue'], 'All Traffic open to 0.0.0.0/0')
        # Details should reflect the protocol and source
        self.assertIn('Protocol: -1', finding['details'])
        self.assertIn('Source: 0.0.0.0/0', finding['details'])
        self.assertEqual(finding['direction'], 'ingress')


if __name__ == '__main__':
    unittest.main()