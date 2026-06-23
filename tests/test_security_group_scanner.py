"""
Unit tests for the security group scanner.
These tests use mocking to avoid requiring actual AWS credentials or resources.
"""

import unittest
from unittest.mock import patch, MagicMock

# Import the function to test
from app.services.security_group_scanner import scan_security_groups


class TestSecurityGroupScanner(unittest.TestCase):

    def _configure_mock(self, mock_boto_client, sg_response):
        """
        Configure the mocked boto3.client to return a global client for describe_regions
        and a regional client that returns the provided security group response.
        """
        # Mock the global EC2 client (used for describe_regions)
        mock_global_client = MagicMock()
        mock_global_client.describe_regions.return_value = {
            'Regions': [{'RegionName': 'us-east-1'}]
        }

        # Mock the regional EC2 client (used for describe_security_groups)
        mock_regional_client = MagicMock()
        mock_regional_client.describe_security_groups.return_value = sg_response

        # side_effect returns the global client first, then the regional client
        mock_boto_client.side_effect = [mock_global_client, mock_regional_client]

    @patch('app.services.security_group_scanner.boto3.client')
    def test_no_insecure_rules(self, mock_boto_client):
        """Test when no security groups have insecure rules."""
        # Security group with no inbound rules
        sg_response = {
            'SecurityGroups': [
                {
                    'GroupId': 'sg-0123456789abcdef0',
                    'GroupName': 'test-sg',
                    'IpPermissions': []  # No inbound rules
                }
            ]
        }
        self._configure_mock(mock_boto_client, sg_response)

        # Call the function
        result = scan_security_groups(None)

        # Assertions
        self.assertEqual(result['status'], 'completed')
        self.assertEqual(result['findings_count'], 0)
        self.assertEqual(len(result['findings']), 0)

    @patch('app.services.security_group_scanner.boto3.client')
    def test_ssh_open_to_world(self, mock_boto_client):
        """Test detection of SSH open to 0.0.0.0/0."""
        # Security group with SSH open to the world
        sg_response = {
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
        self._configure_mock(mock_boto_client, sg_response)

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
        # Security group with RDP open to the world
        sg_response = {
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
        self._configure_mock(mock_boto_client, sg_response)

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
        # Security group with both issues
        sg_response = {
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
        self._configure_mock(mock_boto_client, sg_response)

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
        # Mock the EC2 client to raise an Exception on describe_security_groups
        mock_global_client = MagicMock()
        mock_global_client.describe_regions.return_value = {
            'Regions': [{'RegionName': 'us-east-1'}]
        }
        mock_regional_client = MagicMock()
        mock_regional_client.describe_security_groups.side_effect = Exception('AccessDenied')
        mock_boto_client.side_effect = [mock_global_client, mock_regional_client]

        # Call the function
        result = scan_security_groups(None)

        # Assertions
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(result['findings_count'], 0)
        self.assertEqual(len(result['findings']), 1)
        self.assertEqual(result['findings'][0]['issue'], 'Scan failed')
        self.assertIn("Failed to scan any regions", result["findings"][0]["details"])

    # NEW TESTS FOR THE UPDATED LOGIC

    @patch('app.services.security_group_scanner.boto3.client')
    def test_ssh_detected_in_port_range(self, mock_boto_client):
        """Test that SSH is detected when a port range includes port 22."""
        # Security group with a TCP port range 20-30 open to the world
        sg_response = {
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
        self._configure_mock(mock_boto_client, sg_response)

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
        # Security group with IpProtocol: '-1' open to the world
        sg_response = {
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
        self._configure_mock(mock_boto_client, sg_response)

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