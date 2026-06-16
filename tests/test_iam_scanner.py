"""
Unit tests for the IAM scanner.
These tests use mocking to avoid requiring actual AWS credentials or resources.
"""

import unittest
from unittest.mock import patch, MagicMock

# Import the function to test
from app.services.iam_scanner import scan_iam


class TestIamScanner(unittest.TestCase):

    @patch('app.services.iam_scanner.boto3.client')
    def test_user_missing_mfa(self, mock_boto_client):
        """Test detection of a user without MFA enabled."""
        # Mock the IAM client
        mock_iam = MagicMock()
        mock_boto_client.return_value = mock_iam

        # Set up the paginator for list_users
        mock_paginator = MagicMock()
        mock_iam.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [{
            'Users': [
                {
                    'UserName': 'test-user-no-mfa',
                    'UserId': 'EXAMPLEUSERID',
                    'Arn': 'arn:aws:iam::123456789012:user/test-user-no-mfa',
                    'CreateDate': '2020-01-01T00:00:00Z'
                }
            ]
        }]

        # Mock list_mfa_devices to return an empty list (no MFA)
        mock_iam.list_mfa_devices.return_value = {'MFADevices': []}

        # Mock list_access_keys to return no active keys (to avoid extra findings)
        mock_iam.list_access_keys.return_value = {'AccessKeyMetadata': []}

        # Call the function
        result = scan_iam(None)

        # Assertions
        self.assertEqual(result['status'], 'completed')
        self.assertEqual(result['findings_count'], 1)
        self.assertEqual(len(result['findings']), 1)

        finding = result['findings'][0]
        self.assertEqual(finding['user'], 'test-user-no-mfa')
        self.assertEqual(finding['issue'], 'User does not have MFA enabled')
        self.assertIn("has no MFA devices configured", finding['details'])

    @patch('app.services.iam_scanner.boto3.client')
    def test_access_key_older_than_90_days(self, mock_boto_client):
        """Test detection of an access key older than 90 days."""
        # Mock the IAM client
        mock_iam = MagicMock()
        mock_boto_client.return_value = mock_iam

        # Set up the paginator for list_users
        mock_paginator = MagicMock()
        mock_iam.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [{
            'Users': [
                {
                    'UserName': 'test-user-old-key',
                    'UserId': 'EXAMPLEUSERID',
                    'Arn': 'arn:aws:iam::123456789012:user/test-user-old-key',
                    'CreateDate': '2020-01-01T00:00:00Z'
                }
            ]
        }]

        # Mock list_mfa_devices to return an MFA device (so we don't get an MFA finding)
        mock_iam.list_mfa_devices.return_value = {'MFADevices': [{'SerialNumber': 'arn:aws:iam::123456789012:mfa/test-user-old-key'}]}

        # Mock list_access_keys to return one active key created 100 days ago
        from datetime import datetime, timezone, timedelta
        key_date = datetime.now(timezone.utc) - timedelta(days=100)
        mock_iam.list_access_keys.return_value = {
            'AccessKeyMetadata': [
                {
                    'UserName': 'test-user-old-key',
                    'AccessKeyId': 'EXAMPLEKEYID',
                    'Status': 'Active',
                    'CreateDate': key_date
                }
            ]
        }

        # Call the function
        result = scan_iam(None)

        # Assertions
        self.assertEqual(result['status'], 'completed')
        self.assertEqual(result['findings_count'], 1)
        self.assertEqual(len(result['findings']), 1)

        finding = result['findings'][0]
        self.assertEqual(finding['user'], 'test-user-old-key')
        self.assertEqual(finding['issue'], 'Access key older than 90 days')
        self.assertIn("Access key 'EXAMPLEKEYID'", finding['details'])
        self.assertIn("100 days ago", finding['details'])

    @patch('app.services.iam_scanner.boto3.client')
    def test_direct_administrator_access_policy(self, mock_boto_client):
        """Test detection of a user with directly attached AdministratorAccess policy."""
        # Mock the IAM client
        mock_iam = MagicMock()
        mock_boto_client.return_value = mock_iam

        # Set up the paginator for list_users
        mock_paginator = MagicMock()
        mock_iam.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [{
            'Users': [
                {
                    'UserName': 'test-user-admin-direct',
                    'UserId': 'EXAMPLEUSERID',
                    'Arn': 'arn:aws:iam::123456789012:user/test-user-admin-direct',
                    'CreateDate': '2020-01-01T00:00:00Z'
                }
            ]
        }]

        # Mock list_mfa_devices to return an MFA device (no MFA finding)
        mock_iam.list_mfa_devices.return_value = {'MFADevices': [{'SerialNumber': 'arn:aws:iam::123456789012:mfa/test-user-admin-direct'}]}

        # Mock list_access_keys to return no active keys
        mock_iam.list_access_keys.return_value = {'AccessKeyMetadata': []}

        # Mock list_attached_user_policies to return the AdministratorAccess policy
        mock_iam.list_attached_user_policies.return_value = {
            'AttachedPolicies': [
                {
                    'PolicyName': 'AdministratorAccess',
                    'PolicyArn': 'arn:aws:iam::aws:policy/AdministratorAccess'
                }
            ]
        }

        # Mock list_groups_for_user to return no groups (to avoid extra checks)
        mock_iam.list_groups_for_user.return_value = {'Groups': []}

        # Mock list_user_policies and list_group_policies to return empty (no inline policies)
        mock_iam.list_user_policies.return_value = {'PolicyNames': []}
        mock_iam.list_group_policies.return_value = {'PolicyNames': []}

        # Call the function
        result = scan_iam(None)

        # Assertions
        self.assertEqual(result['status'], 'completed')
        self.assertEqual(result['findings_count'], 1)
        self.assertEqual(len(result['findings']), 1)

        finding = result['findings'][0]
        self.assertEqual(finding['user'], 'test-user-admin-direct')
        self.assertEqual(finding['issue'], 'User has AdministratorAccess privileges')
        self.assertIn("direct managed policy", finding['details'])

    @patch('app.services.iam_scanner.boto3.client')
    def test_inline_policy_with_wildcard_action_resource(self, mock_boto_client):
        """Test detection of a user with an inline policy that grants AdministratorAccess via wildcards."""
        # Mock the IAM client
        mock_iam = MagicMock()
        mock_boto_client.return_value = mock_iam

        # Set up the paginator for list_users
        mock_paginator = MagicMock()
        mock_iam.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [{
            'Users': [
                {
                    'UserName': 'test-user-inline-admin',
                    'UserId': 'EXAMPLEUSERID',
                    'Arn': 'arn:aws:iam::123456789012:user/test-user-inline-admin',
                    'CreateDate': '2020-01-01T00:00:00Z'
                }
            ]
        }]

        # Mock list_mfa_devices to return an MFA device (no MFA finding)
        mock_iam.list_mfa_devices.return_value = {'MFADevices': [{'SerialNumber': 'arn:aws:iam::123456789012:mfa/test-user-inline-admin'}]}

        # Mock list_access_keys to return no active keys
        mock_iam.list_access_keys.return_value = {'AccessKeyMetadata': []}

        # Mock list_attached_user_policies to return no attached policies
        mock_iam.list_attached_user_policies.return_value = {'AttachedPolicies': []}

        # Mock list_groups_for_user to return no groups
        mock_iam.list_groups_for_user.return_value = {'Groups': []}

        # Mock list_user_policies to return one inline policy name
        mock_iam.list_user_policies.return_value = {'PolicyNames': ['InlineAdminPolicy']}

        # Mock get_user_policy to return a policy document that grants * on *
        mock_iam.get_user_policy.return_value = {
            'PolicyName': 'InlineAdminPolicy',
            'PolicyDocument': {
                'Version': '2012-10-17',
                'Statement': [
                    {
                        'Effect': 'Allow',
                        'Action': '*',
                        'Resource': '*'
                    }
                ]
            }
        }

        # Call the function
        result = scan_iam(None)

        # Assertions
        self.assertEqual(result['status'], 'completed')
        self.assertEqual(result['findings_count'], 1)
        self.assertEqual(len(result['findings']), 1)

        finding = result['findings'][0]
        self.assertEqual(finding['user'], 'test-user-inline-admin')
        self.assertEqual(finding['issue'], 'User has AdministratorAccess privileges')
        self.assertIn("inline user policy 'InlineAdminPolicy'", finding['details'])


# Helper for the timedelta in the second test
from datetime import timedelta

if __name__ == '__main__':
    unittest.main()