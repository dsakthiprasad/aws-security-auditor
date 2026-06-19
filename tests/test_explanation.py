import unittest
from unittest.mock import patch, Mock
import requests

from app import constants
from app.services.explanation import get_security_explanation, _get_explanation_from_llm, FALLBACK_EXPLANATIONS


class TestExplanationService(unittest.TestCase):

    def setUp(self):
        # Clear the cache before each test to ensure isolation
        _get_explanation_from_llm.cache_clear()

    @patch('app.services.explanation.requests.post')
    def test_successful_llm_response(self, mock_post):
        """Test A: Verify a successful mocked LLM response returns correctly."""
        # Arrange
        mock_response = Mock()
        mock_response.json.return_value = {"response": "This is a test explanation."}
        mock_response.raise_for_status.return_value = None
        mock_post.return_value = mock_response

        issue_type = constants.S3_PUBLIC_BUCKET
        details = "Bucket named 'test-bucket' is publicly readable."

        # Act
        explanation = get_security_explanation(issue_type, details)

        # Assert
        self.assertEqual(explanation, "This is a test explanation.")
        mock_post.assert_called_once()
        # Check that the request was made with the correct parameters
        args, kwargs = mock_post.call_args
        self.assertEqual(args[0], "http://localhost:11434/api/generate")
        self.assertEqual(kwargs["json"]["model"], "qwen2.5:1.5b")
        self.assertIn("prompt", kwargs["json"])
        self.assertEqual(kwargs["timeout"], 10)

    @patch('app.services.explanation.requests.post')
    def test_timeout_triggers_fallback(self, mock_post):
        """Test B: Verify that a requests.exceptions.Timeout triggers the graceful fallback string."""
        # Arrange
        mock_post.side_effect = requests.exceptions.Timeout("Request timed out")

        issue_type = constants.S3_PUBLIC_BUCKET
        details = ""

        # Act
        explanation = get_security_explanation(issue_type, details)

        # Assert
        self.assertEqual(explanation, FALLBACK_EXPLANATIONS[issue_type])
        mock_post.assert_called_once()

    @patch('app.services.explanation.requests.post')
    def test_connection_error_triggers_fallback(self, mock_post):
        """Test C: Verify that a requests.exceptions.ConnectionError triggers the graceful fallback."""
        # Arrange
        mock_post.side_effect = requests.exceptions.ConnectionError("Failed to connect")

        issue_type = constants.SG_SSH_OPEN
        details = ""

        # Act
        explanation = get_security_explanation(issue_type, details)

        # Assert
        self.assertEqual(explanation, FALLBACK_EXPLANATIONS[issue_type])
        mock_post.assert_called_once()

    @patch('app.services.explanation.requests.post')
    def test_caching_prevents_duplicate_calls(self, mock_post):
        """Test D: Verify the caching mechanism works (mock is only called once for duplicate requests)."""
        # Arrange
        mock_response = Mock()
        mock_response.json.return_value = {"response": "Cached explanation."}
        mock_response.raise_for_status.return_value = None
        mock_post.return_value = mock_response

        issue_type = constants.IAM_OLD_KEY
        details = "Access key AKIA... created 100 days ago."

        # Act
        explanation1 = get_security_explanation(issue_type, details)
        explanation2 = get_security_explanation(issue_type, details)

        # Assert
        self.assertEqual(explanation1, "Cached explanation.")
        self.assertEqual(explanation2, "Cached explanation.")
        # The mock should have been called only once due to caching
        mock_post.assert_called_once()

        # Also verify that different arguments produce different calls (cache miss)
        mock_post.reset_mock()
        explanation3 = get_security_explanation(issue_type, "Different details")
        self.assertEqual(explanation3, "Cached explanation.")  # Still cached from the first call? Wait, different details.
        # Actually, the second call with different details should not hit the cache for the first call.
        # But note: we are using the same issue_type but different details, so it's a different cache key.
        # However, we reset the mock and then made a new call with different details.
        # The mock should be called again.
        self.assertEqual(mock_post.call_count, 1)
        # And the explanation should be the same because we returned the same mocked response.
        self.assertEqual(explanation3, "Cached explanation.")


if __name__ == '__main__':
    unittest.main()