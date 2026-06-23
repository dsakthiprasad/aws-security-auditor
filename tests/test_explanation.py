import os
import unittest
from unittest.mock import patch, Mock

from app import constants
from app.services.explanation import (
    get_security_explanation,
    _get_explanation_from_llm,
    FALLBACK_EXPLANATIONS,
)


class TestExplanationService(unittest.TestCase):

    def setUp(self):
        _get_explanation_from_llm.cache_clear()
        os.environ["GEMINI_API_KEY"] = "test-api-key"

    def tearDown(self):
        if "GEMINI_API_KEY" in os.environ:
            del os.environ["GEMINI_API_KEY"]

    @patch("app.services.explanation.genai.GenerativeModel")
    @patch("app.services.explanation.genai.configure")
    def test_successful_llm_response(self, mock_configure, mock_model_class):
        """Gemini returns a valid explanation."""

        mock_model = Mock()
        mock_response = Mock()
        mock_response.text = "This is a test explanation."

        mock_model.generate_content.return_value = mock_response
        mock_model_class.return_value = mock_model

        explanation = get_security_explanation(
            constants.S3_PUBLIC_BUCKET,
            "Bucket is public."
        )

        self.assertEqual(explanation, "This is a test explanation.")

        mock_configure.assert_called_once_with(api_key="test-api-key")
        mock_model.generate_content.assert_called_once()

    @patch("app.services.explanation.genai.GenerativeModel")
    @patch("app.services.explanation.genai.configure")
    def test_api_failure_triggers_fallback(self, mock_configure, mock_model_class):
        """Gemini failure should return fallback explanation."""

        mock_model = Mock()
        mock_model.generate_content.side_effect = Exception("Gemini API failure")
        mock_model_class.return_value = mock_model

        explanation = get_security_explanation(
            constants.S3_PUBLIC_BUCKET,
            ""
        )

        self.assertEqual(
            explanation,
            FALLBACK_EXPLANATIONS[constants.S3_PUBLIC_BUCKET]
        )

    def test_missing_api_key(self):
        """Missing API key returns an error."""

        del os.environ["GEMINI_API_KEY"]

        explanation = get_security_explanation(
            constants.S3_PUBLIC_BUCKET,
            ""
        )

        self.assertTrue(
            explanation.startswith("Error: GEMINI_API_KEY")
        )

    @patch("app.services.explanation.genai.GenerativeModel")
    @patch("app.services.explanation.genai.configure")
    def test_cache(self, mock_configure, mock_model_class):
        """LLM should only be called once because of lru_cache."""

        mock_model = Mock()
        mock_response = Mock()
        mock_response.text = "Cached explanation"

        mock_model.generate_content.return_value = mock_response
        mock_model_class.return_value = mock_model

        explanation1 = get_security_explanation(
            constants.IAM_OLD_KEY,
            "same"
        )

        explanation2 = get_security_explanation(
            constants.IAM_OLD_KEY,
            "same"
        )

        self.assertEqual(explanation1, "Cached explanation")
        self.assertEqual(explanation2, "Cached explanation")

        self.assertEqual(
            mock_model.generate_content.call_count,
            1
        )


if __name__ == "__main__":
    unittest.main()