import unittest
import sys
import os
from unittest.mock import patch, MagicMock

# Mock FastAPI before importing ai_analysis_module
sys.modules['fastapi'] = MagicMock()

# Add the parent directory to the sys.path to allow imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import the module after setting up mocks
from processing_layer.ai_analysis.ai_analysis_module import AIAnalysisModule

class TestAIAnalysisModule(unittest.TestCase):
    def setUp(self):
        self.ai_module = AIAnalysisModule()

    @patch('google.generativeai')
    def test_analyze_log_for_threats(self, mock_genai):
        # This is a placeholder test. Actual implementation would involve
        # mocking the AI model and defining specific test cases for threat detection.
        log_entry = {"message": "Suspicious activity detected: multiple failed login attempts"}
        
        # Mock the behavior of the generative AI model
        mock_model = MagicMock()
        mock_model.generate_content.return_value.text = '{"threat_detected": true, "severity": "high"}'
        mock_genai.GenerativeModel.return_value = mock_model

        analysis_result = self.ai_module.analyze_log_for_threats(log_entry)
        self.assertIsInstance(analysis_result, dict)
        self.assertIn("threat_detected", analysis_result)
        self.assertIn("severity", analysis_result)
        self.assertEqual(analysis_result, {"threat_detected": True, "severity": "high"})
        mock_genai.GenerativeModel.assert_called_once_with("gemini-pro")
        mock_model.generate_content.assert_called_once()

if __name__ == '__main__':
    unittest.main()
