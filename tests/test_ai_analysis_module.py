import unittest
import sys
import os
from unittest.mock import patch, MagicMock
from datetime import datetime

# Mock external dependencies at the very top
sys.modules['fastapi'] = MagicMock()
sys.modules['google'] = MagicMock()
sys.modules['google.generativeai'] = MagicMock()
sys.modules['kafka'] = MagicMock()

# Add the parent directory to the sys.path to allow imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import the module after setting up mocks
from processing_layer.ai_analysis import ai_analysis_module

class TestAIAnalysisModule(unittest.TestCase):
    def setUp(self):
        pass

    @patch('processing_layer.ai_analysis.ai_analysis_module.genai')
    @patch('processing_layer.ai_analysis.ai_analysis_module.KafkaProducer')
    def test_analyze_logs_endpoint(self, mock_kafka_producer, mock_genai):
        # Mock the behavior of the generative AI model
        mock_model = MagicMock()
        mock_model.generate_content.return_value.text = 'Critical threat detected'
        mock_genai.GenerativeModel.return_value = mock_model
        
        # Mock Kafka producer
        mock_producer_instance = MagicMock()
        mock_kafka_producer.return_value = mock_producer_instance
        
        # Set up the global variables
        ai_analysis_module.gemini_model = mock_model
        ai_analysis_module.kafka_producer = mock_producer_instance
        
        # Test data
        logs_data = [{"message": "Suspicious activity detected: multiple failed login attempts"}]
        
        # This would normally be called via FastAPI, but we're testing the logic
        import asyncio
        result = asyncio.run(ai_analysis_module.analyze_logs(logs_data))
        
        self.assertIsInstance(result, dict)
        self.assertEqual(result["status"], "success")
        self.assertIn("results", result)
        self.assertEqual(len(result["results"]), 1)

    def test_fastapi_app_creation(self):
        # Test that the FastAPI app is created
        self.assertIsNotNone(ai_analysis_module.app)
        # The app should be a mock due to our mocking

if __name__ == '__main__':
    unittest.main()
