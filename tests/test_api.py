import unittest
import sys
import os
from unittest.mock import patch, MagicMock
import asyncio

# Mock external dependencies at the very top
sys.modules['fastapi'] = MagicMock()
sys.modules['fastapi.staticfiles'] = MagicMock()
sys.modules['elasticsearch'] = MagicMock()

# Add the parent directory to the sys.path to allow imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import the api module after setting up all external mocks
from reporting_layer import api

class TestAPI(unittest.TestCase):
    def setUp(self):
        pass

    @patch('reporting_layer.api.Elasticsearch')
    def test_get_alerts(self, MockElasticsearch):
        # Configure the mock Elasticsearch instance
        mock_es_instance = MockElasticsearch.return_value
        mock_es_instance.search.return_value = {
            "hits": {
                "hits": [
                    {"_source": {"description": "test alert", "timestamp": "2023-01-01T10:00:00Z"}}
                ]
            }
        }

        # Test the get_alerts function
        result = asyncio.run(api.get_alerts(size=10))
        
        self.assertIsInstance(result, dict)
        self.assertIn("alerts", result)
        self.assertEqual(len(result["alerts"]), 1)
        self.assertEqual(result["alerts"][0]["description"], "test alert")
        mock_es_instance.search.assert_called_once()

    @patch('reporting_layer.api.Elasticsearch')
    def test_get_logs(self, MockElasticsearch):
        # Configure the mock Elasticsearch instance
        mock_es_instance = MockElasticsearch.return_value
        mock_es_instance.search.return_value = {
            "hits": {
                "hits": [
                    {"_source": {"message": "test log", "level": "info"}}
                ]
            }
        }

        # Test the get_logs function
        result = asyncio.run(api.get_logs(size=10))
        
        self.assertIsInstance(result, dict)
        self.assertIn("logs", result)
        self.assertEqual(len(result["logs"]), 1)
        self.assertEqual(result["logs"][0]["message"], "test log")
        mock_es_instance.search.assert_called_once()

    @patch('reporting_layer.api.Elasticsearch')
    def test_get_alerts_with_error(self, MockElasticsearch):
        # Configure the mock to raise an exception
        mock_es_instance = MockElasticsearch.return_value
        mock_es_instance.search.side_effect = Exception("Connection error")

        # Test the get_alerts function with error
        result = asyncio.run(api.get_alerts())
        
        self.assertIsInstance(result, dict)
        self.assertIn("alerts", result)
        self.assertIn("error", result)
        self.assertEqual(result["alerts"], [])
        self.assertEqual(result["error"], "Connection error")

    def test_fastapi_app_creation(self):
        # Test that the FastAPI app is created
        self.assertIsNotNone(api.app)

if __name__ == '__main__':
    unittest.main()
