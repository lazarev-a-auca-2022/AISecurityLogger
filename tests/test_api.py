import unittest
import sys
import os
from unittest.mock import patch, MagicMock

import unittest
import sys
import os
from unittest.mock import patch, MagicMock

# Mock external dependencies at the very top
sys.modules['flask'] = MagicMock()
sys.modules['flask.json'] = MagicMock()
sys.modules['flask.request'] = MagicMock()
sys.modules['flask.jsonify'] = MagicMock()
sys.modules['flask_cors'] = MagicMock()
sys.modules['flask_cors.CORS'] = MagicMock()
sys.modules['fastapi'] = MagicMock()
sys.modules['fastapi.staticfiles'] = MagicMock()
sys.modules['elasticsearch'] = MagicMock()
sys.modules['kafka'] = MagicMock() # Add kafka mock

# Add the parent directory to the sys.path to allow imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import the api module after setting up all external mocks
import reporting_layer.api as api_module

class TestAPI(unittest.TestCase):
    def setUp(self):
        self.app = api_module.app.test_client()
        self.app.testing = True

    @patch('storage_layer.es_indexer.ESIndexer')
    def test_get_logs(self, MockESIndexer):
        # Configure the mock instance that api.py will use
        mock_es_indexer_instance = MockESIndexer.return_value
        mock_es_indexer_instance.search_logs.return_value = {"hits": {"hits": [{"_source": {"message": "test log"}}]}}

        response = self.app.get('/logs')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"test log", response.data)
        mock_es_indexer_instance.search_logs.assert_called_once()

    @patch('storage_layer.es_indexer.ESIndexer')
    @patch('processing_layer.log_normalizer.LogNormalizer')
    @patch('processing_layer.ai_analysis.ai_analysis_module.AIAnalysisModule')
    def test_post_log(self, MockAIAnalysisModule, MockLogNormalizer, MockESIndexer):
        mock_es_indexer_instance = MockESIndexer.return_value
        mock_log_normalizer_instance = MockLogNormalizer.return_value
        mock_ai_analysis_module_instance = MockAIAnalysisModule.return_value

        mock_log_normalizer_instance.normalize_log.return_value = {"normalized": "log"}
        mock_ai_analysis_module_instance.analyze_log_for_threats.return_value = {"threat_detected": False}
        mock_es_indexer_instance.index_log.return_value = {"result": "created"}

        response = self.app.post('/log', json={"raw_log": "test raw log"})
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Log processed and indexed", response.data)
        mock_log_normalizer_instance.normalize_log.assert_called_once_with("test raw log")
        mock_ai_analysis_module_instance.analyze_log_for_threats.assert_called_once_with({"normalized": "log"})
        mock_es_indexer_instance.index_log.assert_called_once_with({"normalized": "log", "ai_analysis": {"threat_detected": False}})

    @patch('storage_layer.es_indexer.ESIndexer')
    @patch('detection_correlation_layer.correlation_engine.correlation_engine.CorrelationEngine')
    @patch('detection_correlation_layer.conflict_resolution_mechanism.conflict_resolution_mechanism.ConflictResolutionMechanism')
    def test_get_correlated_events(self, MockConflictResolutionMechanism, MockCorrelationEngine, MockESIndexer):
        mock_es_indexer_instance = MockESIndexer.return_value
        mock_correlation_engine_instance = MockCorrelationEngine.return_value
        mock_conflict_resolution_mechanism_instance = MockConflictResolutionMechanism.return_value

        mock_es_indexer_instance.search_logs.return_value = {"hits": {"hits": [{"_source": {"message": "event1"}}, {"_source": {"message": "event2"}}]}}
        mock_correlation_engine_instance.correlate_logs.return_value = [{"correlated": "event"}]
        mock_conflict_resolution_mechanism_instance.resolve_conflict.return_value = [{"resolved": "event"}]

        response = self.app.get('/correlated_events')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"resolved", response.data)
        mock_es_indexer_instance.search_logs.assert_called_once()
        mock_correlation_engine_instance.correlate_logs.assert_called_once()
        mock_conflict_resolution_mechanism_instance.resolve_conflict.assert_called_once()

if __name__ == '__main__':
    unittest.main()
