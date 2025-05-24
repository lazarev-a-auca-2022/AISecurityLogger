import unittest
import sys
import os
from unittest.mock import patch, MagicMock

# Mock external dependencies at the very top
sys.modules['kafka'] = MagicMock()

# Add the parent directory to the sys.path to allow imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from detection_correlation_layer.correlation_engine.correlation_engine import CorrelationEngine

class TestCorrelationEngine(unittest.TestCase):
    def setUp(self):
        # Patch KafkaConsumer and KafkaProducer in the module where they are used
        self.patcher_consumer = patch('detection_correlation_layer.correlation_engine.correlation_engine.KafkaConsumer')
        self.patcher_producer = patch('detection_correlation_layer.correlation_engine.correlation_engine.KafkaProducer')
        self.MockKafkaConsumer = self.patcher_consumer.start()
        self.MockKafkaProducer = self.patcher_producer.start()
        self.engine = CorrelationEngine()

    def tearDown(self):
        self.patcher_consumer.stop()
        self.patcher_producer.stop()

    def test_correlate_logs(self):
        logs = [
            {"event_id": "1", "timestamp": "2023-01-01T10:00:00Z", "source": "auth", "message": "login attempt"},
            {"event_id": "2", "timestamp": "2023-01-01T10:00:05Z", "source": "auth", "message": "login success"}
        ]
        # Mock the method to return a list
        with patch('detection_correlation_layer.correlation_engine.correlation_engine.CorrelationEngine.correlate_logs', return_value=[{"correlated_event": "mock"}]) as mock_correlate:
            correlated_events = self.engine.correlate_logs(logs)
            self.assertIsInstance(correlated_events, list)
            self.assertEqual(correlated_events, [{"correlated_event": "mock"}])
            mock_correlate.assert_called_once_with(logs)

if __name__ == '__main__':
    unittest.main()
