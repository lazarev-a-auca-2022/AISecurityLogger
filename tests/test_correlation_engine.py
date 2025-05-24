import unittest
import sys
import os
from unittest.mock import patch, MagicMock

# Mock external dependencies at the very top
sys.modules['kafka'] = MagicMock()
sys.modules['elasticsearch'] = MagicMock()

# Add the parent directory to the sys.path to allow imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from detection_correlation_layer.correlation_engine import correlation_engine

class TestCorrelationEngine(unittest.TestCase):
    def setUp(self):
        # Patch KafkaConsumer and KafkaProducer in the module where they are used
        self.patcher_consumer = patch('detection_correlation_layer.correlation_engine.correlation_engine.KafkaConsumer')
        self.patcher_producer = patch('detection_correlation_layer.correlation_engine.correlation_engine.KafkaProducer')
        self.patcher_es = patch('detection_correlation_layer.correlation_engine.correlation_engine.Elasticsearch')
        self.MockKafkaConsumer = self.patcher_consumer.start()
        self.MockKafkaProducer = self.patcher_producer.start()
        self.MockElasticsearch = self.patcher_es.start()

    def tearDown(self):
        self.patcher_consumer.stop()
        self.patcher_producer.stop()
        self.patcher_es.stop()

    def test_get_es_client(self):
        client = correlation_engine.get_es_client()
        self.MockElasticsearch.assert_called_once()

    def test_get_kafka_producer(self):
        producer = correlation_engine.get_kafka_producer()
        self.MockKafkaProducer.assert_called_once()

    def test_correlate_alerts(self):
        wazuh_alert = {
            "timestamp": "2023-01-01T10:00:00Z",
            "data": {"srcip": "192.168.1.100", "user": "admin"},
            "rule": {"level": 5}
        }
        ai_alert = {
            "timestamp": "2023-01-01T10:00:30Z",
            "log_data": {"source_ip": "192.168.1.100", "user": "admin"},
            "ai_analysis": "Suspicious activity detected"
        }
        
        correlated = correlation_engine.correlate_alerts(wazuh_alert, ai_alert)
        self.assertIsNotNone(correlated)
        self.assertIn("wazuh_alert", correlated)
        self.assertIn("ai_alert", correlated)
        self.assertIn("correlation_details", correlated)

    def test_correlate_alerts_no_match(self):
        wazuh_alert = {
            "timestamp": "2023-01-01T10:00:00Z",
            "data": {"srcip": "192.168.1.100"},
        }
        ai_alert = {
            "timestamp": "2023-01-01T10:00:30Z",
            "log_data": {"source_ip": "192.168.1.200"},  # Different IP
        }
        
        correlated = correlation_engine.correlate_alerts(wazuh_alert, ai_alert)
        self.assertIsNone(correlated)

if __name__ == '__main__':
    unittest.main()
