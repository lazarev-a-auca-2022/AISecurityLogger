import unittest
import sys
import os
from unittest.mock import patch, MagicMock

# Mock external dependencies at the very top
sys.modules['kafka'] = MagicMock()
sys.modules['elasticsearch'] = MagicMock()

# Add the parent directory to the sys.path to allow imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from detection_correlation_layer.conflict_resolution_mechanism import conflict_resolution_mechanism

class TestConflictResolutionMechanism(unittest.TestCase):
    def setUp(self):
        # Patch KafkaConsumer and KafkaProducer in the module where they are used
        self.patcher_consumer = patch('detection_correlation_layer.conflict_resolution_mechanism.conflict_resolution_mechanism.KafkaConsumer')
        self.patcher_es = patch('detection_correlation_layer.conflict_resolution_mechanism.conflict_resolution_mechanism.Elasticsearch')
        self.MockKafkaConsumer = self.patcher_consumer.start()
        self.MockElasticsearch = self.patcher_es.start()

    def tearDown(self):
        self.patcher_consumer.stop()
        self.patcher_es.stop()

    def test_get_es_client(self):
        client = conflict_resolution_mechanism.get_es_client()
        self.MockElasticsearch.assert_called_once()

    def test_resolve_conflict_both_alerts(self):
        correlated_alert = {
            "description": "Test alert",
            "wazuh_alert": {"rule": {"level": 8}},
            "ai_alert": {"ai_analysis": "critical threat detected"}
        }
        
        resolved = conflict_resolution_mechanism.resolve_conflict(correlated_alert)
        self.assertIsInstance(resolved, dict)
        self.assertIn("resolved_timestamp", resolved)
        self.assertIn("status", resolved)
        self.assertIn("severity", resolved)
        self.assertIn("resolution_notes", resolved)
        self.assertEqual(resolved["status"], "resolved")
        self.assertEqual(resolved["severity"], "Critical")

    def test_resolve_conflict_wazuh_only(self):
        correlated_alert = {
            "description": "Test alert",
            "wazuh_alert": {"rule": {"level": 5}},
            "ai_alert": None
        }
        
        resolved = conflict_resolution_mechanism.resolve_conflict(correlated_alert)
        self.assertIsInstance(resolved, dict)
        self.assertEqual(resolved["severity"], 5)
        self.assertEqual(resolved["source_priority"], "Wazuh_Only")

    def test_resolve_conflict_ai_only(self):
        correlated_alert = {
            "description": "Test alert",
            "wazuh_alert": None,
            "ai_alert": {"ai_analysis": "suspicious activity detected"}
        }
        
        resolved = conflict_resolution_mechanism.resolve_conflict(correlated_alert)
        self.assertIsInstance(resolved, dict)
        self.assertEqual(resolved["severity"], "High")
        self.assertEqual(resolved["source_priority"], "AI_Only")

if __name__ == '__main__':
    unittest.main()
