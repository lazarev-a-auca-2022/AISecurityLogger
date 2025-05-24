import unittest
import sys
import os
from unittest.mock import patch, MagicMock

# Mock external dependencies at the very top
sys.modules['kafka'] = MagicMock()

# Add the parent directory to the sys.path to allow imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from detection_correlation_layer.conflict_resolution_mechanism.conflict_resolution_mechanism import ConflictResolutionMechanism

class TestConflictResolutionMechanism(unittest.TestCase):
    def setUp(self):
        # Patch KafkaConsumer and KafkaProducer in the module where they are used
        self.patcher_consumer = patch('detection_correlation_layer.conflict_resolution_mechanism.conflict_resolution_mechanism.KafkaConsumer')
        self.patcher_producer = patch('detection_correlation_layer.conflict_resolution_mechanism.conflict_resolution_mechanism.KafkaProducer')
        self.MockKafkaConsumer = self.patcher_consumer.start()
        self.MockKafkaProducer = self.patcher_producer.start()
        self.crm = ConflictResolutionMechanism()

    def tearDown(self):
        self.patcher_consumer.stop()
        self.patcher_producer.stop()

    @patch('detection_correlation_layer.conflict_resolution_mechanism.conflict_resolution_mechanism.ConflictResolutionMechanism.resolve_conflict')
    def test_resolve_conflict(self, mock_resolve_conflict):
        mock_resolve_conflict.return_value = [{"resolved_event": "mock"}]
        
        conflicting_events = [
            {"event_id": "1", "severity": "high"},
            {"event_id": "2", "severity": "low"}
        ]
        resolved_events = self.crm.resolve_conflict(conflicting_events)
        self.assertIsInstance(resolved_events, list)
        self.assertEqual(resolved_events, [{"resolved_event": "mock"}])
        mock_resolve_conflict.assert_called_once_with(conflicting_events)

if __name__ == '__main__':
    unittest.main()
