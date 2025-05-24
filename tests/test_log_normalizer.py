import unittest
import sys
import os
from unittest.mock import patch, MagicMock

# Mock external dependencies at the very top
sys.modules['kafka'] = MagicMock()

# Add the parent directory to the sys.path to allow imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from processing_layer import log_normalizer

class TestLogNormalizer(unittest.TestCase):
    def setUp(self):
        # Patch KafkaConsumer and KafkaProducer in the module where they are used
        self.patcher_consumer = patch('processing_layer.log_normalizer.KafkaConsumer')
        self.patcher_producer = patch('processing_layer.log_normalizer.KafkaProducer')
        self.MockKafkaConsumer = self.patcher_consumer.start()
        self.MockKafkaProducer = self.patcher_producer.start()

    def tearDown(self):
        self.patcher_consumer.stop()
        self.patcher_producer.stop()

    def test_normalize_log(self):
        raw_log = '{"level": "INFO", "message": "User login", "timestamp": "2023-01-01T10:00:00Z"}'
        normalized_log = log_normalizer.normalize_log(raw_log)
        self.assertIsInstance(normalized_log, dict)
        self.assertIn("processed_timestamp", normalized_log)
        self.assertIn("log_type", normalized_log)
        self.assertEqual(normalized_log["level"], "INFO")
        self.assertEqual(normalized_log["message"], "User login")

    def test_normalize_log_invalid_json(self):
        raw_log = "This is not valid JSON"
        normalized_log = log_normalizer.normalize_log(raw_log)
        self.assertIsInstance(normalized_log, dict)
        self.assertEqual(normalized_log["log_type"], "raw_json_decode_error")
        self.assertEqual(normalized_log["message"], raw_log)

if __name__ == '__main__':
    unittest.main()
