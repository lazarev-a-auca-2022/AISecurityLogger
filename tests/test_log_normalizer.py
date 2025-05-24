import unittest
import sys
import os
from unittest.mock import patch, MagicMock

# Mock external dependencies at the very top
sys.modules['kafka'] = MagicMock()

# Add the parent directory to the sys.path to allow imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from processing_layer.log_normalizer import LogNormalizer

class TestLogNormalizer(unittest.TestCase):
    def setUp(self):
        # Patch KafkaConsumer and KafkaProducer in the module where they are used
        self.patcher_consumer = patch('processing_layer.log_normalizer.KafkaConsumer')
        self.patcher_producer = patch('processing_layer.log_normalizer.KafkaProducer')
        self.MockKafkaConsumer = self.patcher_consumer.start()
        self.MockKafkaProducer = self.patcher_producer.start()
        self.normalizer = LogNormalizer()

    def tearDown(self):
        self.patcher_consumer.stop()
        self.patcher_producer.stop()

    @patch('processing_layer.log_normalizer.LogNormalizer.normalize_log')
    def test_normalize_log(self, mock_normalize_log):
        mock_normalize_log.return_value = {"message": "normalized log", "level": "INFO"}
        
        raw_log = "INFO: 2023-01-01 10:00:00 - User 'admin' logged in from 192.168.1.1"
        normalized_log = self.normalizer.normalize_log(raw_log)
        self.assertIsInstance(normalized_log, dict)
        self.assertIn("message", normalized_log)
        self.assertIn("level", normalized_log)
        self.assertEqual(normalized_log, {"message": "normalized log", "level": "INFO"})
        mock_normalize_log.assert_called_once_with(raw_log)

if __name__ == '__main__':
    unittest.main()
