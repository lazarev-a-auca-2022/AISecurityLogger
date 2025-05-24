import unittest
import sys
import os
from unittest.mock import patch, MagicMock

# Mock external dependencies at the very top
sys.modules['kafka'] = MagicMock()
sys.modules['elasticsearch'] = MagicMock() # ESIndexer uses Elasticsearch

# Add the parent directory to the sys.path to allow imports from storage_layer
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from storage_layer.es_indexer import ESIndexer

class TestESIndexer(unittest.TestCase):
    def setUp(self):
        # ESIndexer constructor might try to connect to Elasticsearch, so mock it
        # Patch the class itself, so any instance created will be a mock
        with patch('storage_layer.es_indexer.Elasticsearch') as MockElasticsearch:
            self.es_indexer = ESIndexer("test_index")
            self.mock_es_client = MockElasticsearch.return_value # This is the mock instance

    def test_index_log(self):
        log_entry = {"message": "test log", "level": "info"}
        self.es_indexer.index_log(log_entry)
        self.mock_es_client.index.assert_called_once_with(index="test_index", document=log_entry)

    def test_search_logs(self):
        query = {"match_all": {}}
        self.mock_es_client.search.return_value = {"hits": {"hits": []}} # Mock return value
        result = self.es_indexer.search_logs(query)
        self.mock_es_client.search.assert_called_once_with(index="test_index", body=query)
        self.assertEqual(result, {"hits": {"hits": []}})

    def tearDown(self):
        pass

if __name__ == '__main__':
    unittest.main()
