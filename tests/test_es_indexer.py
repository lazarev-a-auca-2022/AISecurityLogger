import unittest
import sys
import os
from unittest.mock import patch, MagicMock

# Mock external dependencies at the very top
sys.modules['kafka'] = MagicMock()
sys.modules['elasticsearch'] = MagicMock() # es_indexer uses Elasticsearch

# Add the parent directory to the sys.path to allow imports from storage_layer
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from storage_layer import es_indexer

class TestESIndexer(unittest.TestCase):
    def setUp(self):
        # Mock Elasticsearch client
        self.patcher_es = patch('storage_layer.es_indexer.Elasticsearch')
        self.MockElasticsearch = self.patcher_es.start()
        self.mock_es_client = self.MockElasticsearch.return_value

    def tearDown(self):
        self.patcher_es.stop()

    def test_get_es_client(self):
        client = es_indexer.get_es_client()
        self.MockElasticsearch.assert_called_once_with(es_indexer.ES_HOSTS)

    @patch('storage_layer.es_indexer.get_es_client')
    def test_index_data(self, mock_get_es_client):
        mock_es_client = MagicMock()
        mock_get_es_client.return_value = mock_es_client
        
        log_entry = {"message": "test log", "level": "info"}
        es_indexer.index_data(mock_es_client, "test_index", log_entry)
        mock_es_client.index.assert_called_once_with(index="test_index", document=log_entry)

    @patch('storage_layer.es_indexer.get_es_client')
    def test_create_index_if_not_exists(self, mock_get_es_client):
        mock_es_client = MagicMock()
        mock_get_es_client.return_value = mock_es_client
        mock_es_client.indices.exists.return_value = False
        
        result = es_indexer.create_index_if_not_exists(mock_es_client, "test_index")
        mock_es_client.indices.exists.assert_called_once_with(index="test_index")
        mock_es_client.indices.create.assert_called_once()
        self.assertTrue(result)

if __name__ == '__main__':
    unittest.main()
