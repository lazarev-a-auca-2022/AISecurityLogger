# Basic Elasticsearch Indexer Module (MVP)

from elasticsearch import Elasticsearch

# Elasticsearch configuration
import os

ES_HOSTS = [os.getenv('ES_HOSTS', 'http://elasticsearch:9200')]
ES_INDEX = os.getenv('ES_INDEX', 'security_events')

def index_log_data(log_data):
    """
    Indexes normalized log data into Elasticsearch.
    """
    try:
        es = Elasticsearch(ES_HOSTS)

        # Index the document
        response = es.index(index=ES_INDEX, document=log_data)

        print(f"Indexed document ID: {response['_id']}")
        return response['_id']
    except Exception as e:
        print(f"Error indexing document in Elasticsearch: {e}")
        return None

if __name__ == "__main__":
    # This is a basic example of how to use the indexer
    # In a real scenario, this would receive data from the normalization module

    sample_log_data = {
        "timestamp": "2023-10-27T10:00:00Z",
        "level": "info",
        "message": "User login successful",
        "user": "test_user"
    }

    print("Indexing sample log data:")
    index_log_data(sample_log_data)
