# Basic Elasticsearch Indexer Module (MVP)

from elasticsearch import Elasticsearch, exceptions
from kafka import KafkaConsumer
import json
import os
import threading
import time # For retries

ES_HOSTS = [os.getenv('ES_HOSTS', 'http://elasticsearch:9200')]
KAFKA_BROKER_ADDRESS = os.getenv('KAFKA_BROKER_ADDRESS', 'kafka:9092')

# Define all Kafka topics this indexer will consume from
KAFKA_TOPICS_TO_CONSUME = {
    'normalized_logs': os.getenv('KAFKA_NORMALIZED_LOGS_TOPIC', 'normalized_logs'),
    'wazuh_alerts': os.getenv('KAFKA_TOPIC_WAZUH_ALERTS', 'wazuh_alerts'),
    'ai_alerts': os.getenv('KAFKA_TOPIC_AI_ALERTS', 'ai_alerts'),
    'correlated_alerts': os.getenv('KAFKA_TOPIC_CORRELATED_ALERTS', 'correlated_alerts'),
    'resolved_security_alerts': os.getenv('KAFKA_TOPIC_RESOLVED_ALERTS', 'resolved_security_alerts')
}

# Define Elasticsearch indices for each topic
ES_INDICES = {
    'normalized_logs': os.getenv('ES_INDEX_NORMALIZED_LOGS', 'normalized_logs'),
    'wazuh_alerts': os.getenv('ES_INDEX_WAZUH_ALERTS', 'wazuh_alerts'),
    'ai_alerts': os.getenv('ES_INDEX_AI_ALERTS', 'ai_alerts'),
    'correlated_alerts': os.getenv('ES_INDEX_CORRELATED_ALERTS', 'correlated_alerts'),
    'resolved_security_alerts': os.getenv('ES_INDEX_RESOLVED_ALERTS', 'resolved_security_alerts')
}

def get_es_client():
    return Elasticsearch(ES_HOSTS)

def create_index_if_not_exists(es_client, index_name):
    """
    Creates an Elasticsearch index with a basic mapping if it does not already exist.
    """
    # Define a basic mapping for security logs/alerts
    # This can be expanded with more specific field types and analysis settings
    mapping = {
        "mappings": {
            "properties": {
                "timestamp": {"type": "date"},
                "processed_timestamp": {"type": "date"},
                "resolved_timestamp": {"type": "date"},
                "source": {"type": "keyword"},
                "log_type": {"type": "keyword"},
                "severity": {"type": "keyword"},
                "confidence": {"type": "keyword"},
                "description": {"type": "text"},
                "message": {"type": "text"},
                "source_ip": {"type": "ip"},
                "user": {"type": "keyword"},
                # Add more fields as needed based on expected log/alert structure
            }
        }
    }
    
    max_retries = 5
    retry_delay = 5 # seconds
    
    for i in range(max_retries):
        try:
            if not es_client.indices.exists(index=index_name):
                es_client.indices.create(index=index_name, body=mapping)
                print(f"Created Elasticsearch index: {index_name}")
            else:
                print(f"Elasticsearch index '{index_name}' already exists.")
            return True
        except exceptions.ConnectionError as e:
            print(f"Connection error to Elasticsearch: {e}. Retrying in {retry_delay}s...")
            time.sleep(retry_delay)
        except Exception as e:
            print(f"Error creating index {index_name}: {e}")
            return False
    print(f"Failed to connect to Elasticsearch after {max_retries} retries. Could not create index {index_name}.")
    return False

def index_data(es_client, index_name, data):
    """
    Indexes data into a specified Elasticsearch index.
    """
    try:
        response = es_client.index(index=index_name, document=data)
        print(f"Indexed document ID: {response['_id']} into index: {index_name}")
    except Exception as e:
        print(f"Error indexing document into {index_name}: {e}")

def consume_and_index(topic_name, es_client):
    """
    Consumes messages from a Kafka topic and indexes them into Elasticsearch.
    """
    consumer = KafkaConsumer(
        KAFKA_TOPICS_TO_CONSUME[topic_name],
        bootstrap_servers=[KAFKA_BROKER_ADDRESS],
        auto_offset_reset='earliest',
        enable_auto_commit=True,
        group_id=f'es-indexer-{topic_name}-group',
        value_deserializer=lambda x: json.loads(x.decode('utf-8'))
    )

    print(f"[*] Listening for messages on topic: {KAFKA_TOPICS_TO_CONSUME[topic_name]}")

    try:
        for message in consumer:
            data = message.value
            print(f"Received data from {topic_name} for indexing: {data}")
            index_data(es_client, ES_INDICES[topic_name], data)
    except KeyboardInterrupt:
        print(f"[*] Shutting down consumer for {topic_name}")
    finally:
        consumer.close()

if __name__ == "__main__":
    es_client = get_es_client()
    threads = []

    for topic_name in KAFKA_TOPICS_TO_CONSUME:
        thread = threading.Thread(target=consume_and_index, args=(topic_name, es_client))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()
