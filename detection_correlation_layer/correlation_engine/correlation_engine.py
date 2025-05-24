import os
import json
from kafka import KafkaConsumer, KafkaProducer
from elasticsearch import Elasticsearch
from collections import deque
from datetime import datetime, timedelta

KAFKA_BROKER_ADDRESS = os.getenv('KAFKA_BROKER_ADDRESS', 'kafka:9092')
KAFKA_TOPIC_WAZUH_ALERTS = os.getenv('KAFKA_TOPIC_WAZUH_ALERTS', 'wazuh_alerts')
KAFKA_TOPIC_AI_ALERTS = os.getenv('KAFKA_TOPIC_AI_ALERTS', 'ai_alerts')
KAFKA_TOPIC_CORRELATED_ALERTS = os.getenv('KAFKA_TOPIC_CORRELATED_ALERTS', 'correlated_alerts')
ES_HOSTS = os.getenv('ES_HOSTS', 'http://elasticsearch:9200').split(',')
ES_INDEX_ALERTS = os.getenv('ES_INDEX_ALERTS', 'security_alerts')

# Time window for correlation (e.g., 5 minutes)
CORRELATION_WINDOW_SECONDS = int(os.getenv('CORRELATION_WINDOW_SECONDS', 300))

def get_es_client():
    return Elasticsearch(ES_HOSTS)

def get_kafka_producer():
    return KafkaProducer(
        bootstrap_servers=[KAFKA_BROKER_ADDRESS],
        value_serializer=lambda x: json.dumps(x).encode('utf-8')
    )

def consume_messages(topic):
    consumer = KafkaConsumer(
        topic,
        bootstrap_servers=KAFKA_BROKER_ADDRESS,
        auto_offset_reset='earliest',
        enable_auto_commit=True,
        group_id=f'correlation_engine_{topic}_group',
        value_deserializer=lambda x: json.loads(x.decode('utf-8'))
    )
    return consumer

def parse_timestamp(timestamp_str):
    # Assuming timestamp is in ISO format with 'Z' for UTC
    return datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))

def correlate_alerts(wazuh_alert, ai_alert):
    """
    Sophisticated correlation logic:
    - Check if both alerts have a 'timestamp' and 'source_ip' (or 'user') field.
    - Check if timestamps are within the CORRELATION_WINDOW_SECONDS.
    - Check if common identifiers (e.g., source_ip, user) match.
    """
    wazuh_ts = parse_timestamp(wazuh_alert.get("timestamp")) if wazuh_alert.get("timestamp") else None
    ai_ts = parse_timestamp(ai_alert.get("timestamp")) if ai_alert.get("timestamp") else None

    if not wazuh_ts or not ai_ts:
        return None # Cannot correlate without timestamps

    # Check if timestamps are within the correlation window
    if abs((wazuh_ts - ai_ts).total_seconds()) > CORRELATION_WINDOW_SECONDS:
        return None

    # Basic correlation based on common identifiers (e.g., source_ip, user)
    wazuh_ip = wazuh_alert.get("data", {}).get("srcip") or wazuh_alert.get("source_ip")
    ai_ip = ai_alert.get("log_data", {}).get("source_ip") or ai_alert.get("source_ip")

    wazuh_user = wazuh_alert.get("data", {}).get("user") or wazuh_alert.get("user")
    ai_user = ai_alert.get("log_data", {}).get("user") or ai_alert.get("user")

    ip_match = wazuh_ip and ai_ip and (wazuh_ip == ai_ip)
    user_match = wazuh_user and ai_user and (wazuh_user == ai_user)

    if ip_match or user_match:
        correlated_alert = {
            "timestamp": datetime.utcnow().isoformat() + 'Z',
            "source": "correlation_engine",
            "wazuh_alert": wazuh_alert,
            "ai_alert": ai_alert,
            "confidence": "high", # Can be dynamically set based on correlation rules
            "description": "Correlated alert: Wazuh and AI detected a related event.",
            "correlation_details": {
                "matched_on_ip": ip_match,
                "matched_on_user": user_match,
                "wazuh_timestamp": wazuh_ts.isoformat() + 'Z',
                "ai_timestamp": ai_ts.isoformat() + 'Z',
                "time_difference_seconds": abs((wazuh_ts - ai_ts).total_seconds())
            }
        }
        return correlated_alert
    return None

def store_alert(es_client, alert_data):
    try:
        es_client.index(index=ES_INDEX_ALERTS, document=alert_data)
        print(f"Stored alert in Elasticsearch: {alert_data.get('description', 'No description')}")
    except Exception as e:
        print(f"Error storing alert in Elasticsearch: {e}")

def main():
    es_client = get_es_client()
    producer = get_kafka_producer()

    wazuh_consumer = consume_messages(KAFKA_TOPIC_WAZUH_ALERTS)
    ai_consumer = consume_messages(KAFKA_TOPIC_AI_ALERTS)

    # In-memory buffers for alerts
    wazuh_alerts_buffer = deque()
    ai_alerts_buffer = deque()

    print(f"Correlation Engine started. Consuming from {KAFKA_TOPIC_WAZUH_ALERTS} and {KAFKA_TOPIC_AI_ALERTS}")

    while True:
        # Poll for new messages from both consumers
        wazuh_messages = wazuh_consumer.poll(timeout_ms=1000, max_records=10)
        ai_messages = ai_consumer.poll(timeout_ms=1000, max_records=10)

        current_time = datetime.utcnow()

        # Process Wazuh alerts
        if wazuh_messages:
            for tp, messages in wazuh_messages.items():
                for message in messages:
                    wazuh_alert = message.value
                    print(f"Received Wazuh alert: {wazuh_alert}")
                    wazuh_alerts_buffer.append(wazuh_alert)
                    # Store raw Wazuh alert
                    store_alert(es_client, {"source": "wazuh_raw", "alert": wazuh_alert, "timestamp": datetime.utcnow().isoformat() + 'Z'})

        # Process AI alerts
        if ai_messages:
            for tp, messages in ai_messages.items():
                for message in messages:
                    ai_alert = message.value
                    print(f"Received AI alert: {ai_alert}")
                    ai_alerts_buffer.append(ai_alert)
                    # Store raw AI alert
                    store_alert(es_client, {"source": "ai_raw", "alert": ai_alert, "timestamp": datetime.utcnow().isoformat() + 'Z'})

        # Clean up old alerts from buffers and attempt correlation
        # Note: This simple buffer management might miss correlations if events arrive
        # significantly out of order or if the processing loop is slow.
        # A more robust solution would involve persistent storage for buffering
        # and more advanced matching algorithms.

        # Remove old alerts from Wazuh buffer
        while wazuh_alerts_buffer and \
              (current_time - parse_timestamp(wazuh_alerts_buffer[0].get("timestamp", datetime.utcnow().isoformat() + 'Z'))).total_seconds() > CORRELATION_WINDOW_SECONDS:
            wazuh_alerts_buffer.popleft()

        # Remove old alerts from AI buffer
        while ai_alerts_buffer and \
              (current_time - parse_timestamp(ai_alerts_buffer[0].get("timestamp", datetime.utcnow().isoformat() + 'Z'))).total_seconds() > CORRELATION_WINDOW_SECONDS:
            ai_alerts_buffer.popleft()

        # Attempt correlation between buffered alerts
        correlated_count = 0
        for w_alert in list(wazuh_alerts_buffer): # Iterate over a copy to allow modification
            for a_alert in list(ai_alerts_buffer):
                correlated = correlate_alerts(w_alert, a_alert)
                if correlated:
                    print(f"Correlated alert found: {correlated}")
                    store_alert(es_client, correlated)
                    producer.send(KAFKA_TOPIC_CORRELATED_ALERTS, correlated)
                    producer.flush()
                    correlated_count += 1
                    # In a more advanced system, you might remove correlated alerts from buffers
                    # to avoid re-processing, but for simplicity, we keep them for now.
                    # wazuh_alerts_buffer.remove(w_alert) # This is inefficient for deque
                    # ai_alerts_buffer.remove(a_alert) # This is inefficient for deque
        if correlated_count > 0:
            print(f"Successfully correlated and sent {correlated_count} alerts to Kafka topic: {KAFKA_TOPIC_CORRELATED_ALERTS}")

if __name__ == "__main__":
    main()
