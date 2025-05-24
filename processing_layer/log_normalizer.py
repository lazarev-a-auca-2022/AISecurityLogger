# Basic Log Normalization and Structuring Module (MVP)

from kafka import KafkaConsumer
import json

# Kafka configuration
import os

KAFKA_BROKER_ADDRESS = os.getenv('KAFKA_BROKER_ADDRESS', 'kafka:9092')
KAFKA_TOPIC = os.getenv('KAFKA_TOPIC', 'security_logs')

def normalize_log(log_data):
    """
    Placeholder function for log normalization and structuring.
    Replace with actual parsing and normalization logic based on log formats.
    """
    # Assuming log_data is a JSON string for this example
    try:
        log_entry = json.loads(log_data)
        # Perform normalization and structuring here
        # For example, add a timestamp if not present, rename fields, etc.
        normalized_log = log_entry # Replace with actual normalized data
        return normalized_log
    except json.JSONDecodeError:
        print(f"Error decoding JSON: {log_data}")
        return None
    except Exception as e:
        print(f"Error normalizing log: {e}")
        return None

if __name__ == "__main__":
    consumer = KafkaConsumer(
        KAFKA_TOPIC,
        bootstrap_servers=[KAFKA_BROKER_ADDRESS],
        auto_offset_reset='earliest',
        enable_auto_commit=True,
        group_id='log-normalizer-group',
        value_deserializer=lambda x: x.decode('utf-8')
    )

    print(f"[*] Listening for messages on topic: {KAFKA_TOPIC}")

    try:
        for message in consumer:
            log_data = message.value
            print(f"Received message: {log_data}")
            normalized_log = normalize_log(log_data)
            if normalized_log:
                print(f"Normalized log: {normalized_log}")
                # TODO: Add logic to send normalized log to the next stage (e.g., Wazuh, Storage)
    except KeyboardInterrupt:
        print("[*] Shutting down consumer")
    finally:
        consumer.close()
