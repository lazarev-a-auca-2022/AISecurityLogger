# Basic Log Normalization and Structuring Module (MVP)

from kafka import KafkaConsumer, KafkaProducer
import json
import os
import requests
from datetime import datetime

KAFKA_BROKER_ADDRESS = os.getenv('KAFKA_BROKER_ADDRESS', 'kafka:9092')
KAFKA_RAW_LOGS_TOPIC = os.getenv('KAFKA_RAW_LOGS_TOPIC', 'security_logs')
KAFKA_NORMALIZED_LOGS_TOPIC = os.getenv('KAFKA_NORMALIZED_LOGS_TOPIC', 'normalized_logs')
WAZUH_MANAGER_API = os.getenv('WAZUH_MANAGER_API', 'http://wazuh-manager:55000')

def normalize_log(log_data):
    """
    Placeholder function for log normalization and structuring.
    Replace with actual parsing and normalization logic based on log formats.
    """
    try:
        log_entry = json.loads(log_data)
        
        # Add a processed timestamp
        log_entry['processed_timestamp'] = datetime.utcnow().isoformat() + 'Z'

        # Add a log_type if not present, or infer from existing fields
        if 'log_type' not in log_entry:
            if 'event' in log_entry and 'code' in log_entry['event']:
                log_entry['log_type'] = 'security_event'
            elif 'level' in log_entry and log_entry['level'].lower() in ['error', 'warn', 'info', 'debug']:
                log_entry['log_type'] = 'application_log'
            else:
                log_entry['log_type'] = 'unknown'
        
        # Ensure a 'message' field exists, using raw data if not
        if 'message' not in log_entry:
            log_entry['message'] = log_data # Fallback to raw data if no specific message field

        normalized_log = log_entry
        return normalized_log
    except json.JSONDecodeError:
        print(f"Error decoding JSON: {log_data}. Returning raw data as message.")
        return {
            "processed_timestamp": datetime.utcnow().isoformat() + 'Z',
            "log_type": "raw_json_decode_error",
            "message": log_data
        }
    except Exception as e:
        print(f"Error normalizing log: {e}. Returning raw data as message.")
        return {
            "processed_timestamp": datetime.utcnow().isoformat() + 'Z',
            "log_type": "normalization_error",
            "message": log_data
        }

def send_to_wazuh(log_entry):
    """
    Sends a log entry to the Wazuh manager API.
    This is a simplified example and might need authentication/proper API endpoint.
    """
    try:
        # In a real-world scenario, direct API ingestion of raw logs into Wazuh for analysis
        # is not the primary method. Wazuh typically relies on agents to collect logs
        # or receives logs via syslog/filebeat.
        # If normalized logs are to be sent to Wazuh for rule-based analysis,
        # a more robust integration would involve:
        # 1. Configuring a Wazuh agent to consume from a Kafka topic (e.g., via Filebeat).
        # 2. Using the Wazuh API to add custom alerts based on the normalized data,
        #    rather than raw log ingestion. This would require specific API endpoints
        #    for alert creation, not general log ingestion.
        # For the purpose of this MVP, we are simulating the sending of normalized logs.
        # The actual integration would depend on how Wazuh is configured to receive
        # external log data for its rule engine.
        print(f"Simulating sending normalized log to Wazuh for rule-based analysis: {log_entry}")
        # Example of how you *might* send an alert if a specific Wazuh API endpoint existed for it:
        # headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer YOUR_WAZUH_API_TOKEN'}
        # response = requests.post(f"{WAZUH_MANAGER_API}/alerts", json=log_entry, headers=headers)
        # response.raise_for_status()
        # print(f"Successfully sent alert to Wazuh: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"Error simulating sending log to Wazuh: {e}")

if __name__ == "__main__":
    consumer = KafkaConsumer(
        KAFKA_RAW_LOGS_TOPIC,
        bootstrap_servers=[KAFKA_BROKER_ADDRESS],
        auto_offset_reset='earliest',
        enable_auto_commit=True,
        group_id='log-normalizer-group',
        value_deserializer=lambda x: x.decode('utf-8')
    )

    producer = KafkaProducer(
        bootstrap_servers=[KAFKA_BROKER_ADDRESS],
        value_serializer=lambda x: json.dumps(x).encode('utf-8')
    )

    print(f"[*] Listening for messages on topic: {KAFKA_RAW_LOGS_TOPIC}")
    print(f"[*] Producing normalized logs to topic: {KAFKA_NORMALIZED_LOGS_TOPIC}")

    try:
        for message in consumer:
            log_data = message.value
            print(f"Received message: {log_data}")
            normalized_log = normalize_log(log_data)
            if normalized_log:
                print(f"Normalized log: {normalized_log}")
                producer.send(KAFKA_NORMALIZED_LOGS_TOPIC, normalized_log)
                producer.flush() # Ensure message is sent
                send_to_wazuh(normalized_log) # Send to Wazuh
    except KeyboardInterrupt:
        print("[*] Shutting down consumer and producer")
    finally:
        consumer.close()
        producer.close()
