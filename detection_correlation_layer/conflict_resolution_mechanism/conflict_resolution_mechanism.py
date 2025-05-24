import os
import json
from kafka import KafkaConsumer
from elasticsearch import Elasticsearch

KAFKA_BROKER_ADDRESS = os.getenv('KAFKA_BROKER_ADDRESS', 'kafka:9092')
KAFKA_TOPIC_CORRELATED_ALERTS = os.getenv('KAFKA_TOPIC_CORRELATED_ALERTS', 'correlated_alerts')
ES_HOSTS = os.getenv('ES_HOSTS', 'http://elasticsearch:9200').split(',')
ES_INDEX_RESOLVED_ALERTS = os.getenv('ES_INDEX_RESOLVED_ALERTS', 'resolved_security_alerts')

def get_es_client():
    return Elasticsearch(ES_HOSTS)

def consume_messages(topic):
    consumer = KafkaConsumer(
        topic,
        bootstrap_servers=KAFKA_BROKER_ADDRESS,
        auto_offset_reset='earliest',
        enable_auto_commit=True,
        group_id=f'conflict_resolution_group',
        value_deserializer=lambda x: json.loads(x.decode('utf-8'))
    )
    return consumer

from datetime import datetime

def resolve_conflict(correlated_alert):
    """
    Conflict resolution logic:
    Analyzes 'wazuh_alert' and 'ai_alert' within the correlated_alert
    to determine the final confidence, severity, and status.
    Prioritizes alerts based on defined confidence levels and rules.
    """
    print(f"Resolving conflict for alert: {correlated_alert.get('description')}")

    wazuh_alert = correlated_alert.get("wazuh_alert")
    ai_alert = correlated_alert.get("ai_alert")

    resolved_alert = correlated_alert.copy()
    resolved_alert["resolved_timestamp"] = datetime.utcnow().isoformat() + 'Z'
    resolved_alert["status"] = "resolved"
    resolved_alert["severity"] = "Medium" # Default severity

    resolution_notes = []

    if wazuh_alert and ai_alert:
        # Both Wazuh and AI alerts are present
        resolution_notes.append("Both Wazuh and AI alerts contributed.")

        # Example rule: If AI analysis indicates Critical or Attack Attempt, set severity to Critical
        ai_analysis_text = ai_alert.get("ai_analysis", "").lower()
        if "critical" in ai_analysis_text or "attack attempt" in ai_analysis_text:
            resolved_alert["severity"] = "Critical"
            resolution_notes.append("AI analysis indicated critical threat, setting severity to Critical.")
        elif "suspicious activity" in ai_analysis_text:
            resolved_alert["severity"] = "High"
            resolution_notes.append("AI analysis indicated suspicious activity, setting severity to High.")
        
        # Further rules could compare Wazuh's rule level/severity with AI's categorization
        # For instance, if Wazuh's rule level is very high, it might override AI's lower severity.
        # wazuh_level = wazuh_alert.get("rule", {}).get("level")
        # if wazuh_level and wazuh_level >= 10: # Example: Wazuh rule level 10+ is critical
        #     resolved_alert["severity"] = "Critical"
        #     resolution_notes.append("Wazuh rule level indicated critical threat.")

    elif wazuh_alert:
        resolved_alert["severity"] = wazuh_alert.get("rule", {}).get("level", 5) # Use Wazuh level as severity
        resolved_alert["source_priority"] = "Wazuh_Only"
        resolution_notes.append("Only Wazuh alert present.")
    elif ai_alert:
        # If only AI alert is present, try to infer severity from AI analysis text
        ai_analysis_text = ai_alert.get("ai_analysis", "").lower()
        if "critical" in ai_analysis_text:
            resolved_alert["severity"] = "Critical"
        elif "suspicious activity" in ai_analysis_text or "warning" in ai_analysis_text:
            resolved_alert["severity"] = "High"
        else:
            resolved_alert["severity"] = "Low"
        resolved_alert["source_priority"] = "AI_Only"
        resolution_notes.append("Only AI alert present.")
    else:
        resolved_alert["severity"] = "Unknown"
        resolution_notes.append("No specific alerts found for resolution.")

    resolved_alert["resolution_notes"] = " | ".join(resolution_notes)
    return resolved_alert

def store_resolved_alert(es_client, alert_data):
    try:
        es_client.index(index=ES_INDEX_RESOLVED_ALERTS, document=alert_data)
        print(f"Stored resolved alert: {alert_data.get('description')}")
    except Exception as e:
        print(f"Error storing resolved alert in Elasticsearch: {e}")

def main():
    es_client = get_es_client()
    consumer = consume_messages(KAFKA_TOPIC_CORRELATED_ALERTS)

    print(f"Conflict Resolution Mechanism started. Consuming from {KAFKA_TOPIC_CORRELATED_ALERTS}")

    for message in consumer:
        correlated_alert = message.value
        resolved_alert = resolve_conflict(correlated_alert)
        store_resolved_alert(es_client, resolved_alert)

if __name__ == "__main__":
    main()
