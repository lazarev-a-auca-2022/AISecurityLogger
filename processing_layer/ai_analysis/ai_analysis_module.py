from fastapi import FastAPI
import google.generativeai as genai
import os
import json
from kafka import KafkaProducer
from typing import List

app = FastAPI()

# Global variable for the generative model
gemini_model = None
kafka_producer = None

KAFKA_BROKER_ADDRESS = os.getenv('KAFKA_BROKER_ADDRESS', 'kafka:9092')
KAFKA_TOPIC_AI_ALERTS = os.getenv('KAFKA_TOPIC_AI_ALERTS', 'ai_alerts')

@app.on_event("startup")
async def startup_event():
    """
    Configure Google AI Studio and load the generative model on startup.
    Initialize Kafka producer.
    """
    global gemini_model, kafka_producer
    google_api_key = os.getenv("GOOGLE_API_KEY")
    if not google_api_key:
        print("GOOGLE_API_KEY environment variable not set. AI analysis will not function.")
        return

    try:
        genai.configure(api_key=google_api_key)
        gemini_model = genai.GenerativeModel('gemini-pro') # Or 'gemini-1.5-pro-latest' or other suitable model
        print("Google AI Studio model loaded successfully.")
    except Exception as e:
        print(f"Could not configure Google AI Studio or load model: {e}")
        gemini_model = None

    try:
        kafka_producer = KafkaProducer(
            bootstrap_servers=[KAFKA_BROKER_ADDRESS],
            value_serializer=lambda x: json.dumps(x).encode('utf-8')
        )
        print("Kafka Producer initialized successfully.")
    except Exception as e:
        print(f"Could not initialize Kafka Producer: {e}")
        kafka_producer = None

@app.post("/analyze_logs") # Changed endpoint name for batch processing
async def analyze_logs(logs_data: List[dict]):
    """
    Analyze incoming log data (batch) using the Google AI Studio model.
    """
    if gemini_model is None:
        print("Google AI Studio model not loaded. Cannot perform analysis.")
        return {"analysis": "error", "message": "AI model not loaded or configured."}

    results = []
    for log_data in logs_data:
        # In a full implementation, consider using a fine-tuned model for security-specific data
        # For now, using a general-purpose Gemini model.
        input_text = f"Analyze the following security log for potential threats, anomalies, or important events. Provide a concise summary and categorize the event (e.g., 'Informational', 'Warning', 'Critical', 'Suspicious Activity', 'Attack Attempt'):\n\n{log_data}"

        try:
            response = gemini_model.generate_content(input_text)
            analysis_result_text = response.text
        except Exception as e:
            print(f"Error during AI analysis for log: {log_data}. Error: {e}")
            results.append({"analysis": "error", "message": f"AI analysis failed for log: {e}", "log_data": log_data})
            continue

        print(f"Received log data for analysis: {log_data}")
        print(f"AI Analysis result: {analysis_result_text}")

        analysis_result = {
            "timestamp": datetime.utcnow().isoformat() + 'Z', # Use current UTC timestamp
            "source": "ai_analysis_module",
            "log_data": log_data,
            "ai_analysis": analysis_result_text
        }

        if kafka_producer:
            try:
                kafka_producer.send(KAFKA_TOPIC_AI_ALERTS, analysis_result)
                kafka_producer.flush()
                print(f"Sent AI analysis result to Kafka topic: {KAFKA_TOPIC_AI_ALERTS}")
            except Exception as e:
                print(f"Error sending AI analysis result to Kafka: {e}")
        else:
            print("Kafka Producer not initialized. Cannot send AI analysis result to Kafka.")
        
        results.append({"status": "success", "analysis_result": analysis_result})

    return {"status": "success", "results": results}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
