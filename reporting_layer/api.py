from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from elasticsearch import Elasticsearch
import os

app = FastAPI()

# Elasticsearch configuration
ES_HOSTS = [os.getenv('ES_HOSTS', 'http://elasticsearch:9200')]
ES_INDEX_NORMALIZED_LOGS = os.getenv('ES_INDEX_NORMALIZED_LOGS', 'normalized_logs')
ES_INDEX_RESOLVED_ALERTS = os.getenv('ES_INDEX_RESOLVED_ALERTS', 'resolved_security_alerts')

# Mount static files
app.mount("/", StaticFiles(directory=".", html=True), name="static")

@app.get("/api/reports")
def get_reports():
    # Placeholder for fetching and returning reports
    return {"reports": []}

@app.get("/api/alerts")
async def get_alerts(size: int = 100):
    """
    Fetches resolved security alerts from Elasticsearch.
    """
    try:
        es = Elasticsearch(ES_HOSTS)
        search_body = {
            "size": size,
            "query": {
                "match_all": {}
            },
            "sort": [
                {"timestamp": {"order": "desc"}} # Assuming a timestamp field
            ]
        }
        res = es.search(index=ES_INDEX_RESOLVED_ALERTS, body=search_body)
        alerts = [hit['_source'] for hit in res['hits']['hits']]
        return {"alerts": alerts}
    except Exception as e:
        print(f"Error fetching alerts from Elasticsearch: {e}")
        return {"alerts": [], "error": str(e)}

@app.get("/api/logs")
async def get_logs(size: int = 100):
    """
    Fetches normalized logs from Elasticsearch.
    """
    try:
        es = Elasticsearch(ES_HOSTS)
        search_body = {
            "size": size,
            "query": {
                "match_all": {}
            },
            "sort": [
                {"@timestamp": {"order": "desc"}} # Assuming a timestamp field
            ]
        }
        res = es.search(index=ES_INDEX_NORMALIZED_LOGS, body=search_body)
        logs = [hit['_source'] for hit in res['hits']['hits']]
        return {"logs": logs}
    except Exception as e:
        print(f"Error fetching logs from Elasticsearch: {e}")
        return {"logs": [], "error": str(e)}
