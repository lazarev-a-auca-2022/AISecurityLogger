from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from elasticsearch import Elasticsearch
import os

app = FastAPI()

# Elasticsearch configuration
ES_HOSTS = [os.getenv('ES_HOSTS', 'http://elasticsearch:9200')]
ES_INDEX = os.getenv('ES_INDEX', 'security_events')

# Mount static files
app.mount("/", StaticFiles(directory=".", html=True), name="static")

@app.get("/api/reports")
def get_reports():
    # Placeholder for fetching and returning reports
    return {"reports": []}

@app.get("/api/alerts")
def get_alerts():
    # Placeholder for fetching and returning alerts
    return {"alerts": []}

@app.get("/api/logs")
async def get_logs(size: int = 100):
    """
    Fetches logs from Elasticsearch.
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
        res = es.search(index=ES_INDEX, body=search_body)
        logs = [hit['_source'] for hit in res['hits']['hits']]
        return {"logs": logs}
    except Exception as e:
        print(f"Error fetching logs from Elasticsearch: {e}")
        return {"logs": [], "error": str(e)}
