import requests
import json
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

BASE_URL = "http://localhost:8000"

def test_health():
    """Test the health check endpoint"""
    response = requests.get(f"{BASE_URL}/health")
    print(f"Health check status: {response.status_code}")
    print(response.json())
    print("-" * 50)

def create_knowledge_graph():
    """Create a knowledge graph from sample text"""
    url = f"{BASE_URL}/api/process/text"
    payload = {
        "text": "Albert Einstein developed the theory of relativity and was awarded the Nobel Prize in Physics in 1921. He was born in Germany in 1879 and died in Princeton, New Jersey in 1955. His famous equation E=mc² relates energy to mass."
    }
    headers = {"Content-Type": "application/json"}
    
    response = requests.post(url, json=payload, headers=headers)
    print(f"Create knowledge graph status: {response.status_code}")
    print(json.dumps(response.json(), indent=2))
    print("-" * 50)
    
    return response.json().get("graph_id")

def query_knowledge_graph(graph_id):
    """Query the created knowledge graph"""
    url = f"{BASE_URL}/api/query"
    payload = {
        "query": "What did Einstein develop?",
        "graph_id": graph_id
    }
    headers = {"Content-Type": "application/json"}
    
    response = requests.post(url, json=payload, headers=headers)
    print(f"Query status: {response.status_code}")
    print(json.dumps(response.json(), indent=2))
    print("-" * 50)

if __name__ == "__main__":
    print("Testing API endpoints...")
    test_health()
    
    print("Creating knowledge graph...")
    graph_id = create_knowledge_graph()
    
    if graph_id:
        print(f"Querying knowledge graph with ID: {graph_id}")
        query_knowledge_graph(graph_id)
    else:
        print("No graph ID returned, cannot query.")
        
