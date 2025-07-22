import requests
import time
import sys

MAX_RETRIES = 30
RETRY_INTERVAL = 5  # seconds

def check_ollama_health():
    for i in range(MAX_RETRIES):
        try:
            response = requests.get("http://localhost:11434")
            if response.status_code == 200:
                print(f"Ollama is healthy after {i+1} attempts!")
                return True
        except Exception as e:
            pass
        
        print(f"Attempt {i+1}/{MAX_RETRIES}: Ollama not ready yet, retrying in {RETRY_INTERVAL}s...")
        time.sleep(RETRY_INTERVAL)
    
    print("Failed to verify Ollama health after maximum retries")
    return False

if __name__ == "__main__":
    if check_ollama_health():
        sys.exit(0)
    else:
        sys.exit(1)