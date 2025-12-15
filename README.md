# Network Security Graph RAG

A network security analyzer that builds knowledge graphs from network traffic data and uses AI to answer security questions.

## What It Does

- **Ingests network traffic** - Supports CSV files from UNSW-NB15, CICIDS2017, and similar datasets
- **Builds a graph** - Creates a Neo4j knowledge graph of IPs, ports, and connections
- **Detects anomalies** - Uses ML (Isolation Forest) to find suspicious patterns
- **Answers questions** - Ask about your network in plain English using RAG

## Getting Started

### Requirements

- Docker & Docker Compose
- A Groq API key (free tier works)

### Setup

1. Clone this repo
2. Copy `.env.example` to `.env` and add your Groq API key
3. Run `docker compose up -d`
4. Check health: `curl http://localhost:8000/health`

### Adding Your Data

Drop CSV files into `backend/sample_data/` and restart, or upload via API:

```bash
curl -X POST http://localhost:8000/api/network/upload-csv -F "file=@your_traffic.csv"
```

## API Endpoints

### Network Analysis

- `POST /api/network/upload-csv` - Upload a CSV file
- `POST /api/network/ingest` - Ingest JSON logs
- `GET /api/network/graphs` - List all graphs
- `GET /api/network/analyze/{graph_id}` - Full security analysis
- `GET /api/network/summary/{graph_id}` - Human-readable summary
- `GET /api/network/anomalies/{graph_id}` - Anomaly report
- `GET /api/network/stats/{graph_id}` - Network statistics

### Queries

- `POST /api/query` - Ask questions in natural language

### Documents

- `POST /api/process/document` - Extract knowledge from documents
- `POST /api/process/text` - Process raw text
- `POST /api/process/url` - Process a URL

## Environment Variables

| Variable | What It Does |
|----------|--------------|
| `LLM_PROVIDER` | Which LLM to use (groq/ollama/gemini) |
| `GROQ_API_KEY` | Your Groq API key |
| `GROQ_MODEL` | Model name (default: llama-3.3-70b-versatile) |
| `NEO4J_URI` | Neo4j connection string |
| `NEO4J_PASSWORD` | Neo4j password |

## Example Usage

Get a security summary:
```bash
curl http://localhost:8000/api/network/summary/network_security
```

Ask a question:
```bash
curl -X POST http://localhost:8000/api/query \
  -H "Content-Type: application/json" \
  -d '{"query": "What attacks were detected?", "graph_id": "network_security"}'
```

## Project Structure

```
├── backend/
│   ├── app/              # Main application code
│   │   ├── api/          # API routes
│   │   ├── models/       # Data models
│   │   ├── services/     # Business logic
│   │   └── utils/        # Helper functions
│   ├── sample_data/      # Drop CSVs here
│   └── requirements.txt
├── docker/               # Docker setup
├── docker-compose.yml
└── .env.example
```

## Tech Stack

- **FastAPI** - Backend framework
- **Neo4j** - Graph database
- **Groq** - LLM provider (uses Llama 3.3 70B)
- **scikit-learn** - ML for anomaly detection
- **Docker** - Containerization

## License

MIT
