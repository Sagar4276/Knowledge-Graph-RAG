# Network Security Graph RAG

A network security analysis system that uses **knowledge graphs** and **RAG (Retrieval-Augmented Generation)** to detect threats and answer security questions with **grounded, explainable answers**.

![Python](https://img.shields.io/badge/Python-3.9+-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-green)
![Neo4j](https://img.shields.io/badge/Neo4j-5.x-blue)
![License](https://img.shields.io/badge/License-MIT-yellow)

## Why This Exists

Traditional log analysis tools let you search. This system lets you **understand**.

| Problem | Solution |
|---------|----------|
| Relational queries fail for "show me IPs that talked to same suspicious destination" | Graph traversal makes this trivial |
| ML anomaly detection gives scores, not explanations | Graph-native detection with full explainability |
| LLM chatbots hallucinate about your data | Cypher-grounded RAG ensures answers come from real query results |

This project combines: **Graph structure + ML detection + Grounded RAG**

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         NETWORK SECURITY GRAPH RAG                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────┐     ┌──────────────┐     ┌─────────────────────────────────┐  │
│  │  CSV    │────▶│   Parser     │────▶│         Neo4j Graph             │  │
│  │  Logs   │     │ (Auto-detect)│     │  IPs → Ports → Connections      │  │
│  └─────────┘     └──────────────┘     └─────────────────────────────────┘  │
│                                                     │                       │
│                         ┌───────────────────────────┼───────────────────┐   │
│                         ▼                           ▼                   │   │
│              ┌─────────────────────┐    ┌─────────────────────┐         │   │
│              │  Behavioral         │    │  ML Anomaly          │         │   │
│              │  Detection          │    │  Detection           │         │   │
│              │  • Port Scanners    │    │  • Isolation Forest  │         │   │
│              │  • Recon-to-Exploit │    │  • Statistical       │         │   │
│              │  • Multi-stage      │    │    Outliers          │         │   │
│              └─────────────────────┘    └─────────────────────┘         │   │
│                         │                           │                   │   │
│                         └───────────┬───────────────┘                   │   │
│                                     ▼                                   │   │
│                      ┌─────────────────────────────┐                    │   │
│                      │    Cypher-Grounded RAG      │                    │   │
│                      │  Query → Intent → Template  │                    │   │
│                      │  → Results → LLM Answer     │                    │   │
│                      └─────────────────────────────┘                    │   │
│                                                                         │   │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Key Features

### 1. Data Ingestion (Auto-Detection)
- **UNSW-NB15** - Raw and preprocessed formats
- **CICIDS2017** - Full dataset support
- **Custom CSVs** - Flexible column mapping
- Unified `network_security` graph with MERGE semantics (no duplicates)

### 2. Behavioral Threat Detection

| Detection Type | What It Finds | Cypher Pattern |
|----------------|---------------|----------------|
| **Port Scanners** | IPs accessing >5 distinct ports | Connection fan-out analysis |
| **Reconnaissance** | Multi-port access patterns | Port diversity ratio |
| **Multi-Stage Attackers** | High ports AND high volume | Combined AND logic |
| **Recon-to-Exploit** | Broad scan + focused targeting | Port concentration ratio ≥0.6 |
| **High Volume** | Connection flooding | Connections >50 threshold |

Each detection is **fully explainable**:
```json
{
  "ip_address": "59.166.0.7",
  "ports_accessed": 10,
  "total_connections": 11,
  "severity": "High",
  "anomaly_type": "Multi-port Access",
  "threat_pattern": "Recon-to-Exploit"
}
```

### 3. Cypher-Grounded RAG

**Not free-form LLM generation.** The system uses template-constrained Cypher:

1. LLM classifies query intent + extracts entities
2. Intent maps to safe, parameterized Cypher template
3. Query executes against Neo4j
4. LLM answers **only from actual results**

**Supported Intents:**
- `attacks_detected` - Behavioral threat inference
- `ip_connections` - Specific IP analysis
- `anomalies` - Behavioral anomaly detection
- `top_talkers` - Most active IPs
- `port_scanners` - Port scanning detection
- `multi_stage_attackers` - Combined attack patterns
- `exploit_preparation` - Recon-to-exploit detection
- `suspicious_ips` - Pattern-based suspicious IP detection

## Quick Start

### Prerequisites
- Docker & Docker Compose
- Groq API key (free tier available)

### Installation

```bash
# Clone repository
git clone https://github.com/Sagar4276/Knowledge-Graph-RAG.git
cd Knowledge-Graph-RAG

# Configure environment
cp .env.example .env
# Edit .env and add your GROQ_API_KEY

# Start services
docker compose up -d

# Verify
curl http://localhost:8000/health
```

### Upload Data

```bash
# Upload CSV (auto-detects format)
curl -X POST http://localhost:8000/api/network/upload-csv \
  -F "file=@UNSW_NB15_training-set.csv"
```

### Query the Graph

**Using the dedicated network query endpoint (recommended):**
```bash
curl -X POST http://localhost:8000/api/network/query \
  -H "Content-Type: application/json" \
  -d '{"query": "What attacks were detected?"}'
```

**Example Queries:**
```json
{"query": "Show me port scanning activity"}
{"query": "Which IPs are suspicious?"}
{"query": "What anomalies were detected in the network?"}
{"query": "Which IPs show both port scanning and high connection volume?"}
```

**Sample Response:**
```json
{
  "answer": "Two types of attacks were detected: Reconnaissance (13 IPs including 59.166.0.0) and High Volume Traffic (10 IPs including 149.171.126.8).",
  "intent": "attacks_detected",
  "confidence_score": 0.9,
  "query_results_count": 2,
  "grounding_context": "Results from Neo4j: ..."
}
```

## API Reference

### Network Security Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/network/upload-csv` | POST | Upload and process CSV file |
| `/api/network/query` | POST | Grounded RAG query (recommended) |
| `/api/network/stats/{graph_id}` | GET | Network statistics |
| `/api/network/anomalies/{graph_id}` | GET | Anomaly report |
| `/api/network/analyze/{graph_id}` | GET | Full security analysis |
| `/api/network/summary/{graph_id}` | GET | Security summary |
| `/api/network/cleanup` | DELETE | Remove old graphs (keep network_security) |
| `/api/network/reset` | DELETE | Delete all graphs |

### Graph Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/graphs` | GET | List all graphs |
| `/api/graphs/{graph_id}` | GET | Get specific graph |
| `/api/query` | POST | Generic RAG query |

### Swagger Documentation

Access interactive API docs at: `http://localhost:8000/api/docs`

## Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `GROQ_API_KEY` | Groq API key (required) | - |
| `GROQ_MODEL` | LLM model | `llama-3.3-70b-versatile` |
| `NEO4J_URI` | Neo4j connection | `bolt://neo4j:7687` |
| `NEO4J_PASSWORD` | Neo4j password | `password` |

## Project Structure

```
Knowledge-Graph-RAG/
├── backend/
│   ├── app/
│   │   ├── api/routes/
│   │   │   ├── network.py      # Network security endpoints
│   │   │   ├── query.py        # RAG query endpoints
│   │   │   └── graph.py        # Graph operations
│   │   ├── services/
│   │   │   ├── neo4j_service.py          # Neo4j operations
│   │   │   ├── cypher_query_service.py   # Grounded RAG
│   │   │   ├── auto_processor.py         # CSV parsing
│   │   │   ├── anomaly_detector.py       # ML detection
│   │   │   └── network_parser.py         # Log parsing
│   │   └── models/              # Pydantic models
│   ├── tests/                   # Test files
│   └── Dockerfile
├── docker-compose.yml
├── .env.example
└── README.md
```

## Limitations (Honest Assessment)

### What This System Cannot Do

| Limitation | Reason |
|------------|--------|
| **Encrypted traffic analysis** | Only metadata (IPs, ports, bytes) is analyzed |
| **Real-time streaming** | Batch processing only |
| **Dataset generalization** | Tested on UNSW-NB15/CICIDS2017 |
| **Novel attack detection** | No zero-day capability |

### What This Is NOT

- ❌ A replacement for a SIEM
- ❌ Real-time threat detection
- ❌ Production SOC-ready (without hardening)
- ❌ Trained on your specific network baseline

### What This IS

- ✅ Graph-based network analysis
- ✅ Behavioral pattern detection
- ✅ Explainable threat detection
- ✅ Grounded RAG (no hallucination)
- ✅ Educational/research tool
- ✅ Interview-ready project

## Why Graph Database?

| Query Type | Log Search | SQL | **Graph** |
|------------|-----------|-----|-----------|
| "IP scanned 50 ports?" | ✅ Easy | ✅ Easy | ✅ Easy |
| "IP talked to 3 IPs that hit same C2?" | ❌ Hard | ⚠️ Complex joins | ✅ Single traversal |
| "Attack chain visualization?" | ❌ No | ❌ Complex | ✅ Native |

## Tech Stack

- **FastAPI** - Async Python API framework
- **Neo4j** - Native graph database
- **Groq** - Fast LLM inference (Llama 3.3 70B)
- **scikit-learn** - Isolation Forest for ML anomaly detection
- **Docker** - Containerization

## Testing

```bash
cd backend
pip install -r requirements.txt
pytest tests/
```

## Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Acknowledgments

- UNSW-NB15 dataset: [UNSW Sydney](https://research.unsw.edu.au/projects/unsw-nb15-dataset)
- CICIDS2017 dataset: [Canadian Institute for Cybersecurity](https://www.unb.ca/cic/datasets/ids-2017.html)
