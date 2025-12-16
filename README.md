# Network Security Graph RAG

A network security analysis system that uses **knowledge graphs** and **RAG** to detect threats and answer security questions.

## Why This Exists

Traditional log analysis tools let you search. This system lets you **understand**.

- **Relational queries fail** when you need "show me all IPs that talked to the same suspicious destination within 10 minutes" — that requires graph traversal
- **ML anomaly detection alone** gives you scores, not explanations — you need context
- **LLM chatbots hallucinate** when asked about your data — they need grounded answers from real query results

This project combines all three: graph structure + ML detection + grounded RAG.

## Architecture

```
CSV/Logs → Parser → Neo4j Graph → Anomaly Detection → RAG Queries
                         ↓                ↓
                    Graph-native      Isolation Forest
                    detection         (ML-based)
                         ↓                ↓
                    Explainable       Statistical
                    anomalies         anomalies
                         ↘            ↙
                      Cypher-grounded RAG
                      (NL → Intent → Template → Results → Answer)
```

## Features

### Data Ingestion
- Auto-detects CSV format (UNSW-NB15, CICIDS2017, custom)
- Builds knowledge graph: IPs → Ports → Connections → Attacks
- Stores in Neo4j for relationship-aware queries

### Anomaly Detection (Hybrid Approach)

**ML-based (Isolation Forest):**
- Statistical outlier detection on per-connection features
- Scores based on: port rarity, time of day, bytes transferred

**Graph-native:**
| Detection | What it finds | How |
|-----------|--------------|-----|
| Degree spike | Lateral movement | IP with connections > mean + 2σ |
| Fan-out | Port scanning | Single IP → multiple ports on same target |
| Protocol rarity | Covert channels | Protocols used in <1% of traffic |
| Suspicious ports | Known malware | Connections to 4444, 31337, etc. |

Each anomaly includes **full explainability**:
```json
{
  "anomaly_type": "degree_spike",
  "entity": "10.0.0.5",
  "confidence_score": 0.87,
  "baseline": 12.3,
  "observed": 47,
  "reason": "IP has 47 outgoing connections, significantly above graph average of 12.3"
}
```

### RAG Queries (Cypher-Grounded)

**Not free-form LLM generation.** The system uses template-constrained Cypher:

1. LLM classifies query intent + extracts entities
2. Intent maps to safe, parameterized Cypher template
3. Query executes against Neo4j
4. LLM answers **only from actual results**

Supported query types:
- `attacks_detected` - "What attacks were found?"
- `ip_connections` - "Show connections for 192.168.1.10"
- `anomalies` - "What anomalies were detected?"
- `top_talkers` - "Which IPs have most traffic?"
- `suspicious_ips` - "Show suspicious entities"

## Quick Start

```bash
# Clone and configure
git clone https://github.com/Sagar4276/Knowledge-Graph-RAG.git
cd Knowledge-Graph-RAG
cp .env.example .env
# Add your GROQ_API_KEY to .env

# Start services
docker compose up -d

# Verify
curl http://localhost:8000/health
```

### Ingesting Data

```bash
# Upload a CSV (auto-detects format)
curl -X POST http://localhost:8000/api/network/upload-csv \
  -F "file=@your_traffic.csv"

# Response includes graph_id for queries
```

### Querying

```bash
# Ask a question (grounded in actual data)
curl -X POST http://localhost:8000/api/query \
  -H "Content-Type: application/json" \
  -d '{"query": "What attacks were detected?", "graph_id": "network_security"}'

# Get full analysis with graph anomalies
curl http://localhost:8000/api/network/analyze/network_security
```

## API Reference

### Core Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/network/upload-csv` | POST | Upload CSV, auto-process |
| `/api/network/analyze/{graph_id}` | GET | Full security analysis with graph anomalies |
| `/api/query` | POST | Cypher-grounded RAG query |
| `/api/network/anomalies/{graph_id}` | GET | Anomaly report |
| `/api/network/stats/{graph_id}` | GET | Network statistics |

### Query Response Format

```json
{
  "answer": "The graph contains 3 attack types: DoS, Reconnaissance, and Generic...",
  "intent": "attacks_detected",
  "entities_extracted": {},
  "query_results_count": 3,
  "cypher_template_used": "MATCH (g:Graph {id: $graph_id})...",
  "grounding_context": "Query type: attacks_detected\nResults: ..."
}
```

## Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `GROQ_API_KEY` | Groq API key (required) | - |
| `GROQ_MODEL` | LLM model | `llama-3.3-70b-versatile` |
| `NEO4J_URI` | Neo4j connection | `bolt://neo4j:7687` |
| `NEO4J_PASSWORD` | Neo4j password | `password` |

## Limitations

This section is deliberately honest about what this system **cannot** do.

### Detection Gaps

| Limitation | Why it matters |
|------------|----------------|
| **Encrypted traffic blind spot** | Deep packet inspection isn't supported — only metadata (IPs, ports, bytes) |
| **No real-time streaming** | Batch processing only; not suitable for live SOC integration |
| **Dataset bias** | Trained/tested on UNSW-NB15 and CICIDS2017 — may not generalize to your network |
| **Static attack signatures** | Novel attacks won't match known attack types |

### ML Caveats

| Caveat | Mitigation |
|--------|------------|
| **Isolation Forest false positives** | Combined with graph-native detection for better accuracy |
| **No temporal awareness** | Beaconing detection not yet implemented |
| **Cold start problem** | Per-graph baselines help, but small datasets produce noisy thresholds |

### RAG Limitations

| Limitation | How we handle it |
|------------|------------------|
| **Fixed query templates** | 10 intent types cover most security questions; extend as needed |
| **No multi-hop reasoning** | Complex attack chains require multiple queries |
| **LLM context limits** | Results capped at 20 rows to stay within token budget |

### What This Is NOT

- ❌ A replacement for a SIEM
- ❌ Real-time threat detection
- ❌ Suitable for production SOC without additional hardening
- ❌ Trained on your specific network baseline

## Comparison: Why Graph?

| Approach | IP scanned 50 ports? | IP talked to 3 IPs that also hit same C2? |
|----------|---------------------|-------------------------------------------|
| Log search (Splunk) | ✅ Easy | ❌ Hard (requires joins) |
| Relational DB | ✅ Possible | ⚠️ Complex multi-joins |
| **Graph DB** | ✅ Trivial | ✅ Single traversal |

Graph databases excel at **relationship-heavy queries** — exactly what security analysis needs.

## Testing

```bash
cd backend
pip install -r requirements.txt
pytest tests/
```

Note: Automated test coverage is limited. Focus was on correctness of graph construction and query grounding.

## Tech Stack

- **FastAPI** - API framework
- **Neo4j** - Graph database
- **Groq** - LLM inference (Llama 3.3 70B)
- **scikit-learn** - Isolation Forest
- **Docker** - Containerization

## License

MIT
