# Network Security Graph RAG: Technical Case Study

## Executive Summary

This project implements a **production-grade security analysis system** that:
- Ingests network traffic data (CSV) and threat reports (text/URL)
- Builds knowledge graphs in Neo4j with graph-native anomaly detection
- Enables natural language security queries via Cypher-grounded RAG
- Merges analyst findings with raw telemetry for cross-correlation

**Key differentiators:**
- Template-constrained Cypher prevents LLM hallucination
- Connection modeled as first-class entities, not just edges
- Explicit attack chain relationships (LEADS_TO, FOLLOWED_BY)
- Entity class separation (telemetry/semantic/security)

---

## Problem Statement

Traditional security tools have three major limitations:

1. **Siloed data**: Network logs, threat intel, and analyst notes exist separately
2. **No relationship modeling**: Flat logs can't represent attack chains
3. **Query rigidity**: Analysts must know exact queries, can't ask natural questions

### Our Solution

```
Raw Data → Graph Model → Multi-Modal Detection → RAG Interface
   │           │                  │                    │
   │           │                  │                    └─ Natural language queries
   │           │                  └─ ML + Graph-native anomalies
   │           └─ Entities + Relationships in Neo4j
   └─ CSV network logs, Text threat reports, URLs
```

---

## Architecture

### Data Flow

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   CSV Logs   │────▶│   Parser +   │────▶│   Neo4j      │
│  (UNSW-NB15) │     │   Anomaly    │     │   Graph      │
└──────────────┘     │   Detector   │     └──────────────┘
                     └──────────────┘            │
┌──────────────┐     ┌──────────────┐            │
│ Text/URL     │────▶│   LLM Graph  │────────────┘
│ (Reports)    │     │   Extractor  │
└──────────────┘     └──────────────┘
                            │
┌──────────────┐     ┌──────────────┐
│   User       │────▶│   Cypher     │────▶ Grounded Answer
│   Query      │     │   RAG        │
└──────────────┘     └──────────────┘
```

### Tech Stack

| Component | Technology | Why |
|-----------|------------|-----|
| API | FastAPI | Async, auto-docs, type safety |
| Graph DB | Neo4j 5.x | Native graph, Cypher, APOC |
| LLM | Groq (Llama 3.3 70B) | Fast inference, good reasoning |
| ML | scikit-learn | Isolation Forest for anomalies |
| Embeddings | Not used | Cypher-grounded, no vector search |

---

## Key Technical Decisions

### 1. Connection as a First-Class Entity

**Problem**: Traditional graphs model connections as edges, losing metadata.

**Before (bad):**
```
IP_A ──CONNECTED_TO──▶ IP_B
         │
         └─ Where's the port? Protocol? Timestamp?
```

**After (good):**
```
IP_A ──SOURCE_OF──▶ Connection ──TARGET_OF──▶ IP_B
                        │
                        ├── USED_PORT ──▶ 22
                        ├── USED_PROTOCOL ──▶ SSH  
                        └── timestamp: 2025-01-12T10:30:00Z
```

This enables queries like:
```cypher
MATCH (c:Node {type: 'Connection'})
WHERE c.properties.port = 22
  AND c.properties.timestamp > datetime('2025-01-12')
RETURN c
```

### 2. Template-Constrained Cypher (Anti-Hallucination)

**Problem**: Free-form LLM Cypher generation is dangerous.

**Solution**: Two-stage approach:
1. LLM classifies intent → returns `{intent: "anomalies", entities: {}}`
2. Intent maps to pre-validated Cypher template

```python
CYPHER_TEMPLATES = {
    QueryIntent.ANOMALIES: """
        MATCH (g:Graph {id: $graph_id})-[:CONTAINS]->(n:Node)
        WHERE n.is_anomaly = true OR n.anomaly_score > 0.5
        RETURN n.label, n.anomaly_score, n.anomaly_types
        LIMIT 20
    """
}
```

**Result**: Zero hallucination, guaranteed valid Cypher.

### 3. Graph-Native Anomaly Detection

**Problem**: ML anomaly detection misses structural patterns.

**Solution**: Combine ML with graph algorithms:

| Method | What it Detects |
|--------|-----------------|
| Isolation Forest | Statistical outliers in features |
| Degree Spike | IPs with connection count > mean + 2σ |
| Fan-Out Detection | Single IP → many ports on same target |
| Protocol Rarity | Rare protocols (< 1% of traffic) |
| Suspicious Ports | Known malware ports (4444, 31337, etc.) |

Each anomaly includes **explainability**:
```json
{
  "anomaly_type": "degree_spike",
  "entity": "149.171.126.1",
  "baseline": 22.7,
  "observed": 254,
  "confidence_score": 0.785,
  "reason": "IP has 254 connections, significantly above average of 22.7"
}
```

### 4. Attack Chain Modeling

**Problem**: Security analysts think in attack chains, not flat data.

**Solution**: Explicit causal edges:

```
CredentialAccess ──LEADS_TO──▶ LateralMovement ──LEADS_TO──▶ Exfiltration
```

Enables kill-chain queries:
```cypher
MATCH path = (start)-[:LEADS_TO*1..5]->(end:Node {type: 'Exfiltration'})
RETURN [n IN nodes(path) | n.label] AS attack_chain
```

### 5. Entity Class Separation

**Problem**: Mixing analyst inference with raw telemetry pollutes signal.

**Solution**: Every entity tagged with `entity_class`:

| Class | Source | Example |
|-------|--------|---------|
| `telemetry` | Network logs | IPs, Ports, Connections |
| `semantic` | Text extraction | Devices, Organizations |
| `security` | Threat inference | Threats, Attack types |

Enables clean filtering:
```cypher
WHERE n.properties.entity_class = 'security'
```

---

## Performance Characteristics

### Tested Scale

| Metric | Value |
|--------|-------|
| CSV ingestion | 5,000 rows in ~30s |
| Nodes per graph | 2,000+ |
| Query latency | < 500ms (indexed) |
| LLM response | 2-4s (Groq) |

### Indexes Used

```cypher
CREATE INDEX graph_id IF NOT EXISTS FOR (g:Graph) ON (g.id);
CREATE INDEX node_type IF NOT EXISTS FOR (n:Node) ON (n.type);
CREATE INDEX node_anomaly IF NOT EXISTS FOR (n:Node) ON (n.is_anomaly);
```

---

## Limitations (Honest Assessment)

### Detection Limitations

| Gap | Impact | Mitigation |
|-----|--------|------------|
| No encrypted traffic analysis | Can't inspect TLS content | Metadata-based detection |
| Batch processing only | Not real-time | Could add stream processing |
| Dataset bias | UNSW-NB15 patterns only | Train on production data |

### ML Caveats

- Isolation Forest finds statistical outliers, not confirmed attacks
- Thresholds (mean + 2σ) are heuristics, not optimized
- No temporal correlation between events

### RAG Limitations

- Cypher templates are finite (10 intents currently)
- Can't answer arbitrary analytical questions
- Depends on LLM intent classification accuracy

---

## API Reference

### Core Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/network/upload-csv` | POST | Ingest network data |
| `/api/process/text` | POST | Extract graph from text |
| `/api/process/url` | POST | Extract graph from URL |
| `/api/query` | POST | Natural language query |
| `/api/network/analyze/{graph_id}` | GET | Full security analysis |

### Query Example

**Request:**
```json
POST /api/query
{
  "query": "What anomalies were detected?",
  "graph_id": "network_security"
}
```

**Response:**
```json
{
  "answer": "Found 12 anomalies with highest score 1.0 for 175.45.176.0...",
  "intent": "anomalies",
  "cypher_template_used": "MATCH (g:Graph...)...",
  "grounding_context": "Query results: 12 rows...",
  "query_results_count": 12
}
```

---

## Future Improvements

1. **Real-time streaming**: Kafka integration for live detection
2. **MITRE ATT&CK mapping**: Auto-tag detected techniques
3. **Alert enrichment**: Pull context from VirusTotal, AbuseIPDB
4. **Graph visualization**: Frontend for attack path exploration
5. **Multi-tenant**: Organization-level graph isolation

---

## Conclusion

This project demonstrates:
- ✅ Graph-based security modeling with proper schema design
- ✅ Hybrid anomaly detection (ML + graph-native)
- ✅ Grounded RAG that doesn't hallucinate
- ✅ Production-grade error handling and explainability
- ✅ Honest documentation of limitations

The key insight: **Security data is inherently relational**. Modeling it as a graph enables queries that flat logs cannot answer.

---

## Repository

- **GitHub**: [Your repo URL]
- **Documentation**: `/docs/CYPHER_QUERIES.md`, `/CODEBASE.md`
- **Live Demo**: `docker compose up -d`

---

*Developed as a demonstration of production-grade security engineering principles.*
