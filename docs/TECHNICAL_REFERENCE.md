# Network Security Graph RAG: Complete Technical Reference

> **A-to-Z documentation covering every algorithm, service, and endpoint with code verification**

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [Architecture](#architecture)
3. [Algorithms (Verified in Code)](#algorithms-verified-in-code)
4. [Services](#services)
5. [API Endpoints](#api-endpoints)
6. [Data Flow](#data-flow)
7. [Schema Design](#schema-design)
8. [Configuration](#configuration)
9. [Testing](#testing)

---

## Project Overview

**Purpose**: A production-grade security analysis system that:
- Ingests network logs (CSV) and threat reports (text/URL)
- Builds knowledge graphs in Neo4j
- Detects anomalies using ML + graph-native algorithms
- Answers natural language queries with grounded RAG

**Repository**: https://github.com/Sagar4276/Knowledge-Graph-RAG

**Tech Stack**:
| Component | Technology |
|-----------|------------|
| API Framework | FastAPI |
| Graph Database | Neo4j 5.x |
| LLM Provider | Groq (Llama 3.3 70B) |
| ML Library | scikit-learn |
| Containerization | Docker Compose |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        FastAPI Backend                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐ │
│  │ CSV Upload  │  │ Text/URL    │  │ Natural Language Query  │ │
│  │ Endpoint    │  │ Processing  │  │ Endpoint                │ │
│  └──────┬──────┘  └──────┬──────┘  └───────────┬─────────────┘ │
│         │                │                      │               │
│         ▼                ▼                      ▼               │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐ │
│  │ Network     │  │ Graph       │  │ Cypher Query Service    │ │
│  │ Parser      │  │ Extractor   │  │ (Template-constrained)  │ │
│  └──────┬──────┘  └──────┬──────┘  └───────────┬─────────────┘ │
│         │                │                      │               │
│         ▼                │                      │               │
│  ┌─────────────┐         │                      │               │
│  │ Anomaly     │         │                      │               │
│  │ Detector    │         │                      │               │
│  │ (ML + Rules)│         │                      │               │
│  └──────┬──────┘         │                      │               │
│         │                │                      │               │
│         ▼                ▼                      ▼               │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                      Neo4j Graph Database                   ││
│  │  - Nodes: IPs, Ports, Devices, Threats, Connections         ││
│  │  - Edges: CONNECTED_TO, LEADS_TO, SOURCE_OF, TARGET_OF      ││
│  └─────────────────────────────────────────────────────────────┘│
│         │                                                       │
│         ▼                                                       │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                 Graph Anomaly Detector                      ││
│  │  - Degree Spike    - Fan-Out Detection                      ││
│  │  - Protocol Rarity - Suspicious Port Access                 ││
│  └─────────────────────────────────────────────────────────────┘│
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Algorithms (Verified in Code)

### 1. Isolation Forest (ML-based Anomaly Detection)

**File**: `backend/app/services/anomaly_detector.py`
**Line**: 15, 41

```python
from sklearn.ensemble import IsolationForest

self.model = IsolationForest(
    n_estimators=100,
    contamination=0.1,
    random_state=42
)
```

**What it detects**: Statistical outliers in feature vectors
**Features used**:
- bytes_sent, bytes_received
- duration
- port rarity
- is_suspicious_port flag
- time-of-day score

---

### 2. Degree Spike Detection (Graph-native)

**File**: `backend/app/services/graph_anomaly_detector.py`
**Line**: 108-166

```python
def detect_degree_spikes(self, graph_id: str) -> List[GraphAnomalyResult]:
    # Calculate mean and standard deviation of connection counts
    # Flag IPs with degree > mean + 2σ
```

**What it detects**: IPs with unusually high connection counts
**Threshold**: `mean + (2 * std_dev)`
**Explainability output**:
```json
{
  "anomaly_type": "degree_spike",
  "baseline": 22.7,
  "observed": 254,
  "confidence_score": 0.785,
  "reason": "IP has 254 connections, significantly above average of 22.7"
}
```

---

### 3. Fan-Out Detection (Port Scanning)

**File**: `backend/app/services/graph_anomaly_detector.py`
**Line**: 168-226

```python
def detect_fan_out(self, graph_id: str) -> List[GraphAnomalyResult]:
    # Single source IP → many destination ports on same target
    # Indicates port scanning behavior
```

**What it detects**: Single IP connecting to many ports on one target
**Threshold**: 10+ unique ports to same destination
**Output type**: `fan_out_port_scan`

---

### 4. Protocol Rarity Detection

**File**: `backend/app/services/graph_anomaly_detector.py`
**Line**: 228-283

```python
def detect_protocol_rarity(self, graph_id: str) -> List[GraphAnomalyResult]:
    # Protocols used in < 1% of total traffic
    # May indicate covert channels
```

**What it detects**: Rare protocols (ICMP, etc.) that may be covert channels
**Threshold**: < 1% of total traffic
**Output example**:
```json
{
  "anomaly_type": "rare_protocol",
  "entity": "ICMP",
  "observed": "0.34% (2 connections)",
  "reason": "Protocol 'ICMP' used in only 0.34% of connections"
}
```

---

### 5. Suspicious Port Access Detection

**File**: `backend/app/services/graph_anomaly_detector.py`
**Line**: 285-340

**File**: `backend/app/services/network_parser.py`
**Line**: 70

```python
SUSPICIOUS_PORTS = {
    4444: "Metasploit", 5555: "ADB", 12345: "NetBus",
    31337: "BackOrifice", 6666: "IRC Backdoor",
    1337: "Elite", 8888: "Sun JDWP", 9001: "Tor"
}

def is_suspicious_port(port: int) -> bool:
    return port in SUSPICIOUS_PORTS
```

**What it detects**: Connections to known malware/backdoor ports
**Ports monitored**: 4444, 5555, 12345, 31337, 6666, 1337, 8888, 9001

---

### 6. Rule-Based Anomaly Detection

**File**: `backend/app/services/anomaly_detector.py`
**Line**: 206-237

```python
def _rule_based_detection(self, conn: Dict[str, Any]) -> List[str]:
    # Checks for:
    # - Suspicious ports with port number: "suspicious_port:4444"
    # - Known malware ports: "known_malware_port:4444"
    # - Large external transfers: "large_external_transfer:15000000bytes"
    # - Unusual time access: "unusual_time:score=0.85"
    # - High ephemeral ports: "high_ephemeral_port:52000"
```

**Features**:
- Port-specific anomaly tagging
- Data exfiltration detection (> 10MB outbound)
- After-hours activity detection
- Ephemeral port abuse detection

---

## Services

### 1. NetworkLogParser
**File**: `backend/app/services/network_parser.py`

- Parses CSV/JSON network logs
- Normalizes IP addresses and ports
- Flags suspicious ports
- Detects internal vs external IPs

### 2. AnomalyDetector
**File**: `backend/app/services/anomaly_detector.py`

- Combines Isolation Forest ML with rule-based detection
- Returns anomaly scores (0-1)
- Returns anomaly types with details

### 3. GraphAnomalyDetector
**File**: `backend/app/services/graph_anomaly_detector.py`

- Runs graph-native algorithms on Neo4j
- Degree spike, fan-out, protocol rarity, suspicious ports
- Returns explainable anomaly results

### 4. CypherQueryService
**File**: `backend/app/services/cypher_query_service.py`

- Template-constrained Cypher generation
- 10 query intents with pre-validated templates
- Anti-hallucination by design

**Supported Intents** (Line 59+):
```python
class QueryIntent(Enum):
    GENERAL = "general"
    ANOMALIES = "anomalies"
    CONNECTIONS = "connections"
    ATTACKERS = "attackers"
    NETWORK_TOPOLOGY = "network_topology"
    DATA_TRANSFER = "data_transfer"
    PORT_SCAN = "port_scan"
    ATTACK_TYPES = "attack_types"
    IP_DETAILS = "ip_details"
    THREAT_SUMMARY = "threat_summary"
```

### 5. GraphExtractor
**File**: `backend/app/services/graph_extractor.py`

- LLM-based knowledge graph extraction from text
- Security-grade schema: Connection as node, attack chains
- Entity class tagging (telemetry/semantic/security)

### 6. GraphMerger
**File**: `backend/app/services/graph_merger.py`

- Merges semantic (text) and telemetry (CSV) graphs
- Entity deduplication by label
- Source provenance tracking
- Cross-correlation detection

### 7. Neo4jService
**File**: `backend/app/services/neo4j_service.py`

- Graph storage and retrieval
- Cypher query execution
- Index management

### 8. DocumentProcessor
**File**: `backend/app/services/document_processor.py`

- URL fetching with retries and User-Agent
- PDF/DOCX/TXT processing
- HTML text extraction

---

## API Endpoints

### Data Ingestion

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/network/upload-csv` | POST | Upload CSV network logs |
| `/api/network/ingest` | POST | Ingest JSON network logs |
| `/api/process/text` | POST | Extract graph from text |
| `/api/process/url` | POST | Extract graph from URL |
| `/api/process/document` | POST | Extract graph from file |

### Analysis

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/network/analyze/{graph_id}` | GET | Full security analysis |
| `/api/network/anomalies/{graph_id}` | GET | Anomaly report |
| `/api/network/stats/{graph_id}` | GET | Network statistics |

### Detection

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/network/detect-scan` | POST | Port scan detection |
| `/api/network/detect-exfiltration` | POST | Data exfiltration detection |

### Query

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/query` | POST | Natural language query |

### Graph Management

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/network/graphs` | GET | List all graphs |
| `/api/network/merge-graphs` | POST | Merge semantic + telemetry |
| `/api/network/correlations/{graph_id}` | GET | Find cross-graph correlations |

---

## Data Flow

### CSV Ingestion Flow

```
CSV File
    ↓
NetworkLogParser.parse_logs()
    ↓
AnomalyDetector.analyze()
    ↓ (ML + Rule-based anomalies)
AutoProcessor._connections_to_enhanced_graph()
    ↓ (Build nodes + edges)
Neo4jService.store_graph()
    ↓
GraphAnomalyDetector.detect_all()
    ↓ (Graph-native anomalies)
Final Graph with Anomaly Scores
```

### Text Extraction Flow

```
Text Input
    ↓
GraphExtractor.extract_knowledge_graph()
    ↓ (LLM with security-grade prompt)
validate_graph_data()
    ↓ (Add entity_class, confidence)
Neo4jService.store_graph()
    ↓
Semantic Graph
```

### Query Flow

```
Natural Language Query
    ↓
CypherQueryService.classify_intent()
    ↓ (LLM classification)
CYPHER_TEMPLATES[intent]
    ↓ (Pre-validated template)
Neo4jService.query_graph()
    ↓
LLM Answer Generation
    ↓ (Grounded in query results)
Final Answer + Context
```

---

## Schema Design

### Node Types

**Telemetry** (from network logs):
- `InternalIP`, `ExternalIP`, `Port`, `Protocol`, `Connection`, `Session`

**Semantic** (from text extraction):
- `Person`, `Organization`, `Device`, `Domain`

**Security** (threat inference):
- `Threat`, `Attack`, `AttackChain`, `Indicator`, `Evidence`
- `CredentialAccess`, `LateralMovement`, `Exfiltration`, `CommandAndControl`

### Edge Types

**Network**:
- `CONNECTED_TO`, `USES_PORT`, `RESOLVES_TO`

**Connection-centric**:
- `SOURCE_OF`, `TARGET_OF`, `INITIATED`, `USED_PORT`, `USED_PROTOCOL`

**Attack Chain**:
- `LEADS_TO`, `FOLLOWED_BY`, `RESULTS_IN`, `INDICATES`

### Key Properties

**On Nodes**:
- `is_anomaly`: boolean
- `anomaly_score`: 0.0-1.0
- `anomaly_types`: list of strings
- `entity_class`: "telemetry" | "semantic" | "security"
- `confidence`: 0.0-1.0 (for security entities)
- `severity`: "low" | "medium" | "high" | "critical"

---

## Configuration

### Environment Variables

```env
# Neo4j
NEO4J_URI=bolt://neo4j:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=your_password

# Groq LLM
GROQ_API_KEY=your_api_key
LLM_MODEL=llama-3.3-70b-versatile
```

### Docker Compose

```yaml
services:
  backend:
    build:
      context: ./backend
      dockerfile: backend.Dockerfile
    ports:
      - "8000:8000"
    depends_on:
      - neo4j

  neo4j:
    image: neo4j:5
    ports:
      - "7474:7474"
      - "7687:7687"
    environment:
      - NEO4J_AUTH=neo4j/your_password
```

---

## Testing

### Test Files

- `backend/tests/test_comprehensive.py` — Full test suite (20+ tests)
- `backend/tests/test_sanity.py` — Quick sanity checks

### Running Tests

```bash
docker compose exec backend pytest tests/ -v
```

### Test Coverage

- Network parsing: IP normalization, port detection
- ML anomaly detection: Isolation Forest training/prediction
- Graph anomaly detection: Degree spike, fan-out, protocol rarity
- Cypher service: Template validation, injection prevention
- Security: Result capping, input sanitization

---

## Quick Start

```bash
# 1. Clone and setup
git clone https://github.com/Sagar4276/Knowledge-Graph-RAG.git
cd Knowledge-Graph-RAG
cp .env.example .env  # Edit with your Groq API key

# 2. Start services
docker compose up -d

# 3. Access Swagger UI
open http://localhost:8000/docs

# 4. Upload network data
# Use /api/network/upload-csv endpoint

# 5. Query the graph
# POST /api/query with {"query": "What anomalies were detected?", "graph_id": "network_security"}
```

---

## Algorithm Verification Summary

| Claimed Algorithm | Location | Line | Status |
|-------------------|----------|------|--------|
| Isolation Forest | `anomaly_detector.py` | 15, 41 | ✅ Verified |
| Degree Spike | `graph_anomaly_detector.py` | 108 | ✅ Verified |
| Fan-Out Detection | `graph_anomaly_detector.py` | 168 | ✅ Verified |
| Protocol Rarity | `graph_anomaly_detector.py` | 228 | ✅ Verified |
| Suspicious Ports | `graph_anomaly_detector.py` + `network_parser.py` | 285, 70 | ✅ Verified |
| Cypher Templates | `cypher_query_service.py` | 59 | ✅ Verified (10 intents) |
| Attack Chains (LEADS_TO) | `graph_extractor.py` | 105, 229-231 | ✅ Verified |
| Entity Class Separation | `graph_extractor.py` | 444-450 | ✅ Verified |

---

*Last updated: December 17, 2025*
*All algorithms verified against codebase*
