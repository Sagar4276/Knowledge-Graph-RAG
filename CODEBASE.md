# Codebase Documentation

A complete breakdown of all files and what they do.

---

## Project Overview

This is a **Network Security Analyzer** that:
1. Takes network traffic data (CSV files or JSON logs)
2. Builds a knowledge graph in Neo4j (IPs, ports, connections)
3. Detects anomalies using ML (Isolation Forest)
4. Answers security questions using RAG (Retrieval Augmented Generation)

---

## Directory Structure

```
Knowledge-Graph-RAG/
├── backend/
│   ├── app/
│   │   ├── api/              # API endpoints
│   │   ├── models/           # Data models (Pydantic)
│   │   ├── services/         # Business logic
│   │   └── utils/            # Helper functions
│   ├── sample_data/          # Drop CSVs here for auto-processing
│   ├── tests/                # Unit tests
│   └── requirements.txt      # Python dependencies
├── docker/                   # Dockerfile for backend
├── docker-compose.yml        # Runs everything together
├── .env.example              # Environment variable template
└── README.md                 # Quick start guide
```

---

## Core Files Explained

### Entry Point

**`backend/app/main.py`**
- Creates the FastAPI app
- Sets up CORS middleware
- Connects to Neo4j database
- Registers 4 API routers: document, graph, query, network
- **Auto-processes CSVs** on startup from `sample_data/` folder

**`backend/app/config.py`**
- Loads settings from environment variables
- Configures: Neo4j connection, LLM provider (Groq/Ollama), API settings
- Default LLM: Groq with `llama-3.3-70b-versatile`

---

## Services (Business Logic)

### `services/auto_processor.py`
**Purpose**: Automatically detects and processes CSV files

What it does:
- **Detects dataset format** (UNSW-NB15, CICIDS2017, or generic)
- **Converts to standard log format** with source/dest IPs, ports, bytes, protocol
- **Runs full pipeline**: parse → detect anomalies → build graph → store in Neo4j
- **Tracks processed files** so it doesn't re-process on restart

Key functions:
- `detect_dataset_format()` - Figures out what kind of CSV you have
- `convert_csv_to_logs()` - Converts any format to our standard format
- `scan_and_process_csv_files()` - Called on startup to process new files

---

### `services/network_parser.py`
**Purpose**: Parses network logs into structured connections

What it does:
- Parses raw log entries into connection objects
- Identifies source/destination IPs and ports
- Classifies IPs as internal or external
- Maps port numbers to service names (SSH, HTTP, etc.)
- Converts connections to graph format (nodes + edges)

Key functions:
- `parse_logs()` - Takes raw logs, returns structured connections
- `connections_to_graph()` - Creates Neo4j-ready graph structure
- `detect_port_scan()` - Finds IPs scanning multiple ports
- `detect_data_exfiltration()` - Finds large outbound transfers

---

### `services/anomaly_detector.py`
**Purpose**: Detects unusual network activity using ML

What it does:
- Uses **Isolation Forest** algorithm to find outliers
- Falls back to rule-based detection if sklearn not available
- Scores connections based on: port rarity, time of day, bytes transferred
- Flags suspicious patterns like: unusual hours, suspicious ports, high traffic

Key functions:
- `fit()` - Trains the model on your data
- `predict()` - Scores new connections for anomalies
- `get_summary()` - Returns human-readable anomaly report
- `analyze_network_traffic()` - Main entry point

---

### `services/neo4j_service.py`
**Purpose**: Stores and queries the knowledge graph

What it does:
- Connects to Neo4j database
- Creates indexes for fast lookups
- Stores graphs with nodes (IPs, Ports, Attacks) and edges (connections)
- Supports **MERGE** to combine multiple datasets into one graph
- Provides filtering and querying capabilities

Key functions:
- `store_graph()` / `store_graph_merge()` - Save graph to database
- `get_graph()` - Retrieve graph by ID
- `list_graphs()` - List all available graphs
- `filter_graph()` - Filter by node/edge type or search term
- `query_graph()` - Run custom Cypher queries

---

### `services/rag_service.py`
**Purpose**: Answers questions using the knowledge graph + LLM

What it does:
- Takes user question in natural language
- Retrieves relevant context from the graph
- Sends context + question to LLM (Groq)
- Returns AI-generated answer with graph context
- **Caches responses** to avoid repeated LLM calls

The RAG prompt includes:
- Network topology info
- Detected attacks and anomalies
- Statistics about the traffic
- Specific entity relationships

---

### `services/llm_factory.py`
**Purpose**: Creates LLM instances (Groq or Ollama)

Supported providers:
- **Groq** (default) - Fast cloud API, uses Llama 3.3 70B
- **Ollama** (fallback) - Local inference, requires Ollama running

Key function:
- `get_llm()` - Returns configured LLM based on `LLM_PROVIDER` env var

---

### `services/document_processor.py`
**Purpose**: Extracts text from uploaded documents

Supports: PDF, DOCX, DOC, TXT files
- Extracts text content
- Splits into chunks for processing

---

### `services/graph_extractor.py`
**Purpose**: Extracts knowledge graph from text using LLM

What it does:
- Sends text to LLM with entity extraction prompt
- Parses LLM response to extract entities and relationships
- Creates graph structure from extracted info

---

## API Routes

### `api/routes/network.py` (Main endpoints)

| Endpoint | What it does |
|----------|--------------|
| `POST /network/upload-csv` | Upload CSV, auto-detect format, process everything |
| `POST /network/ingest` | Ingest JSON logs manually |
| `POST /network/process-logs` | Full pipeline with analysis |
| `GET /network/graphs` | List all graph IDs |
| `GET /network/analyze/{id}` | Run all security analyses |
| `GET /network/summary/{id}` | Human-readable security summary |
| `GET /network/anomalies/{id}` | Get anomaly report |
| `GET /network/stats/{id}` | Get network statistics |
| `GET /network/connections/{ip}` | Get connections for an IP |
| `POST /network/port-scan` | Detect port scanning |
| `POST /network/exfiltration` | Detect data exfiltration |

---

### `api/routes/query.py`

| Endpoint | What it does |
|----------|--------------|
| `POST /query` | Ask questions in natural language using RAG |

---

### `api/routes/graph.py`

| Endpoint | What it does |
|----------|--------------|
| `GET /graphs` | List all graphs |
| `GET /graphs/{id}` | Get graph data |
| `POST /graphs/{id}/filter` | Filter graph nodes |

---

### `api/routes/document.py`

| Endpoint | What it does |
|----------|--------------|
| `POST /process/document` | Upload document, extract knowledge graph |
| `POST /process/text` | Process raw text |
| `POST /process/url` | Process URL content |

---

## Data Models

### `models/network_models.py`
- `NetworkLogEntry` - Single log entry with src/dst IP, ports, bytes
- `NetworkLogsInput` - Wrapper for list of log entries
- `AnomalyResult` - Anomaly detection result
- `NetworkAnalysis` - Complete analysis response

### `models/graph.py`
- `Node` - Graph node (id, label, type, properties)
- `Edge` - Graph edge (source, target, type)
- `Graph` - Complete graph with nodes + edges

### `models/query.py`
- `QueryRequest` - RAG query with question and optional graph ID
- `QueryResponse` - Answer with context paths

### `models/document.py`
- `DocumentInput` - Document upload data
- `TextInput` - Raw text input

---

## Utils

### `utils/errors.py`
- Custom exception classes
- Error handlers for API responses

### `utils/logging_utils.py`
- Configures logging format and levels
- Sets up file and console handlers

### `utils/text_processors.py`
- Text cleaning and chunking utilities
- Used for document processing

---

## Supported Dataset Formats

| Format | Detection Method |
|--------|------------------|
| **UNSW-NB15** | No headers, 49 columns, IPs in cols 0 & 2 |
| **CICIDS2017** | Has headers like "Source IP", "Destination Port" |
| **Generic** | Tries to find IP/port columns by name or pattern |

---

## How the Pipeline Works

1. **Upload CSV** → `upload_and_process_csv()`
2. **Detect Format** → `detect_dataset_format()` figures out what you uploaded
3. **Convert** → `convert_csv_to_logs()` standardizes to our format
4. **Parse** → `NetworkLogParser.parse_logs()` creates connection objects
5. **Detect Anomalies** → `NetworkAnomalyDetector.predict()` scores each connection
6. **Build Graph** → `connections_to_graph()` creates nodes and edges
7. **Store** → `Neo4jService.store_graph_merge()` saves to database
8. **Query** → `query_knowledge_graph()` answers questions using RAG

---

## Environment Variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `LLM_PROVIDER` | Which LLM to use | `groq` |
| `GROQ_API_KEY` | Your Groq API key | (required) |
| `GROQ_MODEL` | Model name | `llama-3.3-70b-versatile` |
| `NEO4J_URI` | Database connection | `bolt://neo4j:7687` |
| `NEO4J_USER` | Database user | `neo4j` |
| `NEO4J_PASSWORD` | Database password | `password` |
| `ENABLE_AUTO_PROCESS` | Auto-process CSVs on startup | `true` |

---

## Tests

Located in `backend/tests/`:
- `test_document_processor.py` - Tests document extraction
- `test_graph_extractor.py` - Tests knowledge graph extraction
- `test_rag_service.py` - Tests RAG query functionality

Run tests:
```bash
cd backend
pytest tests/
```

---

That's everything! 🎉
