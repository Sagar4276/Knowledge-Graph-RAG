# Cypher Queries for Security Graph RAG Interviews

These are **production-grade Cypher queries** that demonstrate deep understanding of graph-based security analysis.

---

## 1. Attack Chain Traversal

### "Show me all attack paths that ended in data exfiltration"

```cypher
MATCH path = (start:Node)-[:LEADS_TO*1..5]->(end:Node)
WHERE end.type = 'Exfiltration'
RETURN 
  [n IN nodes(path) | n.label] AS attack_chain,
  [n IN nodes(path) | n.type] AS stages,
  length(path) AS chain_length,
  end.properties.confidence AS confidence
ORDER BY chain_length DESC
LIMIT 10
```

**Why this matters**: Shows you understand kill-chain modeling, not just flat queries.

---

## 2. Anomaly-Based Threat Hunting

### "Find IPs with anomaly scores above threshold that connected to external hosts"

```cypher
MATCH (g:Graph {id: $graph_id})-[:CONTAINS]->(src:Node)-[r:CONNECTED_TO]->(dst:Node)
WHERE src.is_anomaly = true 
  AND src.anomaly_score > 0.7
  AND dst.type = 'ExternalIP'
RETURN 
  src.label AS suspicious_ip,
  src.anomaly_score AS score,
  src.anomaly_types AS threat_indicators,
  collect(DISTINCT dst.label) AS external_destinations,
  count(r) AS connection_count
ORDER BY score DESC
LIMIT 20
```

---

## 3. Lateral Movement Detection

### "Trace lateral movement from compromised credentials"

```cypher
MATCH (cred:Node {type: 'CredentialAccess'})-[:LEADS_TO]->(lateral:Node {type: 'LateralMovement'})
OPTIONAL MATCH (lateral)-[:INDICATES|LEADS_TO]->(conn:Node {type: 'Connection'})
OPTIONAL MATCH (conn)-[:TARGET_OF]->(target:Node)
RETURN 
  cred.label AS initial_compromise,
  lateral.label AS movement_type,
  conn.properties.protocol AS protocol,
  conn.properties.port AS port,
  collect(DISTINCT target.label) AS compromised_systems,
  lateral.properties.confidence AS confidence
```

---

## 4. Graph-Native Degree Spike Detection

### "Find IPs with connection counts significantly above the graph average"

```cypher
MATCH (g:Graph {id: $graph_id})-[:CONTAINS]->(n:Node)
WHERE n.type IN ['InternalIP', 'ExternalIP']
WITH n, size((n)-[:CONNECTED_TO|SOURCE_OF]->()) AS out_degree

// Calculate graph-level statistics
WITH collect({node: n, degree: out_degree}) AS all_data
WITH all_data, 
     reduce(s = 0, x IN all_data | s + x.degree) / size(all_data) AS mean,
     all_data AS data

UNWIND data AS item
WITH item.node AS n, item.degree AS degree, mean,
     sqrt(reduce(s = 0.0, x IN data | s + (x.degree - mean)^2) / size(data)) AS std_dev

WHERE degree > mean + (2 * std_dev)
RETURN 
  n.label AS high_activity_ip,
  degree AS connections,
  round(mean, 2) AS graph_average,
  round((degree - mean) / std_dev, 2) AS z_score,
  'degree_spike' AS anomaly_type
ORDER BY degree DESC
LIMIT 15
```

---

## 5. Port Scan Detection

### "Identify IPs that connected to 10+ unique ports on the same target"

```cypher
MATCH (g:Graph {id: $graph_id})-[:CONTAINS]->(src:Node)-[r:CONNECTED_TO]->(dst:Node)
WITH src, dst, collect(DISTINCT r.port) AS ports
WHERE size(ports) >= 10
RETURN 
  src.label AS scanner_ip,
  dst.label AS target_ip,
  size(ports) AS ports_scanned,
  ports[0..10] AS sample_ports,
  CASE 
    WHEN size(ports) > 50 THEN 'high'
    WHEN size(ports) > 20 THEN 'medium'
    ELSE 'low'
  END AS confidence
ORDER BY ports_scanned DESC
```

---

## 6. Connection-Centric Analysis

### "Show all details of connections involving suspicious ports"

```cypher
MATCH (conn:Node {type: 'Connection'})
WHERE conn.properties.port IN [4444, 5555, 31337, 12345]
   OR conn.properties.protocol = 'IRC'
OPTIONAL MATCH (src)-[:SOURCE_OF|INITIATED]->(conn)
OPTIONAL MATCH (conn)-[:TARGET_OF]->(dst)
RETURN 
  conn.label AS connection,
  conn.properties.timestamp AS timestamp,
  conn.properties.port AS port,
  conn.properties.protocol AS protocol,
  src.label AS source,
  dst.label AS destination,
  'malware_port' AS threat_type
```

---

## 7. Entity Class Filtering

### "Separate semantic findings from telemetry data"

```cypher
// Security findings only (analyst inferences)
MATCH (g:Graph {id: $graph_id})-[:CONTAINS]->(n:Node)
WHERE n.properties.entity_class = 'security'
RETURN 
  n.label AS finding,
  n.type AS category,
  n.properties.confidence AS confidence,
  n.properties.severity AS severity
ORDER BY n.properties.confidence DESC

UNION

// Telemetry data only (raw network data)
MATCH (g:Graph {id: $graph_id})-[:CONTAINS]->(n:Node)
WHERE n.properties.entity_class = 'telemetry'
RETURN 
  n.label AS entity,
  n.type AS category,
  null AS confidence,
  null AS severity
LIMIT 50
```

---

## 8. Cross-Graph Correlation

### "Find common IOCs between text-derived and network-derived graphs"

```cypher
MATCH (g1:Graph)-[:CONTAINS]->(n1:Node)
WHERE g1.properties.graph_type = 'semantic'
  AND n1.type IN ['InternalIP', 'ExternalIP', 'Port']

MATCH (g2:Graph)-[:CONTAINS]->(n2:Node)  
WHERE g2.properties.graph_type = 'telemetry'
  AND n2.label = n1.label

RETURN 
  n1.label AS common_entity,
  n1.type AS entity_type,
  g1.id AS semantic_graph,
  g2.id AS telemetry_graph,
  'cross_reference' AS match_type
```

---

## 9. Attack Surface Analysis

### "What external IPs are most connected to internal hosts?"

```cypher
MATCH (g:Graph {id: $graph_id})-[:CONTAINS]->(ext:Node {type: 'ExternalIP'})
OPTIONAL MATCH (ext)<-[:CONNECTED_TO]-(internal:Node {type: 'InternalIP'})
WITH ext, collect(DISTINCT internal.label) AS connected_hosts, count(internal) AS host_count
WHERE host_count > 1
RETURN 
  ext.label AS external_ip,
  host_count AS internal_hosts_connected,
  connected_hosts[0..5] AS sample_hosts,
  CASE 
    WHEN ext.is_anomaly = true THEN 'suspicious'
    ELSE 'normal'
  END AS risk_status
ORDER BY host_count DESC
LIMIT 20
```

---

## 10. Timeline Reconstruction

### "Show events in chronological order for incident response"

```cypher
MATCH (g:Graph {id: $graph_id})-[:CONTAINS]->(e:Node)
WHERE e.properties.timestamp IS NOT NULL
RETURN 
  e.label AS event,
  e.type AS event_type,
  e.properties.timestamp AS timestamp,
  e.properties.entity_class AS source_type,
  CASE 
    WHEN e.type IN ['Exfiltration', 'CommandAndControl'] THEN 'critical'
    WHEN e.type IN ['LateralMovement', 'CredentialAccess'] THEN 'high'
    ELSE 'medium'
  END AS priority
ORDER BY e.properties.timestamp
```

---

## Interview Tips

When asked about these queries:

1. **Explain the graph model first** — Connection as a node, attack chains via LEADS_TO
2. **Mention performance** — "We use indexes on `graph_id` and `type`"
3. **Discuss limitations** — "Timestamp ordering assumes clock synchronization"
4. **Show alternatives** — "For larger graphs, we'd use APOC for pagination"

---

## Quick Reference: Key Patterns

| Pattern | Use Case |
|---------|----------|
| `-[:LEADS_TO*1..5]->` | Attack chain traversal |
| `WHERE n.properties.entity_class = 'security'` | Filter semantic vs telemetry |
| `size((n)-[:CONNECTED_TO]->())` | Degree calculation |
| `collect(DISTINCT x)` | Aggregation without duplicates |
| `CASE WHEN ... THEN ... END` | Inline risk scoring |
