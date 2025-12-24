"""
Cypher Query Service for the Network Security Graph RAG system.

Uses template-constrained Cypher + intent classification.
NO free-form LLM Cypher generation (prevents injection & invalid queries).
"""

import logging
import re
from typing import Dict, Any, List, Optional, Tuple
from enum import Enum

from app.services.llm_factory import get_llm
from app.services.neo4j_service import Neo4jService

logger = logging.getLogger(__name__)


class QueryIntent(Enum):
    """Supported query intents for security analysis."""
    ATTACKS_DETECTED = "attacks_detected"
    IP_CONNECTIONS = "ip_connections"
    ANOMALIES = "anomalies"
    TOP_TALKERS = "top_talkers"
    PORT_ANALYSIS = "port_analysis"
    NETWORK_TOPOLOGY = "network_topology"
    ATTACK_DETAILS = "attack_details"
    SUSPICIOUS_IPS = "suspicious_ips"
    PROTOCOL_ANALYSIS = "protocol_analysis"
    GENERAL = "general"
    PORT_SCANNERS = "port_scanners"  # IPs doing port scanning
    MULTI_STAGE_ATTACKERS = "multi_stage_attackers"  # IPs with both high ports AND high volume
    EXPLOIT_PREPARATION = "exploit_preparation"  # IPs with broad recon but focused targeting


# Intent classification prompt - extracts intent + entities + confidence, NOT Cypher
INTENT_PROMPT = """You are a security query classifier. Given a user question about network security data, extract:
1. The query intent (one of the allowed types)
2. Any specific entities mentioned (IPs, ports, attack types, protocols)
3. Your confidence in this classification (0.0 to 1.0)

Allowed intents:
- attacks_detected: Questions about what attacks were found
- ip_connections: Questions about a specific IP's connections
- anomalies: Questions about detected anomalies
- top_talkers: Questions about most active IPs or high-traffic nodes
- port_analysis: Questions about port usage or scanning
- port_scanners: Questions about which IPs are scanning ports or doing reconnaissance
- multi_stage_attackers: Questions about IPs with BOTH high port diversity AND high connection volume
- exploit_preparation: Questions about IPs that scan broadly but concentrate on sensitive services (recon-to-exploit)
- network_topology: Questions about network structure
- attack_details: Questions about specific attack type details
- suspicious_ips: Questions about which IPs are suspicious
- protocol_analysis: Questions about protocol usage
- general: General questions that don't fit other categories

Confidence guidelines:
- 0.9-1.0: Very clear intent with specific entities
- 0.7-0.9: Clear intent, may lack specific entities
- 0.5-0.7: Somewhat ambiguous, could fit multiple intents
- 0.0-0.5: Very vague or unclear query

Respond ONLY in this exact JSON format (no markdown):
{{"intent": "<intent_name>", "confidence": <0.0-1.0>, "entities": {{"ip": "<ip or null>", "port": "<port or null>", "attack_type": "<attack or null>", "protocol": "<protocol or null>"}}}}

User question: {question}

JSON response:"""

# Vague query patterns that should trigger clarification regardless of LLM confidence
VAGUE_QUERY_PATTERNS = [
    r"anything weird",
    r"anything strange", 
    r"what's happening",
    r"what is happening",
    r"something wrong",
    r"any problems",
    r"any issues",
    r"tell me about",
    r"show me everything",
    r"what do you see",
    r"what can you find",
]


# Cypher template registry - safe, parameterized queries
CYPHER_TEMPLATES: Dict[QueryIntent, str] = {
    QueryIntent.ATTACKS_DETECTED: """
        MATCH (g:Graph {id: $graph_id})-[:CONTAINS]->(ip:Node)
        WHERE ip.type = 'IP' OR ip.label =~ '\\\\d+\\\\.\\\\d+\\\\.\\\\d+\\\\.\\\\d+'
        MATCH (ip)-[r:CONNECTED_TO|CONNECTS_TO]->()
        WITH ip.label AS source_ip,
             count(DISTINCT COALESCE(r.port, 0)) AS ports_accessed,
             count(r) AS total_connections
        WHERE ports_accessed > 5 OR total_connections > 50
        WITH 
            CASE 
                WHEN ports_accessed > 10 THEN 'Port Scanning'
                WHEN ports_accessed > 5 THEN 'Reconnaissance'
                WHEN total_connections > 100 THEN 'High Volume Traffic'
                ELSE 'Suspicious Activity'
            END AS threat_type,
            source_ip,
            ports_accessed,
            total_connections
        RETURN threat_type, 
               count(source_ip) AS affected_ips,
               collect(source_ip)[..5] AS sample_ips
        ORDER BY affected_ips DESC
    """,
    
    QueryIntent.IP_CONNECTIONS: """
        MATCH (g:Graph {id: $graph_id})-[:CONTAINS]->(ip:Node)
        WHERE ip.label = $ip OR ip.id CONTAINS $ip
        OPTIONAL MATCH (ip)-[r]->(target)
        WHERE target.label IS NOT NULL
        RETURN ip.label AS source_ip,
               type(r) AS connection_type,
               target.label AS destination,
               r.bytes_sent AS bytes_sent,
               r.port AS port
        LIMIT 25
    """,
    
    QueryIntent.ANOMALIES: """
        MATCH (g:Graph {id: $graph_id})-[:CONTAINS]->(ip:Node)
        WHERE ip.type = 'IP' OR ip.label =~ '\\\\d+\\\\.\\\\d+\\\\.\\\\d+\\\\.\\\\d+'
        MATCH (ip)-[r:CONNECTED_TO|CONNECTS_TO]->()
        WITH ip.label AS ip_address,
             count(DISTINCT COALESCE(r.port, 0)) AS distinct_ports,
             count(r) AS connections,
             sum(COALESCE(r.bytes_sent, 0)) AS bytes_sent
        WHERE distinct_ports > 5 OR connections > 30
        RETURN ip_address,
               distinct_ports AS ports_accessed,
               connections,
               bytes_sent,
               CASE 
                   WHEN distinct_ports > 10 AND connections > 50 THEN 'Critical'
                   WHEN distinct_ports > 5 THEN 'High'
                   ELSE 'Medium'
               END AS severity,
               CASE
                   WHEN distinct_ports > 10 THEN 'Port Scanning + High Volume'
                   WHEN distinct_ports > 5 THEN 'Multi-port Access'
                   WHEN connections > 50 THEN 'High Connection Volume'
                   ELSE 'Unusual Activity'
               END AS anomaly_type
        ORDER BY distinct_ports DESC, connections DESC
        LIMIT 15
    """,
    
    QueryIntent.TOP_TALKERS: """
        MATCH (g:Graph {id: $graph_id})-[:CONTAINS]->(ip:Node)
        WHERE ip.type = 'IP' OR ip.label =~ '\\\\d+\\\\.\\\\d+\\\\.\\\\d+\\\\.\\\\d+'
        OPTIONAL MATCH (ip)-[r]->()
        WITH ip, count(r) AS out_degree, sum(COALESCE(r.bytes_sent, 0)) AS total_bytes
        RETURN ip.label AS ip_address,
               out_degree AS connections,
               total_bytes AS bytes_sent
        ORDER BY out_degree DESC
        LIMIT 10
    """,
    
    QueryIntent.PORT_ANALYSIS: """
        MATCH (g:Graph {id: $graph_id})-[:CONTAINS]->(p:Node)
        WHERE p.type = 'Port' OR p.label CONTAINS 'Port'
        OPTIONAL MATCH ()-[r]->(p)
        WITH p, count(r) AS connection_count
        RETURN p.label AS port,
               connection_count AS connections,
               CASE 
                   WHEN p.label CONTAINS '22' THEN 'SSH'
                   WHEN p.label CONTAINS '80' THEN 'HTTP'
                   WHEN p.label CONTAINS '443' THEN 'HTTPS'
                   WHEN p.label CONTAINS '3389' THEN 'RDP'
                   ELSE 'Other'
               END AS service
        ORDER BY connection_count DESC
        LIMIT 15
    """,
    
    QueryIntent.NETWORK_TOPOLOGY: """
        MATCH (g:Graph {id: $graph_id})-[:CONTAINS]->(n:Node)
        WITH labels(n) AS types, count(n) AS count
        RETURN types[0] AS node_type, count
        UNION
        MATCH (g:Graph {id: $graph_id})-[:CONTAINS]->(n1:Node)-[r]->(n2:Node)
        WITH type(r) AS rel_type, count(r) AS count
        RETURN 'Relationship: ' + rel_type AS node_type, count
        ORDER BY count DESC
        LIMIT 20
    """,
    
    QueryIntent.ATTACK_DETAILS: """
        MATCH (g:Graph {id: $graph_id})-[:CONTAINS]->(a:Node)
        WHERE toLower(a.label) CONTAINS toLower($attack_type) 
              OR a.attack_category = $attack_type
        OPTIONAL MATCH (source)-[r]->(a)
        RETURN a.label AS attack,
               collect(DISTINCT source.label)[..5] AS source_ips,
               a.severity AS severity,
               a.count AS occurrences
        LIMIT 10
    """,
    
    QueryIntent.SUSPICIOUS_IPS: """
        MATCH (g:Graph {id: $graph_id})-[:CONTAINS]->(ip:Node)
        WHERE ip.type = 'IP' OR ip.label =~ '\\\\d+\\\\.\\\\d+\\\\.\\\\d+\\\\.\\\\d+'
        MATCH (ip)-[r:CONNECTED_TO|CONNECTS_TO]->()
        WITH ip.label AS ip_address,
             count(DISTINCT COALESCE(r.port, 0)) AS ports_accessed,
             count(r) AS total_connections
        WHERE ports_accessed > 3 OR total_connections > 20
        RETURN ip_address,
               ports_accessed,
               total_connections,
               CASE 
                   WHEN ports_accessed > 10 THEN 'Port Scanner'
                   WHEN ports_accessed > 5 THEN 'Reconnaissance'
                   WHEN total_connections > 50 THEN 'High Volume'
                   ELSE 'Unusual Pattern'
               END AS reason
        ORDER BY ports_accessed DESC, total_connections DESC
        LIMIT 15
    """,
    
    QueryIntent.PROTOCOL_ANALYSIS: """
        MATCH (g:Graph {id: $graph_id})-[:CONTAINS]->(p:Node)
        WHERE p.type = 'Protocol' OR p.protocol IS NOT NULL
        WITH COALESCE(p.protocol, p.label) AS protocol, count(*) AS usage
        RETURN protocol, usage
        ORDER BY usage DESC
        LIMIT 10
    """,
    
    QueryIntent.GENERAL: """
        MATCH (g:Graph {id: $graph_id})-[:CONTAINS]->(n:Node)
        WITH labels(n) AS types, n.label AS label
        RETURN types[0] AS type, collect(DISTINCT label)[..5] AS examples, count(*) AS count
        ORDER BY count DESC
        LIMIT 10
    """,
    
    QueryIntent.PORT_SCANNERS: """
        MATCH (g:Graph {id: $graph_id})-[:CONTAINS]->(ip:Node)
        WHERE ip.type = 'IP' OR ip.label =~ '\\\\d+\\\\.\\\\d+\\\\.\\\\d+\\\\.\\\\d+'
        MATCH (ip)-[r:CONNECTED_TO|CONNECTS_TO]->(target)
        WITH ip.label AS source_ip, 
             count(DISTINCT COALESCE(r.port, target.label)) AS ports_accessed,
             count(r) AS total_connections,
             collect(DISTINCT COALESCE(r.port, target.label))[..10] AS sample_ports
        WHERE ports_accessed > 5
        RETURN source_ip, 
               ports_accessed, 
               total_connections,
               sample_ports,
               'Port Scanner' AS behavior_type
        ORDER BY ports_accessed DESC
        LIMIT 15
    """,
    
    QueryIntent.MULTI_STAGE_ATTACKERS: """
        MATCH (g:Graph {id: $graph_id})-[:CONTAINS]->(ip:Node)
        WHERE ip.type = 'IP' OR ip.label =~ '\\\\d+\\\\.\\\\d+\\\\.\\\\d+\\\\.\\\\d+'
        MATCH (ip)-[r:CONNECTED_TO|CONNECTS_TO]->()
        WITH ip.label AS ip_address,
             count(DISTINCT COALESCE(r.port, 0)) AS ports_accessed,
             count(r) AS total_connections,
             sum(COALESCE(r.bytes_sent, 0)) AS bytes_sent
        WHERE ports_accessed > 5 AND total_connections > 50
        RETURN ip_address,
               ports_accessed,
               total_connections,
               bytes_sent,
               'Multi-Stage Attacker' AS threat_type,
               'Reconnaissance + Flooding' AS attack_pattern
        ORDER BY ports_accessed DESC, total_connections DESC
        LIMIT 10
    """,
    
    QueryIntent.EXPLOIT_PREPARATION: """
        MATCH (g:Graph {id: $graph_id})-[:CONTAINS]->(ip:Node)
        WHERE ip.type = 'IP' OR ip.label =~ '\\\\d+\\\\.\\\\d+\\\\.\\\\d+\\\\.\\\\d+'
        MATCH (ip)-[r:CONNECTED_TO|CONNECTS_TO]->(target)
        WITH ip.label AS ip_address,
             COALESCE(r.port, target.label) AS port,
             count(*) AS port_count
        WITH ip_address, 
             count(DISTINCT port) AS distinct_ports,
             sum(port_count) AS total_connections,
             collect({port: port, count: port_count}) AS port_stats
        WHERE distinct_ports >= 10 AND total_connections >= 20
        UNWIND port_stats AS ps
        WITH ip_address, distinct_ports, total_connections, ps
        ORDER BY ps.count DESC
        WITH ip_address, distinct_ports, total_connections,
             collect(ps)[..3] AS top_3_ports
        WITH ip_address, distinct_ports, total_connections, top_3_ports,
             reduce(s = 0.0, p IN top_3_ports | s + p.count) AS top_3_count
        WITH ip_address, distinct_ports, total_connections, top_3_ports,
             round(100.0 * top_3_count / total_connections) / 100.0 AS port_focus_ratio
        WHERE port_focus_ratio >= 0.5
        RETURN ip_address,
               distinct_ports AS ports_scanned,
               total_connections,
               top_3_ports AS focused_targets,
               port_focus_ratio,
               CASE 
                   WHEN port_focus_ratio >= 0.8 THEN 'Critical - Highly Focused'
                   WHEN port_focus_ratio >= 0.6 THEN 'High - Targeted Attack'
                   ELSE 'Medium - Recon-to-Exploit'
               END AS threat_level,
               'Recon-to-Exploit Pattern' AS attack_type
        ORDER BY port_focus_ratio DESC, distinct_ports DESC
        LIMIT 10
    """
}


class CypherQueryService:
    """
    Safe, template-constrained Cypher query service.
    
    Flow:
    1. LLM classifies intent + extracts entities
    2. Intent maps to predefined Cypher template
    3. Parameters filled safely (no injection)
    4. Results returned with grounding info
    """
    
    def __init__(self, neo4j_service: Neo4jService):
        self.neo4j_service = neo4j_service
        self.llm = get_llm()
    
    def classify_intent(self, question: str) -> Tuple[QueryIntent, Dict[str, Any], float]:
        """
        Use LLM to classify query intent, extract entities, and assess confidence.
        
        Returns:
            Tuple of (intent, entities_dict, confidence_score)
        """
        prompt = INTENT_PROMPT.format(question=question)
        
        # Secondary heuristic: check for vague query patterns
        question_lower = question.lower()
        is_vague_query = any(re.search(pattern, question_lower) for pattern in VAGUE_QUERY_PATTERNS)
        
        try:
            response = self.llm.invoke(prompt)
            logger.info(f"Intent classification response: {response}")
            
            # Parse JSON response
            import json
            # Clean up response - remove markdown if present
            clean_response = response.strip()
            if clean_response.startswith("```"):
                clean_response = clean_response.split("```")[1]
                if clean_response.startswith("json"):
                    clean_response = clean_response[4:]
            clean_response = clean_response.strip()
            
            parsed = json.loads(clean_response)
            intent_str = parsed.get("intent", "general")
            entities = parsed.get("entities", {})
            confidence = float(parsed.get("confidence", 0.5))
            
            # Clamp confidence to valid range
            confidence = max(0.0, min(1.0, confidence))
            
            # Apply secondary heuristic: cap confidence for vague queries
            if is_vague_query and confidence > 0.6:
                logger.info(f"Vague query pattern detected, capping confidence from {confidence} to 0.6")
                confidence = 0.6
            
            # Map to enum
            try:
                intent = QueryIntent(intent_str)
            except ValueError:
                logger.warning(f"Unknown intent '{intent_str}', falling back to GENERAL")
                intent = QueryIntent.GENERAL
                confidence = min(confidence, 0.5)  # Lower confidence for unknown intent
            
            return intent, entities, confidence
            
        except Exception as e:
            logger.error(f"Intent classification failed: {e}")
            return QueryIntent.GENERAL, {}, 0.3  # Low confidence on error
    
    def execute_query(
        self, 
        graph_id: str, 
        intent: QueryIntent, 
        entities: Dict[str, Any]
    ) -> Tuple[List[Dict], str]:
        """
        Execute the appropriate Cypher template with safe parameters.
        
        Returns:
            Tuple of (results, cypher_query_used)
        """
        template = CYPHER_TEMPLATES.get(intent, CYPHER_TEMPLATES[QueryIntent.GENERAL])
        
        # Build parameters safely
        params = {"graph_id": graph_id}
        
        # Add entity parameters if present
        if entities.get("ip"):
            params["ip"] = str(entities["ip"])
        if entities.get("port"):
            params["port"] = str(entities["port"])
        if entities.get("attack_type"):
            params["attack_type"] = str(entities["attack_type"])
        if entities.get("protocol"):
            params["protocol"] = str(entities["protocol"])
        
        try:
            # Validate query with EXPLAIN (catches invalid Cypher)
            # Note: Some Neo4j versions may not support this, so we wrap in try
            try:
                explain_query = f"EXPLAIN {template}"
                self.neo4j_service.query_graph(graph_id, explain_query, params)
            except Exception:
                pass  # EXPLAIN failed, but query might still work
            
            # Execute actual query
            results = self.neo4j_service.query_graph(graph_id, template, params)
            
            return results, template.strip()
            
        except Exception as e:
            logger.error(f"Query execution failed: {e}")
            return [], template.strip()
    
    def format_results_for_llm(
        self, 
        results: List[Dict], 
        intent: QueryIntent,
        question: str
    ) -> str:
        """
        Format query results into grounded context for LLM.
        """
        if not results:
            return f"NO DATA FOUND for query type '{intent.value}'. The graph may not contain relevant information."
        
        context = f"Query type: {intent.value}\n"
        context += f"Results ({len(results)} rows):\n"
        
        for i, row in enumerate(results[:20], 1):  # Limit to 20 rows
            row_str = ", ".join(f"{k}: {v}" for k, v in row.items() if v is not None)
            context += f"  {i}. {row_str}\n"
        
        if len(results) > 20:
            context += f"  ... and {len(results) - 20} more rows\n"
        
        return context


# Grounded RAG prompt - forces answer to come from results
GROUNDED_RAG_PROMPT = """You are a network security analyst. Answer the user's question using ONLY the query results below.

RULES:
1. ONLY use information from the query results
2. If results are empty, say "No data found" 
3. Cite specific values from the results
4. Do NOT make up or hallucinate information
5. Be concise and security-focused

USER QUESTION: {question}

QUERY RESULTS:
{context}

ANSWER (grounded in results only):"""


# Confidence thresholds (two-band system)
CONFIDENCE_PROCEED = 0.75       # >= this: proceed normally
CONFIDENCE_WARN = 0.5           # >= this but < PROCEED: proceed with warning  
CONFIDENCE_CLARIFY = 0.5        # < this: request clarification

# Clarification response text
CLARIFICATION_RESPONSE = """I'm not confident I understood your question correctly. Could you please be more specific?

For example, you could ask:
- "What attacks were detected?" 
- "Show me connections for IP 192.168.1.10"
- "Which IPs have the highest anomaly scores?"
- "What ports are being scanned?"

Please rephrase your question with more specific details."""


def query_with_grounding(
    question: str,
    neo4j_service: Neo4jService,
    graph_id: str
) -> Dict[str, Any]:
    """
    Main entry point for grounded RAG queries with validation hardening.
    
    Flow:
    1. Classify intent + extract entities + get confidence
    2. Check confidence threshold (clarify if too low)
    3. Validate entities exist in graph
    4. Execute safe Cypher template
    5. Sanity check results
    6. Ground LLM answer in actual results
    """
    import time
    start_time = time.time()
    
    service = CypherQueryService(neo4j_service)
    validation_warnings = []
    entities_validated = {}
    
    # Step 1: Classify intent with confidence
    intent, entities, confidence = service.classify_intent(question)
    logger.info(f"Classified intent: {intent.value}, entities: {entities}, confidence: {confidence}")
    
    # Step 2: Confidence gate (two-band system)
    if confidence < CONFIDENCE_CLARIFY:
        # Very low confidence - request clarification
        logger.info(f"Confidence {confidence} below threshold {CONFIDENCE_CLARIFY}, requesting clarification")
        return {
            "answer": CLARIFICATION_RESPONSE,
            "intent": intent.value,
            "entities_extracted": entities,
            "query_results_count": 0,
            "cypher_template_used": None,
            "grounding_context": None,
            "paths": [],
            "confidence_score": confidence,
            "validation_warnings": ["Low confidence in query understanding. Please rephrase."],
            "entities_validated": {}
        }
    elif confidence < CONFIDENCE_PROCEED:
        # Medium confidence - proceed with warning
        validation_warnings.append(f"Query understanding confidence is moderate ({confidence:.2f}). Results may not match your intent.")
    
    # Step 3: Entity validation before query execution
    has_entities = any(v and v != "null" for v in entities.values())
    if has_entities:
        entities_validated = neo4j_service.validate_entities(
            graph_id=graph_id,
            ip=entities.get("ip") if entities.get("ip") != "null" else None,
            port=entities.get("port") if entities.get("port") != "null" else None,
            protocol=entities.get("protocol") if entities.get("protocol") != "null" else None,
            attack_type=entities.get("attack_type") if entities.get("attack_type") != "null" else None
        )
        
        # Check for missing entities
        missing_entities = [k for k, v in entities_validated.items() if not v]
        if missing_entities:
            entity_warnings = [f"Entity '{k}' (value: {entities.get(k)}) not found in graph" for k in missing_entities]
            validation_warnings.extend(entity_warnings)
            logger.warning(f"Missing entities in graph: {missing_entities}")
            
            # If primary entity is missing, return explicit message instead of empty results
            if "ip" in missing_entities and intent == QueryIntent.IP_CONNECTIONS:
                return {
                    "answer": f"The IP address '{entities.get('ip')}' was not found in the network graph. Please verify the IP address exists in the ingested data.",
                    "intent": intent.value,
                    "entities_extracted": entities,
                    "query_results_count": 0,
                    "cypher_template_used": None,
                    "grounding_context": None,
                    "paths": [],
                    "confidence_score": confidence,
                    "validation_warnings": entity_warnings,
                    "entities_validated": entities_validated
                }
    
    # Step 4: Execute query
    results, cypher_used = service.execute_query(graph_id, intent, entities)
    logger.info(f"Query returned {len(results)} results")
    
    # Step 5: Result sanity checks
    if len(results) == 0:
        # Check if this is unexpected based on intent
        if intent in [QueryIntent.ATTACKS_DETECTED, QueryIntent.ANOMALIES, QueryIntent.SUSPICIOUS_IPS]:
            validation_warnings.append(
                f"No {intent.value.replace('_', ' ')} found. This could mean the data is clean, "
                f"or the detection hasn't been run, or the query didn't match any records."
            )
        elif has_entities and all(entities_validated.get(k, True) for k in entities_validated):
            # Entities exist but no results - possible data/query mismatch
            validation_warnings.append(
                "Entities were found in the graph but the query returned no results. "
                "This may indicate the specific relationship you're asking about doesn't exist."
            )
    
    # Step 6: Format results for LLM
    context = service.format_results_for_llm(results, intent, question)
    
    # Step 7: Generate grounded answer
    prompt = GROUNDED_RAG_PROMPT.format(question=question, context=context)
    
    try:
        llm = get_llm()
        answer = llm.invoke(prompt)
    except Exception as e:
        logger.error(f"LLM answer generation failed: {e}")
        answer = f"Error generating answer: {e}"
    
    execution_time_ms = int((time.time() - start_time) * 1000)
    
    return {
        "answer": answer.strip() if isinstance(answer, str) else str(answer).strip(),
        "intent": intent.value,
        "entities_extracted": entities,
        "query_results_count": len(results),
        "cypher_template_used": cypher_used,
        "grounding_context": context,
        "paths": [],
        "confidence_score": confidence,
        "validation_warnings": validation_warnings,
        "entities_validated": entities_validated,
        "execution_time_ms": execution_time_ms
    }
