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


# Intent classification prompt - extracts intent + entities, NOT Cypher
INTENT_PROMPT = """You are a security query classifier. Given a user question about network security data, extract:
1. The query intent (one of the allowed types)
2. Any specific entities mentioned (IPs, ports, attack types, protocols)

Allowed intents:
- attacks_detected: Questions about what attacks were found
- ip_connections: Questions about a specific IP's connections
- anomalies: Questions about detected anomalies
- top_talkers: Questions about most active IPs or high-traffic nodes
- port_analysis: Questions about port usage or scanning
- network_topology: Questions about network structure
- attack_details: Questions about specific attack type details
- suspicious_ips: Questions about which IPs are suspicious
- protocol_analysis: Questions about protocol usage
- general: General questions that don't fit other categories

Respond ONLY in this exact JSON format (no markdown):
{{"intent": "<intent_name>", "entities": {{"ip": "<ip or null>", "port": "<port or null>", "attack_type": "<attack or null>", "protocol": "<protocol or null>"}}}}

User question: {question}

JSON response:"""


# Cypher template registry - safe, parameterized queries
CYPHER_TEMPLATES: Dict[QueryIntent, str] = {
    QueryIntent.ATTACKS_DETECTED: """
        MATCH (g:Graph {id: $graph_id})-[:CONTAINS]->(a:Node)
        WHERE a.type IN ['Attack', 'AttackType', 'attack'] OR a.label CONTAINS 'Attack'
        WITH a.label AS attack_type, count(*) AS count
        RETURN attack_type, count
        ORDER BY count DESC
        LIMIT 10
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
        MATCH (g:Graph {id: $graph_id})-[:CONTAINS]->(n:Node)
        WHERE n.is_anomaly = true OR n.anomaly_score > 0.5 OR n.type = 'Anomaly'
        RETURN n.label AS entity,
               n.anomaly_score AS score,
               n.anomaly_types AS types,
               n.type AS node_type
        ORDER BY n.anomaly_score DESC
        LIMIT 20
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
        WHERE ip.is_suspicious = true 
              OR ip.anomaly_score > 0.7
              OR ip.threat_score > 0.5
        RETURN ip.label AS ip_address,
               ip.anomaly_score AS anomaly_score,
               ip.anomaly_types AS reasons,
               ip.connection_count AS connections
        ORDER BY ip.anomaly_score DESC
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
    
    def classify_intent(self, question: str) -> Tuple[QueryIntent, Dict[str, Any]]:
        """
        Use LLM to classify query intent and extract entities.
        
        Returns:
            Tuple of (intent, entities_dict)
        """
        prompt = INTENT_PROMPT.format(question=question)
        
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
            
            # Map to enum
            try:
                intent = QueryIntent(intent_str)
            except ValueError:
                logger.warning(f"Unknown intent '{intent_str}', falling back to GENERAL")
                intent = QueryIntent.GENERAL
            
            return intent, entities
            
        except Exception as e:
            logger.error(f"Intent classification failed: {e}")
            return QueryIntent.GENERAL, {}
    
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


def query_with_grounding(
    question: str,
    neo4j_service: Neo4jService,
    graph_id: str
) -> Dict[str, Any]:
    """
    Main entry point for grounded RAG queries.
    
    Flow:
    1. Classify intent + extract entities
    2. Execute safe Cypher template
    3. Ground LLM answer in actual results
    """
    service = CypherQueryService(neo4j_service)
    
    # Step 1: Classify intent
    intent, entities = service.classify_intent(question)
    logger.info(f"Classified intent: {intent.value}, entities: {entities}")
    
    # Step 2: Execute query
    results, cypher_used = service.execute_query(graph_id, intent, entities)
    logger.info(f"Query returned {len(results)} results")
    
    # Step 3: Format results
    context = service.format_results_for_llm(results, intent, question)
    
    # Step 4: Generate grounded answer
    prompt = GROUNDED_RAG_PROMPT.format(question=question, context=context)
    
    try:
        llm = get_llm()
        answer = llm.invoke(prompt)
    except Exception as e:
        logger.error(f"LLM answer generation failed: {e}")
        answer = f"Error generating answer: {e}"
    
    return {
        "answer": answer.strip() if isinstance(answer, str) else str(answer).strip(),
        "intent": intent.value,
        "entities_extracted": entities,
        "query_results_count": len(results),
        "cypher_template_used": cypher_used,
        "grounding_context": context,
        "paths": []  # For backward compatibility
    }
