from typing import Dict, Any, List
import os
import logging
import hashlib
import time
import threading
from .neo4j_service import Neo4jService
from langchain.prompts import PromptTemplate
from langchain.schema.runnable import RunnablePassthrough
from app.services.llm_factory import get_llm

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize LLM
llm = get_llm()

# Create prompt template for RAG - simplified for better performance
RAG_TEMPLATE = """
You are a knowledge graph assistant. Answer based on this graph data:

QUESTION: {question}

GRAPH DATA:
{context}

Answer using only information from the graph. If the graph lacks needed information, explain what's known and what's missing.
"""

rag_prompt = PromptTemplate(
    input_variables=["question", "context"],
    template=RAG_TEMPLATE
)

# Create the chain using pipe operator
rag_chain = (
    {"question": RunnablePassthrough(), "context": RunnablePassthrough()}
    | rag_prompt
    | llm
)

# Simple in-memory LRU cache
_query_cache = {}
MAX_CACHE_SIZE = 100

def query_knowledge_graph(query: str, neo4j_service: Neo4jService, graph_id: str = None) -> Dict[str, Any]:
    """
    Query the knowledge graph using RAG with caching
    
    Args:
        query: The user's question
        neo4j_service: Neo4j service instance
        graph_id: Optional specific graph ID to query
        
    Returns:
        Dictionary containing the answer and relevant paths
    """
    start_time = time.time()
    
    # Check cache for this query + graph combination
    if graph_id:
        cache_key = f"{graph_id}:{hashlib.md5(query.encode()).hexdigest()}"
        if cache_key in _query_cache:
            logger.info(f"Cache hit for query: '{query}'")
            return _query_cache[cache_key]
    
    # Build context for the LLM
    context = ""
    relevant_paths = []
    
    try:
        if not graph_id:
            return {
                "answer": "Please provide a valid graph ID to query the knowledge graph.",
                "paths": [],
                "context_used": ""
            }
        
        # Log the incoming query
        logger.info(f"Processing query: '{query}' for graph {graph_id}")
        
        # First, try a more direct approach for common question types
        if any(term in query.lower() for term in ["found", "create", "establish", "start"]):
            # For questions about founding/creation, directly search for FOUNDED_BY relationships
            # OPTIMIZED: Added LIMIT to prevent large result sets
            founder_cypher = """
            MATCH (g:Graph {id: $graph_id})-[:CONTAINS]->(org:Node)-[r:FOUNDED_BY]->(founder:Node)
            WHERE toLower(org.label) CONTAINS toLower($term)
            RETURN org.label AS organization, founder.label AS founder
            LIMIT 5
            """
            
            # Also try the reverse relationship
            founder_cypher_reverse = """
            MATCH (g:Graph {id: $graph_id})-[:CONTAINS]->(founder:Node)-[r:FOUNDED]->(org:Node)
            WHERE toLower(org.label) CONTAINS toLower($term)
            RETURN org.label AS organization, founder.label AS founder
            LIMIT 5
            """
            
            # Extract potential organization names from the query
            org_terms = [word for word in query.lower().split() if len(word) > 2]
            founders_found = []
            
            for term in org_terms:
                # Try first cypher query
                results = neo4j_service.query_graph(
                    graph_id=graph_id,
                    cypher_query=founder_cypher,
                    params={"term": term}
                )
                
                # If no results, try reverse relationship
                if not results:
                    results = neo4j_service.query_graph(
                        graph_id=graph_id,
                        cypher_query=founder_cypher_reverse,
                        params={"term": term}
                    )
                
                for result in results:
                    org = result.get("organization")
                    founder = result.get("founder")
                    if org and founder:
                        founders_found.append((org, founder))
                        path_str = f"{org} was founded by {founder}"
                        relevant_paths.append(path_str)
                        context += f"{path_str}\n"
            
            # If we found founder information, we can stop here
            if founders_found:
                logger.info(f"Found direct founding information: {founders_found}")
            
        # If we didn't find specific founder information, proceed with general search
        if not context:
            logger.info("No direct founding information found, trying general search")
            
            # OPTIMIZED: Use parametrized CONTAINS for better index usage
            entities_cypher = """
            MATCH (g:Graph {id: $graph_id})-[:CONTAINS]->(n:Node)
            WHERE n.label IS NOT NULL AND toLower(n.label) CONTAINS toLower($term)
            RETURN n.id AS id, n.label AS label, labels(n) AS types
            LIMIT 5
            """
            
            # Extract key terms from the query (enhanced approach)
            query_terms = query.lower().replace("?", "").replace(".", "").split()
            important_terms = [word for word in query_terms if len(word) > 3 and word not in ["what", "where", "when", "which", "whose", "whom", "who", "how", "why", "did", "does", "the", "and", "that", "this", "are", "was"]]
            
            # Find relevant nodes for each term
            relevant_nodes = set()
            
            for term in important_terms:
                nodes = neo4j_service.query_graph(
                    graph_id=graph_id,
                    cypher_query=entities_cypher,
                    params={"term": term}
                )
                for node in nodes:
                    relevant_nodes.add(node["id"])
                    logger.info(f"Found relevant node: {node['label']} ({node['id']})")
            
            # If we found relevant nodes, query paths between them
            if len(relevant_nodes) >= 2:
                logger.info(f"Found {len(relevant_nodes)} relevant nodes, querying paths")
                # Convert set to list to access elements
                node_list = list(relevant_nodes)
                
                # OPTIMIZATION: Only try a limited number of node pairs to avoid combinatorial explosion
                max_pairs = 3
                pair_count = 0
                
                # Query paths between pairs of relevant nodes
                for i in range(len(node_list)):
                    for j in range(i + 1, len(node_list)):
                        if pair_count >= max_pairs:
                            break
                            
                        # OPTIMIZED: Reduced path depth from 3 to 2 for faster queries
                        paths_cypher = """
                        MATCH (g:Graph {id: $graph_id})-[:CONTAINS]->(start:Node {id: $start_id}),
                              (g)-[:CONTAINS]->(end:Node {id: $end_id}),
                              path = shortestPath((start)-[*1..2]-(end))
                        RETURN [node in nodes(path) | node.label] AS node_labels,
                               [rel in relationships(path) | type(rel)] AS rel_types
                        LIMIT 2
                        """
                        
                        paths = neo4j_service.query_graph(
                            graph_id=graph_id,
                            cypher_query=paths_cypher,
                            params={"start_id": node_list[i], "end_id": node_list[j]}
                        )
                        
                        if paths:
                            pair_count += 1
                        
                        for path in paths:
                            node_labels = path["node_labels"]
                            rel_types = path["rel_types"]
                            
                            # Format the path
                            path_str = " -> ".join([
                                f"{node_labels[i]} -{rel_types[i]}-> {node_labels[i+1]}"
                                for i in range(len(rel_types))
                            ])
                            
                            relevant_paths.append(path_str)
                            context += f"Path: {path_str}\n"
                            logger.info(f"Found path: {path_str}")
            
            # If no paths found or we don't have enough relevant nodes, get information about individual nodes
            if not relevant_paths:
                logger.info("No paths found, gathering information about individual nodes")
                # OPTIMIZATION: Limit to just the top 5 nodes
                nodes_to_process = list(relevant_nodes)[:5] if relevant_nodes else []
                
                if nodes_to_process:
                    for node_id in nodes_to_process:
                        # OPTIMIZED: Simplified query to get faster results
                        node_info_cypher = """
                        MATCH (g:Graph {id: $graph_id})-[:CONTAINS]->(n:Node {id: $node_id})
                        OPTIONAL MATCH (n)-[r]-(related)
                        WHERE related.label IS NOT NULL
                        RETURN n.label AS label, labels(n) AS types, 
                               collect(DISTINCT type(r) + ' -> ' + related.label)[..5] AS relationships
                        LIMIT 1
                        """
                        
                        node_info = neo4j_service.query_graph(
                            graph_id=graph_id,
                            cypher_query=node_info_cypher,
                            params={"node_id": node_id}
                        )
                        
                        if node_info:
                            info = node_info[0]
                            node_type = next((t for t in info["types"] if t != "Node"), "Entity")
                            context += f"Node: {info['label']} (Type: {node_type})\n"
                            
                            # Add relationships
                            relationships = info["relationships"]
                            if relationships and relationships[0]:
                                context += f"Relationships: {', '.join(relationships[:5])}\n"
                            
                            context += "\n"
                
                # If still no context, try a full-text search but with limited results
                if not context or len(context.strip()) == 0:
                    logger.info("No node information found, trying full text search")
                    fulltext_cypher = """
                    MATCH (g:Graph {id: $graph_id})-[:CONTAINS]->(n:Node)
                    WHERE any(term IN $search_terms WHERE toLower(n.label) CONTAINS toLower(term))
                    RETURN n.id AS id, n.label AS label, labels(n) AS types
                    LIMIT 5
                    """
                    
                    fulltext_results = neo4j_service.query_graph(
                        graph_id=graph_id,
                        cypher_query=fulltext_cypher,
                        params={"search_terms": important_terms}
                    )
                    
                    for node in fulltext_results:
                        relevant_nodes.add(node["id"])
                    
                    if relevant_nodes:
                        logger.info(f"Full text search found {len(relevant_nodes)} nodes")
                        # Process only a few nodes to keep it fast
                        for node_id in list(relevant_nodes)[:3]:
                            node_info_cypher = """
                            MATCH (g:Graph {id: $graph_id})-[:CONTAINS]->(n:Node {id: $node_id})
                            OPTIONAL MATCH (n)-[r]-(related)
                            WHERE related.label IS NOT NULL
                            RETURN n.label AS label, labels(n) AS types, 
                                   collect(DISTINCT type(r) + ' -> ' + related.label)[..3] AS relationships
                            """
                            
                            node_info = neo4j_service.query_graph(
                                graph_id=graph_id,
                                cypher_query=node_info_cypher,
                                params={"node_id": node_id}
                            )
                            
                            if node_info:
                                info = node_info[0]
                                context += f"Entity: {info['label']} has relationships: {info['relationships']}\n"
        
        # If we still don't have context, get a general overview of the graph
        if not context or len(context.strip()) == 0:
            logger.info("No specific information found, providing graph overview")
            overview_cypher = """
            MATCH (g:Graph {id: $graph_id})-[:CONTAINS]->(n:Node)
            RETURN labels(n) AS types, count(n) AS count
            """
            
            node_counts = neo4j_service.query_graph(
                graph_id=graph_id,
                cypher_query=overview_cypher
            )
            
            if node_counts:
                context += "Graph Overview:\n"
                for item in node_counts:
                    node_type = next((t for t in item["types"] if t != "Node"), "Entity")
                    context += f"- {item['count']} nodes of type {node_type}\n"
            
            # Get some example relationships
            rel_cypher = """
            MATCH (g:Graph {id: $graph_id})-[:CONTAINS]->(n1:Node)-[r]->(n2:Node)
            RETURN n1.label AS source, type(r) AS relationship, n2.label AS target
            LIMIT 5
            """
            
            relationships = neo4j_service.query_graph(
                graph_id=graph_id,
                cypher_query=rel_cypher
            )
            
            if relationships:
                context += "\nExample Relationships:\n"
                for rel in relationships:
                    context += f"- {rel['source']} -{rel['relationship']}-> {rel['target']}\n"
        
        if not context or len(context.strip()) == 0:
            logger.warning(f"No context found for query: {query}")
            context = "No relevant information found in the knowledge graph."
        
        # Log the extracted context
        logger.info(f"Context extraction completed in {time.time() - start_time:.2f}s")
        
        # Generate answer using LLM
        llm_start_time = time.time()
        try:
            # First attempt with pipe syntax
            response = rag_chain.invoke({"question": query, "context": context})
            logger.info("Generated response using pipe syntax")
        except Exception as chain_err:
            logger.error(f"Error with pipe syntax: {chain_err}")
            try:
                # Fall back to the older run method
                from langchain.chains import LLMChain
                fallback_chain = LLMChain(llm=llm, prompt=rag_prompt)
                response = fallback_chain.run(question=query, context=context)
                logger.info("Generated response using LLMChain fallback")
            except Exception as run_err:
                logger.error(f"Error with run method: {run_err}")
                response = f"Error generating response: {str(run_err)}"
        
        logger.info(f"LLM response generated in {time.time() - llm_start_time:.2f}s")
        
        result = {
            "answer": response.strip() if isinstance(response, str) else str(response).strip(),
            "paths": relevant_paths,
            "context_used": context
        }
        
        # Cache the result
        if graph_id:
            _query_cache[cache_key] = result
            # Limit cache size - remove oldest items if needed
            if len(_query_cache) > MAX_CACHE_SIZE:
                # Remove oldest item (first key)
                oldest_key = next(iter(_query_cache))
                del _query_cache[oldest_key]
                
        logger.info(f"Total query processing time: {time.time() - start_time:.2f}s")
        return result
    
    except Exception as e:
        logger.exception(f"Error in query_knowledge_graph: {str(e)}")
        return {
            "answer": f"Error querying knowledge graph: {str(e)}",
            "paths": [],
            "context_used": ""
        }