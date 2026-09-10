import os
from typing import List
from dotenv import load_dotenv

load_dotenv()

# Neo4j Connection
NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "password")

# API Configuration
API_KEY = os.getenv("API_KEY", "dev-key")
API_V1_STR = "/api/v1"
PROJECT_NAME = "Threat Intelligence Graph & Campaign Correlation API"
SCHEMA_VERSION = "1.0"

# CORS Configuration
_raw_cors = os.getenv("CORS_ORIGINS", "http://localhost:3000,http://localhost:5173")
CORS_ORIGINS: List[str] = [
    origin.strip() for origin in _raw_cors.split(",") if origin.strip()
]

# Graph Safety & Query Bounds
DEFAULT_GRAPH_DEPTH = int(os.getenv("DEFAULT_GRAPH_DEPTH", "2"))
MAX_GRAPH_DEPTH = int(os.getenv("MAX_GRAPH_DEPTH", "4"))
DEFAULT_GRAPH_LIMIT = int(os.getenv("DEFAULT_GRAPH_LIMIT", "50"))
MAX_GRAPH_LIMIT = int(os.getenv("MAX_GRAPH_LIMIT", "100"))

# Campaign Clustering Weights (Must sum to 1.0)
WEIGHT_IOC_OVERLAP = float(os.getenv("WEIGHT_IOC_OVERLAP", "0.35"))
WEIGHT_INFRA_OVERLAP = float(os.getenv("WEIGHT_INFRA_OVERLAP", "0.30"))
WEIGHT_SUBJECT_SIMILARITY = float(os.getenv("WEIGHT_SUBJECT_SIMILARITY", "0.15"))
WEIGHT_TEMPORAL = float(os.getenv("WEIGHT_TEMPORAL", "0.10"))
WEIGHT_BEHAVIOR = float(os.getenv("WEIGHT_BEHAVIOR", "0.10"))

# Attribution Confidence Weights (Must sum to 1.0)
CONF_WEIGHT_INFRA = float(os.getenv("CONF_WEIGHT_INFRA", "0.35"))
CONF_WEIGHT_TEMPORAL = float(os.getenv("CONF_WEIGHT_TEMPORAL", "0.25"))
CONF_WEIGHT_BEHAVIOR = float(os.getenv("CONF_WEIGHT_BEHAVIOR", "0.25"))
CONF_WEIGHT_CONTENT = float(os.getenv("CONF_WEIGHT_CONTENT", "0.15"))

# Confidence Threshold Levels
CONF_LEVEL_LOW = float(os.getenv("CONF_LEVEL_LOW", "0.40"))
CONF_LEVEL_MED = float(os.getenv("CONF_LEVEL_MED", "0.70"))
CONF_LEVEL_HIGH = float(os.getenv("CONF_LEVEL_HIGH", "0.90"))

# Attribution Legal & Forensic Disclaimers
ATTRIBUTION_DISCLAIMER = (
    "Correlation identifies probable/shared infrastructure and behavioral relationships. "
    "IP ownership or geolocation must not be interpreted as proof of an attacker's physical identity."
)