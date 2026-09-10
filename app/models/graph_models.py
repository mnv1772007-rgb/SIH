"""
Graph Data Models & Unified Response Envelopes
Role 4: Graph & Campaign Correlation Module
"""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any, Generic, TypeVar
from enum import Enum
from datetime import datetime


T = TypeVar("T")


class NodeType(str, Enum):
    EMAIL = "Email"
    DOMAIN = "Domain"
    IP = "IP"
    URL = "URL"
    HASH = "Hash"
    CAMPAIGN = "Campaign"
    ASN = "ASN"


class RelationshipType(str, Enum):
    SENT_FROM = "SENT_FROM"
    CONTAINS_DOMAIN = "CONTAINS_DOMAIN"
    CONTAINS_URL = "CONTAINS_URL"
    HOSTED_ON_DOMAIN = "HOSTED_ON_DOMAIN"
    RESOLVES_TO = "RESOLVES_TO"
    BELONGS_TO_ASN = "BELONGS_TO_ASN"
    CONTAINS_HASH = "CONTAINS_HASH"
    MEMBER_OF = "MEMBER_OF"
    USES_DOMAIN = "USES_DOMAIN"
    USES_IP = "USES_IP"
    USES_URL = "USES_URL"
    USES_HASH = "USES_HASH"


class ConfidenceLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERY_HIGH = "very_high"


# =======================================================
# Frontend Integration Models (Role 6 Contract)
# =======================================================

class FrontendNode(BaseModel):
    id: str = Field(..., description="Globally unique prefixed ID e.g. email:123, domain:evil.com")
    type: str = Field(..., description="Node category: email, domain, ip, url, hash, campaign, asn")
    label: str = Field(..., description="Human readable label for graph visualization")
    risk_score: float = Field(0.0, description="Risk score 0.0 to 1.0")
    properties: Dict[str, Any] = Field(default_factory=dict, description="Detailed attributes")


class FrontendEdge(BaseModel):
    id: str = Field(..., description="Unique edge ID")
    source: str = Field(..., description="Source node prefixed ID")
    target: str = Field(..., description="Target node prefixed ID")
    type: str = Field(..., description="Relationship type e.g. RESOLVES_TO, USES_IP")
    properties: Dict[str, Any] = Field(default_factory=dict)


class FrontendGraphResponse(BaseModel):
    nodes: List[FrontendNode] = Field(default_factory=list)
    edges: List[FrontendEdge] = Field(default_factory=list)


# =======================================================
# Confidence & Attribution Analysis Models
# =======================================================

class ConfidenceBreakdown(BaseModel):
    infrastructure: float = Field(..., ge=0.0, le=1.0)
    temporal: float = Field(..., ge=0.0, le=1.0)
    behavioral: float = Field(..., ge=0.0, le=1.0)
    content: float = Field(..., ge=0.0, le=1.0)


class AttributionConfidenceResponse(BaseModel):
    campaign_id: str
    confidence: float = Field(..., ge=0.0, le=1.0)
    level: ConfidenceLevel
    breakdown: ConfidenceBreakdown
    evidence: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    methodology_disclaimer: str


# =======================================================
# Unified Standard API Response Envelopes (Phase 11)
# =======================================================

class ApiMeta(BaseModel):
    request_id: str
    schema_version: str = "1.0"
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")


class ApiError(BaseModel):
    code: str
    message: str
    details: Optional[Any] = None


class ApiResponse(BaseModel, Generic[T]):
    success: bool
    data: Optional[T] = None
    error: Optional[ApiError] = None
    meta: ApiMeta


# =======================================================
# Graph Ingestion Result Model
# =======================================================

class IngestionResult(BaseModel):
    analysis_id: str
    email_id: str
    nodes_created: int
    nodes_matched: int
    relationships_created: int
    relationships_matched: int


class GraphStatsResponse(BaseModel):
    total_nodes: int
    total_relationships: int
    nodes_by_type: Dict[str, int]
    relationships_by_type: Dict[str, int]