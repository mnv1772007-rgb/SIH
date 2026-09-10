"""
Legacy Route Compatibility Layer: /api/graph/*
Aliases requests to the standardized /api/v1/graph/* endpoints.
"""

from app.api.v1.graph_routes import router