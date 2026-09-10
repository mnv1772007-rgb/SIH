"""
Legacy Route Compatibility Layer: /api/campaigns/*
Aliases requests to the standardized /api/v1/campaigns/* endpoints.
"""

from app.api.v1.campaign_routes import router