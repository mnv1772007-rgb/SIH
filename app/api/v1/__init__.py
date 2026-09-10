from fastapi import APIRouter
from app.api.v1.graph_routes import router as graph_router
from app.api.v1.campaign_routes import router as campaign_router
from app.api.v1.infrastructure_routes import router as infrastructure_router

api_v1_router = APIRouter()
api_v1_router.include_router(graph_router)
api_v1_router.include_router(campaign_router)
api_v1_router.include_router(infrastructure_router)
