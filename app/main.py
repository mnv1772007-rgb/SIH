import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from app.config import (
    PROJECT_NAME,
    SCHEMA_VERSION,
    CORS_ORIGINS,
    API_V1_STR,
    ATTRIBUTION_DISCLAIMER,
)
from app.services.neo4j_service import neo4j_service
from app.api.v1 import api_v1_router
from app.api.graph_routes import router as legacy_graph_router
from app.api.campaign_routes import router as legacy_campaign_router
from app.api.analyze_routes import router as analyze_router
from app.api.deps import error_response, success_response

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Modern lifespan context manager managing startup and shutdown state."""
    logger.info("Starting up %s (Schema v%s)...", PROJECT_NAME, SCHEMA_VERSION)
    # Connect to Neo4j (resilient, non-blocking if offline)
    neo4j_service.connect()
    yield
    # Graceful shutdown
    logger.info("Shutting down %s...", PROJECT_NAME)
    neo4j_service.close()


app = FastAPI(
    title=PROJECT_NAME,
    description=(
        "SIH Problem Statement 26106: AI-Powered Email Threat Detection, GeoLocation & "
        "Forensic Intelligence Platform.\n\n"
        "**Role 4: Graph & Campaign Correlation Module**\n\n"
        "- Email → Domain → IP → URL → Hash → ASN graph modeling\n"
        "- Explainable multi-feature campaign clustering (NetworkX/Neo4j)\n"
        "- Infrastructure correlation pivots\n"
        "- Operational attribution confidence scoring\n"
        "- JSON-serializable graph structures for frontend visualization\n\n"
        f"> **Notice**: {ATTRIBUTION_DISCLAIMER}"
    ),
    version=SCHEMA_VERSION,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# Safe CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Global Exception Handlers enforcing standard {success, data, error, meta} envelope
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    code_map = {
        400: "BAD_REQUEST",
        401: "UNAUTHORIZED",
        403: "FORBIDDEN",
        404: "ENTITY_NOT_FOUND",
        422: "UNPROCESSABLE_ENTITY",
    }
    code = code_map.get(exc.status_code, "HTTP_ERROR")
    envelope = error_response(
        code=code,
        message=str(exc.detail),
    )
    return JSONResponse(
        status_code=exc.status_code,
        content=envelope.model_dump(),
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    envelope = error_response(
        code="VALIDATION_ERROR",
        message="Request payload failed schema validation",
        details=exc.errors(),
    )
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content=envelope.model_dump(),
    )


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled server error: %s", exc)
    envelope = error_response(
        code="INTERNAL_SERVER_ERROR",
        message="An unexpected internal server error occurred",
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=envelope.model_dump(),
    )


# Mount Standard Versioned API Router
app.include_router(api_v1_router, prefix=API_V1_STR)

# Mount Legacy Routers for backward compatibility with existing SIH modules
app.include_router(legacy_graph_router, prefix="/api/graph")
app.include_router(legacy_campaign_router, prefix="/api/campaigns")

# Mount Analyze router for Frontend connection (both /api/analyze and /analyze)
app.include_router(analyze_router, prefix="/api")
app.include_router(analyze_router)


@app.get("/health", tags=["Health & Status"])
async def health_check():
    """Unauthenticated health status endpoint for load balancers and SIH platform monitors."""
    is_connected = neo4j_service.is_connected()
    stats = neo4j_service.get_graph_stats() if is_connected else None
    return {
        "status": "healthy" if is_connected else "degraded",
        "service": "Role 4 — Graph & Campaign Correlation",
        "schema_version": SCHEMA_VERSION,
        "neo4j": "connected" if is_connected else "disconnected",
        "stats": stats,
    }


@app.get("/", tags=["Health & Status"])
async def root():
    """Root endpoint providing service overview and documentation links."""
    return success_response({
        "service": PROJECT_NAME,
        "role": "Role 4 — Graph & Campaign Correlation",
        "problem_statement": "SIH-26106",
        "version": SCHEMA_VERSION,
        "swagger_docs": "/docs",
        "redoc": "/redoc",
        "api_v1_base": API_V1_STR,
        "primary_endpoints": [
            f"{API_V1_STR}/graph/stats",
            f"{API_V1_STR}/graph/ingest",
            f"{API_V1_STR}/graph/email/{{email_id}}",
            f"{API_V1_STR}/graph/email/{{email_id}}/path",
            f"{API_V1_STR}/graph/domain/{{domain}}",
            f"{API_V1_STR}/graph/ip/{{ip}}",
            f"{API_V1_STR}/graph/all",
            f"{API_V1_STR}/campaigns/cluster",
            f"{API_V1_STR}/campaigns",
            f"{API_V1_STR}/campaigns/{{campaign_id}}",
            f"{API_V1_STR}/campaigns/{{campaign_id}}/graph",
            f"{API_V1_STR}/campaigns/{{campaign_id}}/confidence",
            f"{API_V1_STR}/campaigns/{{campaign_id}}/report",
            f"{API_V1_STR}/infrastructure/clusters",
            f"{API_V1_STR}/infrastructure/ip/{{ip}}",
            f"{API_V1_STR}/infrastructure/domain/{{domain}}",
        ],
        "attribution_policy": ATTRIBUTION_DISCLAIMER,
    })