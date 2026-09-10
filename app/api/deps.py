import uuid
import secrets
from datetime import datetime, timezone
from typing import Optional, Any
from fastapi import Security, HTTPException, status
from fastapi.security.api_key import APIKeyHeader
from app.config import API_KEY, SCHEMA_VERSION
from app.models.graph_models import ApiResponse, ApiMeta, ApiError

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def verify_api_key(header_key: Optional[str] = Security(api_key_header)) -> str:
    """Verifies API key using timing-safe comparison."""
    if not header_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing required authentication header: 'X-API-Key'",
        )
    if not secrets.compare_digest(header_key, API_KEY):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key provided",
        )
    return header_key


def success_response(data: Any, request_id: Optional[str] = None) -> ApiResponse:
    """Wraps successful data in standard envelope."""
    req_id = request_id or str(uuid.uuid4())
    return ApiResponse(
        success=True,
        data=data,
        error=None,
        meta=ApiMeta(
            request_id=req_id,
            schema_version=SCHEMA_VERSION,
            timestamp=datetime.now(timezone.utc).isoformat(),
        ),
    )


def error_response(
    code: str, message: str, details: Optional[Any] = None, request_id: Optional[str] = None
) -> ApiResponse:
    """Wraps error details in standard envelope."""
    req_id = request_id or str(uuid.uuid4())
    return ApiResponse(
        success=False,
        data=None,
        error=ApiError(code=code, message=message, details=details),
        meta=ApiMeta(
            request_id=req_id,
            schema_version=SCHEMA_VERSION,
            timestamp=datetime.now(timezone.utc).isoformat(),
        ),
    )
