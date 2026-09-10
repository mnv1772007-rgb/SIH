from typing import Literal

from pydantic import BaseModel, Field


class RawEmailRequest(BaseModel):
    raw_email: str = Field(min_length=1, max_length=10 * 1024 * 1024)
    source_name: str = Field(default="pasted-email.eml", max_length=255)


class ReportExportRequest(BaseModel):
    """Requested on-demand report representation; no report is persisted to disk."""

    format: Literal["markdown", "json", "html"] = "markdown"


class ThreatIntelLookupRequest(BaseModel):
    """Request model for active multi-source threat intelligence lookup."""

    indicator: str = Field(min_length=1, max_length=2048)
    ioc_type: str | None = Field(default=None, max_length=32)
    force_refresh: bool = False


class ThreatIntelBatchRequest(BaseModel):
    """Request model for batch threat intelligence lookups."""

    indicators: list[dict[str, str]] = Field(max_length=100)
    force_refresh: bool = False

