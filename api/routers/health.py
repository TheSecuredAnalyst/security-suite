"""Health check endpoints."""

from datetime import datetime, timezone

from fastapi import APIRouter

from api.models import HealthResponse

router = APIRouter()


@router.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    """Health check endpoint."""
    return HealthResponse(
        status="healthy",
        version="0.2.0",
        timestamp=datetime.now(timezone.utc),
    )
