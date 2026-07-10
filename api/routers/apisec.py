"""API Security Testing endpoints."""

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, HTTPException
from pydantic import BaseModel, Field

from core.logger import get_logger

logger = get_logger("api.apisec")
router = APIRouter()

# Shared with scans router so results are retrievable via GET /api/v1/scans/{id}
from api.routers.scans import scans_db  # noqa: E402

# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

class APISecScanRequest(BaseModel):
    spec_url: str = Field(..., description="URL to the OpenAPI/Swagger JSON or YAML spec")
    modules: list[str] = Field(
        default=["endpoints", "auth", "fuzzer"],
        description="Which apisec modules to run: endpoints, auth, fuzzer",
    )
    auth_token: str | None = Field(
        default=None,
        description="Bearer token to include in requests (so protected endpoints can be tested)",
    )
    max_fuzz_requests: int = Field(
        default=100,
        description="Max HTTP requests the fuzzer may send",
        ge=1,
        le=1000,
    )


class APISpecInfo(BaseModel):
    title: str
    version: str
    base_url: str
    servers: list[str]
    endpoint_count: int
    security_schemes: list[str]
    description: str


class DiscoverRequest(BaseModel):
    base_url: str = Field(..., description="Base URL of the target API")


# ---------------------------------------------------------------------------
# Background task
# ---------------------------------------------------------------------------

async def _execute_apisec_scan(scan_id: str) -> None:
    """Run apisec modules in the background and store findings in scans_db."""
    scan = scans_db[scan_id]
    scan["status"] = "running"
    scan["started_at"] = datetime.now(timezone.utc)

    spec_url: str = scan["options"]["spec_url"]
    auth_token: str | None = scan["options"].get("auth_token")
    max_fuzz: int = scan["options"].get("max_fuzz_requests", 100)

    try:
        from modules.apisec import APIAuthTester, APIEndpointTester, APIFuzzer, OpenAPIParser

        parser = OpenAPIParser()
        api = await parser.parse_url(spec_url)
        logger.info(f"Scan {scan_id}: parsed {len(api.endpoints)} endpoints from {api.title}")

        for module_name in scan["modules"]:
            try:
                if module_name == "endpoints":
                    tester = APIEndpointTester(auth_token=auth_token)
                    result = await tester.test_api(api)
                elif module_name == "auth":
                    tester = APIAuthTester()
                    result = await tester.test_api_auth(api)
                elif module_name == "fuzzer":
                    fuzzer = APIFuzzer(max_requests=max_fuzz, auth_token=auth_token)
                    result = await fuzzer.fuzz_api(api)
                else:
                    logger.warning(f"Unknown apisec module: {module_name}")
                    continue

                for f in result.findings:
                    scan["findings"].append({
                        "id": str(uuid.uuid4()),
                        "title": f.title,
                        "description": f.description,
                        "severity": f.severity,
                        "module": f.source,
                        "data": f.data or {},
                        "created_at": datetime.now(timezone.utc),
                    })

                logger.info(f"Scan {scan_id}: module '{module_name}' found {len(result.findings)} findings")

            except Exception as e:
                logger.error(f"Scan {scan_id}: module '{module_name}' error: {e}")

        scan["status"] = "completed"
        scan["completed_at"] = datetime.now(timezone.utc)
        logger.info(f"Scan {scan_id} completed with {len(scan['findings'])} total findings")

    except Exception as e:
        scan["status"] = "failed"
        scan["error"] = str(e)
        scan["completed_at"] = datetime.now(timezone.utc)
        logger.error(f"Scan {scan_id} failed: {e}")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/scan", summary="Start an API security scan")
async def start_apisec_scan(
    request: APISecScanRequest,
    background_tasks: BackgroundTasks,
) -> dict:
    """
    Fetch an OpenAPI/Swagger spec and run security tests against it.

    **modules** you can choose from:
    - `endpoints` — tests each endpoint for BOLA/IDOR, injections, mass assignment, info disclosure
    - `auth` — tests authentication bypass, broken auth, JWT weaknesses, rate limiting
    - `fuzzer` — fuzzes parameters with malformed / boundary inputs looking for crashes and leaks

    Results are stored and retrievable via `GET /api/v1/scans/{scan_id}`.
    """
    scan_id = str(uuid.uuid4())

    scans_db[scan_id] = {
        "id": scan_id,
        "target": request.spec_url,
        "modules": request.modules,
        "status": "pending",
        "findings": [],
        "started_at": None,
        "completed_at": None,
        "error": None,
        "dry_run": False,
        "options": {
            "spec_url": request.spec_url,
            "auth_token": request.auth_token,
            "max_fuzz_requests": request.max_fuzz_requests,
            "scan_type": "apisec",
        },
    }

    background_tasks.add_task(_execute_apisec_scan, scan_id)

    return {
        "scan_id": scan_id,
        "status": "pending",
        "message": f"API security scan started. Poll GET /api/v1/scans/{scan_id} for results.",
        "spec_url": request.spec_url,
        "modules": request.modules,
    }


@router.post("/parse", response_model=APISpecInfo, summary="Parse an OpenAPI spec")
async def parse_spec(request: DiscoverRequest) -> APISpecInfo:
    """
    Fetch and parse an OpenAPI/Swagger spec URL, returning a summary of what was found.
    Useful for inspecting an API before deciding which tests to run.
    """
    try:
        from modules.apisec import OpenAPIParser
        parser = OpenAPIParser()
        api = await parser.parse_url(request.base_url)

        return APISpecInfo(
            title=api.title,
            version=api.version,
            base_url=api.base_url,
            servers=api.servers,
            endpoint_count=len(api.endpoints),
            security_schemes=list(api.security_schemes.keys()),
            description=api.description,
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to parse spec: {e}") from e


@router.post("/discover", summary="Discover OpenAPI spec locations")
async def discover_spec(request: DiscoverRequest) -> dict:
    """
    Probe common paths on a base URL to find where the OpenAPI/Swagger spec lives.
    Returns a list of URLs to try (does not fetch them — just lists candidates).
    """
    from modules.apisec import OpenAPIParser
    parser = OpenAPIParser()
    candidates = parser.discover_spec_url(request.base_url)

    return {
        "base_url": request.base_url,
        "candidate_urls": candidates,
        "tip": "Try each URL in your browser or pass one to POST /api/v1/apisec/parse",
    }


@router.get("/modules", summary="List available apisec modules")
async def list_apisec_modules() -> dict:
    """List the available API security testing modules and what they check."""
    return {
        "modules": [
            {
                "name": "endpoints",
                "description": "Test each endpoint for BOLA/IDOR, SQL/NoSQL/command injection, mass assignment, and information disclosure in error responses",
            },
            {
                "name": "auth",
                "description": "Test authentication bypass via header manipulation, broken auth with empty credentials, JWT weaknesses (none-alg, missing exp), and missing rate limiting on login endpoints",
            },
            {
                "name": "fuzzer",
                "description": "Fuzz all parameters with boundary values, injection payloads, and malformed bodies. Detects crashes, error leaks, and unexpected behaviour",
            },
        ]
    }
