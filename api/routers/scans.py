"""Scan endpoints."""

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query

from api.models import FindingResponse, ScanListResponse, ScanRequest, ScanResponse
from core.logger import get_logger, scrub
from core.models import Target

logger = get_logger("api.scans")

router = APIRouter()

# In-memory storage (in production, use a database)
scans_db: dict[str, dict] = {}


@router.post("/", response_model=ScanResponse)
async def create_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
) -> ScanResponse:
    """Create a new scan.

    Args:
        request: Scan configuration
        background_tasks: Background task queue

    Returns:
        ScanResponse with scan details
    """
    scan_id = str(uuid.uuid4())

    scan = {
        "id": scan_id,
        "target": request.target,
        "modules": request.modules,
        "status": "pending",
        "findings": [],
        "started_at": None,
        "completed_at": None,
        "error": None,
        "dry_run": request.dry_run,
        "options": request.options,
    }

    scans_db[scan_id] = scan

    # Schedule scan execution
    if not request.dry_run:
        background_tasks.add_task(execute_scan, scan_id)
    else:
        scan["status"] = "completed"
        scan["completed_at"] = datetime.now(timezone.utc)
        logger.info(f"DRY-RUN scan {scan_id} for {scrub(request.target)}")

    return ScanResponse(
        id=scan["id"],
        target=scan["target"],
        modules=scan["modules"],
        status=scan["status"],
        findings_count=len(scan["findings"]),
    )


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: str) -> ScanResponse:
    """Get scan details by ID.

    Args:
        scan_id: Scan identifier

    Returns:
        ScanResponse with scan details

    Raises:
        HTTPException: If scan not found
    """
    if scan_id not in scans_db:
        raise HTTPException(status_code=404, detail="Scan not found")

    scan = scans_db[scan_id]

    findings = [
        FindingResponse(
            id=f["id"],
            title=f["title"],
            description=f["description"],
            severity=f["severity"].value,
            module=f["module"],
            data=f.get("data", {}),
            created_at=f["created_at"],
        )
        for f in scan["findings"]
    ]

    return ScanResponse(
        id=scan["id"],
        target=scan["target"],
        modules=scan["modules"],
        status=scan["status"],
        findings_count=len(scan["findings"]),
        findings=findings,
        started_at=scan["started_at"],
        completed_at=scan["completed_at"],
        error=scan["error"],
    )


@router.get("/", response_model=ScanListResponse)
async def list_scans(
    page: int = Query(1, ge=1),
    page_size: int = Query(10, ge=1, le=100),
) -> ScanListResponse:
    """List all scans with pagination.

    Args:
        page: Page number (1-indexed)
        page_size: Items per page

    Returns:
        ScanListResponse with paginated results
    """
    all_scans = list(scans_db.values())
    total = len(all_scans)

    start = (page - 1) * page_size
    end = start + page_size

    paginated_scans = all_scans[start:end]

    scan_responses = [
        ScanResponse(
            id=s["id"],
            target=s["target"],
            modules=s["modules"],
            status=s["status"],
            findings_count=len(s["findings"]),
            started_at=s["started_at"],
            completed_at=s["completed_at"],
            error=s["error"],
        )
        for s in paginated_scans
    ]

    return ScanListResponse(
        total=total,
        page=page,
        page_size=page_size,
        scans=scan_responses,
    )


@router.delete("/{scan_id}")
async def delete_scan(scan_id: str) -> dict:
    """Delete a scan.

    Args:
        scan_id: Scan identifier

    Returns:
        Confirmation message

    Raises:
        HTTPException: If scan not found
    """
    if scan_id not in scans_db:
        raise HTTPException(status_code=404, detail="Scan not found")

    del scans_db[scan_id]
    return {"message": f"Scan {scan_id} deleted"}


async def execute_scan(scan_id: str) -> None:
    """Execute a scan in the background.

    Args:
        scan_id: Scan identifier
    """
    try:
        scan = scans_db[scan_id]
        scan["status"] = "running"
        scan["started_at"] = datetime.now(timezone.utc)

        logger.info(f"Starting scan {scan_id} for target {scan['target']}")

        # Import modules dynamically
        from modules.osint import (
            DNSEnumerator,
            HeaderAnalyzer,
            PortScanner,
            SubdomainScanner,
            TechDetector,
            WhoisLookup,
        )
        from modules.webscanner import (
            DirectoryBruteforcer,
            SQLiScanner,
            SSLAnalyzer,
            WebCrawler,
            XSSScanner,
        )

        target = Target.from_string(scan["target"])
        module_map = {
            "dns": DNSEnumerator(),
            "whois": WhoisLookup(),
            "subdomains": SubdomainScanner(),
            "headers": HeaderAnalyzer(),
            "tech": TechDetector(),
            "ports": PortScanner(),
            "crawler": WebCrawler(max_pages=50),
            "xss": XSSScanner(),
            "sqli": SQLiScanner(),
            "dirs": DirectoryBruteforcer(),
            "ssl": SSLAnalyzer(),
        }

        # Run selected modules
        for module_name in scan["modules"]:
            if module_name in module_map:
                try:
                    result = await module_map[module_name].run(target)
                    scan["findings"].extend(result.findings)
                    logger.info(f"Module {module_name} found {len(result.findings)} findings")
                except Exception as e:
                    logger.error(f"Error running module {module_name}: {e}")

        scan["status"] = "completed"
        scan["completed_at"] = datetime.now(timezone.utc)
        logger.info(f"Scan {scan_id} completed with {len(scan['findings'])} findings")

    except Exception as e:
        scan = scans_db[scan_id]
        scan["status"] = "failed"
        scan["error"] = str(e)
        scan["completed_at"] = datetime.now(timezone.utc)
        logger.error(f"Scan {scan_id} failed: {e}")
