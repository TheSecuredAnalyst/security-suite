"""Results endpoints."""

from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import FileResponse

from api.models import FindingResponse
from core.logger import get_logger

logger = get_logger("api.results")

router = APIRouter()


@router.get("/scans/{scan_id}/findings")
async def get_scan_findings(scan_id: str):
    """Get findings for a specific scan.

    Args:
        scan_id: Scan identifier

    Returns:
        List of findings
    """
    from api.routers.scans import scans_db

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

    return {"findings": findings, "total": len(findings)}


@router.get("/scans/{scan_id}/export/json")
async def export_scan_json(scan_id: str):
    """Export scan results as JSON.

    Args:
        scan_id: Scan identifier

    Returns:
        JSON file download
    """
    import json
    import tempfile

    from api.routers.scans import scans_db

    if scan_id not in scans_db:
        raise HTTPException(status_code=404, detail="Scan not found")

    scan = scans_db[scan_id]

    export_data = {
        "id": scan["id"],
        "target": scan["target"],
        "modules": scan["modules"],
        "status": scan["status"],
        "findings_count": len(scan["findings"]),
        "started_at": scan["started_at"].isoformat() if scan["started_at"] else None,
        "completed_at": scan["completed_at"].isoformat() if scan["completed_at"] else None,
        "findings": [
            {
                "id": f["id"],
                "title": f["title"],
                "description": f["description"],
                "severity": f["severity"].value,
                "module": f["module"],
                "data": f.get("data", {}),
                "created_at": f["created_at"].isoformat(),
            }
            for f in scan["findings"]
        ],
    }

    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(export_data, f, indent=2)
        temp_path = f.name

    return FileResponse(
        temp_path,
        filename=f"scan_{scan_id}.json",
        media_type="application/json",
    )


@router.get("/scans/{scan_id}/export/csv")
async def export_scan_csv(scan_id: str):
    """Export scan results as CSV.

    Args:
        scan_id: Scan identifier

    Returns:
        CSV file download
    """
    import csv
    import tempfile

    from api.routers.scans import scans_db

    if scan_id not in scans_db:
        raise HTTPException(status_code=404, detail="Scan not found")

    scan = scans_db[scan_id]

    with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False, newline='') as f:
        writer = csv.DictWriter(
            f,
            fieldnames=['Title', 'Severity', 'Module', 'Description'],
        )
        writer.writeheader()

        for finding in scan["findings"]:
            writer.writerow({
                'Title': finding['title'],
                'Severity': finding['severity'].value,
                'Module': finding['module'],
                'Description': finding['description'],
            })

        temp_path = f.name

    return FileResponse(
        temp_path,
        filename=f"scan_{scan_id}.csv",
        media_type="text/csv",
    )


@router.get("/summary")
async def get_summary(
    days: int = Query(7, ge=1, le=365),
):
    """Get summary statistics for scans.

    Args:
        days: Number of days to include

    Returns:
        Summary statistics
    """
    from datetime import timedelta

    from api.routers.scans import scans_db

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    recent_scans = [
        s for s in scans_db.values()
        if s["completed_at"] and s["completed_at"] >= cutoff
    ]

    total_findings = sum(len(s["findings"]) for s in recent_scans)

    severity_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }

    for scan in recent_scans:
        for finding in scan["findings"]:
            severity = finding["severity"].value
            if severity in severity_counts:
                severity_counts[severity] += 1

    return {
        "total_scans": len(recent_scans),
        "total_findings": total_findings,
        "severity_breakdown": severity_counts,
        "period_days": days,
    }
