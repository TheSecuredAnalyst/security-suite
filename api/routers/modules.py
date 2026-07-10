"""Module information endpoints."""

from fastapi import APIRouter

from api.models import ModuleInfo, ModulesResponse
from core.logger import get_logger

logger = get_logger("api.modules")

router = APIRouter()


@router.get("/", response_model=ModulesResponse)
async def list_modules() -> ModulesResponse:
    """List all available modules and their capabilities.

    Returns:
        ModulesResponse with module information
    """
    osint_modules = [
        ModuleInfo(
            name="dns",
            category="osint",
            description="DNS enumeration and zone transfer detection",
        ),
        ModuleInfo(
            name="whois",
            category="osint",
            description="WHOIS lookup with registrar details",
        ),
        ModuleInfo(
            name="subdomains",
            category="osint",
            description="Subdomain discovery",
        ),
        ModuleInfo(
            name="headers",
            category="osint",
            description="HTTP header analysis for security issues",
        ),
        ModuleInfo(
            name="tech",
            category="osint",
            description="Technology detection (frameworks, CMS, servers)",
        ),
        ModuleInfo(
            name="ports",
            category="osint",
            description="Port scanning (requires nmap)",
        ),
    ]

    webscanner_modules = [
        ModuleInfo(
            name="crawler",
            category="webscanner",
            description="Web crawling and link discovery",
        ),
        ModuleInfo(
            name="xss",
            category="webscanner",
            description="XSS (Cross-Site Scripting) detection",
        ),
        ModuleInfo(
            name="sqli",
            category="webscanner",
            description="SQL injection testing",
        ),
        ModuleInfo(
            name="dirs",
            category="webscanner",
            description="Directory bruteforce",
        ),
        ModuleInfo(
            name="ssl",
            category="webscanner",
            description="SSL/TLS analysis (certificate, protocols, vulnerabilities)",
        ),
    ]

    apisec_modules = [
        ModuleInfo(
            name="openapi",
            category="apisec",
            description="OpenAPI/Swagger specification parsing",
        ),
        ModuleInfo(
            name="auth",
            category="apisec",
            description="API authentication bypass testing",
        ),
        ModuleInfo(
            name="endpoints",
            category="apisec",
            description="API endpoint security testing",
        ),
        ModuleInfo(
            name="fuzzer",
            category="apisec",
            description="Parameter fuzzing and anomaly detection",
        ),
    ]

    compliance_modules = [
        ModuleInfo(
            name="owasp",
            category="compliance",
            description="OWASP Top 10 compliance checking",
        ),
        ModuleInfo(
            name="cis",
            category="compliance",
            description="CIS Controls assessment",
        ),
    ]

    return ModulesResponse(
        osint=osint_modules,
        webscanner=webscanner_modules,
        apisec=apisec_modules,
        compliance=compliance_modules,
        total=len(osint_modules) + len(webscanner_modules) + len(apisec_modules) + len(compliance_modules),
    )


@router.get("/{category}")
async def list_modules_by_category(category: str) -> dict:
    """Get modules for a specific category.

    Args:
        category: Module category (osint, webscanner, apisec, compliance)

    Returns:
        List of modules in category
    """
    modules = await list_modules()

    category_map = {
        "osint": modules.osint,
        "webscanner": modules.webscanner,
        "apisec": modules.apisec,
        "compliance": modules.compliance,
    }

    if category not in category_map:
        return {"error": f"Unknown category: {category}"}

    return {"category": category, "modules": category_map[category]}
