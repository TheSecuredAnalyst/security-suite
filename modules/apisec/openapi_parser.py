"""OpenAPI/Swagger specification parser."""

import json
from dataclasses import dataclass, field
from pathlib import Path

import httpx
import yaml

from core.logger import get_logger, scrub
from core.url_guard import validate_outbound_url


@dataclass
class APIParameter:
    """API endpoint parameter."""
    name: str
    location: str  # query, path, header, cookie
    required: bool = False
    param_type: str = "string"
    description: str = ""
    example: str | None = None


@dataclass
class APIEndpoint:
    """API endpoint definition."""
    path: str
    method: str
    operation_id: str | None = None
    summary: str = ""
    description: str = ""
    parameters: list[APIParameter] = field(default_factory=list)
    request_body: dict | None = None
    responses: dict = field(default_factory=dict)
    security: list[dict] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)


@dataclass
class APISecurityScheme:
    """API security scheme."""
    name: str
    scheme_type: str  # apiKey, http, oauth2, openIdConnect
    location: str | None = None  # header, query, cookie (for apiKey)
    scheme: str | None = None  # bearer, basic (for http)
    bearer_format: str | None = None
    flows: dict | None = None  # for oauth2


@dataclass
class ParsedAPI:
    """Parsed API specification."""
    title: str
    version: str
    base_url: str
    endpoints: list[APIEndpoint]
    security_schemes: dict[str, APISecurityScheme]
    servers: list[str]
    description: str = ""


class OpenAPIParser:
    """Parser for OpenAPI/Swagger specifications."""

    def __init__(self):
        self.logger = get_logger("apisec.parser")

    async def parse_url(self, url: str, allow_private: bool | None = None) -> ParsedAPI:
        """Parse OpenAPI spec from URL.

        Args:
            url: URL to OpenAPI JSON/YAML spec
            allow_private: Permit specs hosted on private/loopback addresses.
                Defaults to the SECSUITE_ALLOW_PRIVATE_TARGETS setting.

        Returns:
            Parsed API specification

        Raises:
            BlockedTargetError: The URL is not a fetchable public http(s) target.
        """
        # The URL reaches us from an API caller, so validate it before it becomes
        # a request target (SSRF).
        safe_url = validate_outbound_url(url, allow_private=allow_private)

        self.logger.info(f"Fetching OpenAPI spec from {scrub(safe_url)}")

        # follow_redirects stays off: a redirect would send us to a location that
        # never passed validate_outbound_url().
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=False) as client:
            response = await client.get(safe_url)
            response.raise_for_status()

            content_type = response.headers.get("content-type", "")
            content = response.text

            if "yaml" in content_type or safe_url.endswith((".yaml", ".yml")):
                spec = yaml.safe_load(content)
            else:
                spec = json.loads(content)

        return self._parse_spec(spec, safe_url)

    def parse_file(self, path: str) -> ParsedAPI:
        """Parse OpenAPI spec from file.

        Args:
            path: Path to OpenAPI JSON/YAML file

        Returns:
            Parsed API specification
        """
        file_path = Path(path)
        self.logger.info(f"Parsing OpenAPI spec from {file_path}")

        content = file_path.read_text()

        if file_path.suffix in (".yaml", ".yml"):
            spec = yaml.safe_load(content)
        else:
            spec = json.loads(content)

        return self._parse_spec(spec, str(file_path))

    def parse_string(self, content: str, format: str = "json") -> ParsedAPI:
        """Parse OpenAPI spec from string.

        Args:
            content: OpenAPI spec content
            format: "json" or "yaml"

        Returns:
            Parsed API specification
        """
        if format == "yaml":
            spec = yaml.safe_load(content)
        else:
            spec = json.loads(content)

        return self._parse_spec(spec, "inline")

    def _parse_spec(self, spec: dict, source: str) -> ParsedAPI:
        """Parse OpenAPI specification dict.

        Args:
            spec: OpenAPI spec dictionary
            source: Source identifier

        Returns:
            Parsed API specification
        """
        # Determine OpenAPI version. YAML parses an unquoted `openapi: 3.0`
        # as a float, so coerce before doing string comparisons.
        openapi_version = str(spec.get("openapi", spec.get("swagger", "2.0")))
        is_v3 = openapi_version.startswith("3")

        # Parse info
        info = spec.get("info", {})
        title = info.get("title", "Unknown API")
        version = info.get("version", "1.0.0")
        description = info.get("description", "")

        # Parse servers/base URL
        servers = []
        if is_v3:
            for server in spec.get("servers", []):
                servers.append(server.get("url", ""))
        else:
            # OpenAPI 2.0 (Swagger)
            host = spec.get("host", "localhost")
            base_path = spec.get("basePath", "/")
            schemes = spec.get("schemes", ["https"])
            servers.append(f"{schemes[0]}://{host}{base_path}")

        base_url = servers[0] if servers else ""

        # Parse security schemes
        security_schemes = {}
        if is_v3:
            schemes = spec.get("components", {}).get("securitySchemes", {})
        else:
            schemes = spec.get("securityDefinitions", {})

        for name, scheme in schemes.items():
            security_schemes[name] = self._parse_security_scheme(name, scheme, is_v3)

        # Parse endpoints
        endpoints = []
        paths = spec.get("paths", {})

        for path, path_item in paths.items():
            # Handle path-level parameters
            path_params = path_item.get("parameters", [])

            for method in ["get", "post", "put", "patch", "delete", "head", "options"]:
                if method not in path_item:
                    continue

                operation = path_item[method]
                endpoint = self._parse_endpoint(
                    path, method, operation, path_params, is_v3
                )
                endpoints.append(endpoint)

        self.logger.info(f"Parsed {len(endpoints)} endpoints from {scrub(title)}")

        return ParsedAPI(
            title=title,
            version=version,
            base_url=base_url,
            endpoints=endpoints,
            security_schemes=security_schemes,
            servers=servers,
            description=description,
        )

    def _parse_security_scheme(
        self, name: str, scheme: dict, is_v3: bool
    ) -> APISecurityScheme:
        """Parse security scheme definition."""
        scheme_type = scheme.get("type", "apiKey")

        return APISecurityScheme(
            name=name,
            scheme_type=scheme_type,
            location=scheme.get("in"),
            scheme=scheme.get("scheme"),
            bearer_format=scheme.get("bearerFormat"),
            flows=scheme.get("flows"),
        )

    def _parse_endpoint(
        self,
        path: str,
        method: str,
        operation: dict,
        path_params: list,
        is_v3: bool,
    ) -> APIEndpoint:
        """Parse endpoint definition."""
        # Combine path-level and operation-level parameters
        all_params = path_params + operation.get("parameters", [])

        parameters = []
        for param in all_params:
            # Handle $ref
            if "$ref" in param:
                continue  # Skip refs for now

            parameters.append(APIParameter(
                name=param.get("name", ""),
                location=param.get("in", "query"),
                required=param.get("required", False),
                param_type=param.get("type", param.get("schema", {}).get("type", "string")),
                description=param.get("description", ""),
                example=param.get("example"),
            ))

        # Parse request body (OpenAPI 3.x)
        request_body = None
        if is_v3 and "requestBody" in operation:
            request_body = operation["requestBody"]

        return APIEndpoint(
            path=path,
            method=method.upper(),
            operation_id=operation.get("operationId"),
            summary=operation.get("summary", ""),
            description=operation.get("description", ""),
            parameters=parameters,
            request_body=request_body,
            responses=operation.get("responses", {}),
            security=operation.get("security", []),
            tags=operation.get("tags", []),
        )

    def discover_spec_url(self, base_url: str) -> list[str]:
        """Discover common OpenAPI spec locations.

        Args:
            base_url: Base URL of the API

        Returns:
            List of potential spec URLs
        """
        base_url = base_url.rstrip("/")

        common_paths = [
            "/openapi.json",
            "/openapi.yaml",
            "/swagger.json",
            "/swagger.yaml",
            "/api-docs",
            "/api-docs.json",
            "/v1/openapi.json",
            "/v2/openapi.json",
            "/v3/openapi.json",
            "/api/openapi.json",
            "/api/swagger.json",
            "/docs/openapi.json",
            "/.well-known/openapi.json",
        ]

        return [f"{base_url}{path}" for path in common_paths]
