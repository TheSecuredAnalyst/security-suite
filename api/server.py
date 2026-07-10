"""FastAPI REST API server for Security Suite."""

import os
import secrets

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse

from api.routers import health, modules, results, scans

_SWAGGER_HTML = """<!DOCTYPE html>
<html>
  <head>
    <title>Security Suite API</title>
    <meta charset="utf-8"/>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>body {{ margin: 0; padding: 0; }}</style>
    <!-- Try unpkg first; if blocked the browser will fall back to the inline error -->
    <link rel="stylesheet"
          href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css"
          onerror="document.getElementById('cdn-err').style.display='block'">
  </head>
  <body>
    <div id="cdn-err" style="display:none;padding:2rem;font-family:sans-serif;color:#c00">
      <b>Swagger UI assets could not load.</b><br>
      This usually means the machine has no internet access.<br>
      You can still use the raw API via <a href="/openapi.json">/openapi.json</a>
      and a tool like Postman or curl.
    </div>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
    <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-standalone-preset.js"></script>
    <script>
      window.onload = function () {{
        if (typeof SwaggerUIBundle === 'undefined') {{
          document.getElementById('cdn-err').style.display = 'block';
          return;
        }}
        SwaggerUIBundle({{
          url: '/openapi.json',
          dom_id: '#swagger-ui',
          presets: [SwaggerUIBundle.presets.apis, SwaggerUIStandalonePreset],
          layout: 'StandaloneLayout',
          deepLinking: true,
          persistAuthorization: true,
        }});
      }};
    </script>
  </body>
</html>"""


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    api_key = os.environ.get("SECSUITE_API_KEY", "")

    app = FastAPI(
        title="Security Suite API",
        description=(
            "REST API for Security Suite — security scanning, API testing, and analysis.\n\n"
            "Set the `SECSUITE_API_KEY` environment variable to require an `X-API-Key` header "
            "on all endpoints (except `/health` and `/docs`)."
        ),
        version="0.2.0",
        docs_url=None,   # we serve custom docs below
        redoc_url=None,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Optional API key gate — skips /health, /docs, /openapi.json
    if api_key:
        _UNPROTECTED = {"/health", "/docs", "/openapi.json", "/redoc"}

        @app.middleware("http")
        async def require_api_key(request: Request, call_next):
            if request.url.path not in _UNPROTECTED:
                provided = request.headers.get("X-API-Key", "")
                # Constant-time compare so the key can't be recovered via timing.
                if not secrets.compare_digest(provided, api_key):
                    # Return the response directly: an HTTPException raised inside
                    # BaseHTTPMiddleware is not handled by FastAPI's exception
                    # handlers and would surface as an uncaught 500.
                    return JSONResponse(
                        status_code=401,
                        content={"detail": "Invalid or missing X-API-Key"},
                    )
            return await call_next(request)

    @app.get("/docs", include_in_schema=False)
    async def swagger_ui() -> HTMLResponse:
        return HTMLResponse(_SWAGGER_HTML)

    # Routers
    app.include_router(health.router, tags=["Health"])
    app.include_router(scans.router, prefix="/api/v1/scans", tags=["Scans"])
    app.include_router(results.router, prefix="/api/v1/results", tags=["Results"])
    app.include_router(modules.router, prefix="/api/v1/modules", tags=["Modules"])

    # API security testing router (imported lazily so fastapi is optional)
    try:
        from api.routers import apisec as apisec_router
        app.include_router(
            apisec_router.router,
            prefix="/api/v1/apisec",
            tags=["API Security Testing"],
        )
    except ImportError:
        pass

    return app
