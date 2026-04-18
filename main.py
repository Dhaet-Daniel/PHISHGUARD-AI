import logging
from datetime import UTC, datetime
from pathlib import Path
from time import perf_counter

from fastapi import FastAPI, Request
from fastapi.openapi.docs import (
    get_redoc_html,
    get_swagger_ui_html,
    get_swagger_ui_oauth2_redirect_html,
)
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address

try:
    from backend.core.limiter import limiter
    from backend.models import init_db
    from backend.routes.predict import router as predict_router
except ModuleNotFoundError:
    from core.limiter import limiter
    from models import init_db
    from routes.predict import router as predict_router

APP_DIR = Path(__file__).resolve().parent
STATIC_DIR = APP_DIR / "static"

logger = logging.getLogger("phishguard.api")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO)

init_db()

app = FastAPI(
    title="PhishGuardAI API",
    version="1.1.0",
    description=(
        "Explainable email phishing analysis with request examples, weighted signal "
        "breakdowns, and reviewer feedback capture."
    ),
    contact={"name": "PhishGuardAI Support", "email": "support@phishguardai.com"},
    docs_url=None,
    redoc_url=None,
    openapi_tags=[
        {
            "name": "phishing-detection",
            "description": "Endpoints for analyzing single emails, batch payloads, and reviewer feedback.",
        },
        {
            "name": "system",
            "description": "Operational endpoints for API discovery and health checks.",
        },
    ],
)

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)


@app.middleware("http")
async def request_timing_middleware(request: Request, call_next):
    start = perf_counter()
    response = await call_next(request)
    duration = perf_counter() - start
    response.headers["X-Process-Time"] = f"{duration:.4f}"
    logger.info(
        "%s %s -> %s (%.4fs)",
        request.method,
        request.url.path,
        response.status_code,
        duration,
    )
    return response


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled error on %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=500,
        content={"detail": "An unexpected server error occurred."},
    )


@app.get("/docs", include_in_schema=False)
async def custom_swagger_ui_html():
    swagger = get_swagger_ui_html(
        openapi_url=app.openapi_url,
        title=f"{app.title} Docs",
        oauth2_redirect_url=app.swagger_ui_oauth2_redirect_url,
        swagger_favicon_url="/static/logo.svg",
        swagger_ui_parameters={
            "docExpansion": "list",
            "defaultModelsExpandDepth": -1,
            "displayRequestDuration": True,
            "filter": True,
            "persistAuthorization": True,
            "tryItOutEnabled": True,
        },
    )
    html = swagger.body.decode("utf-8")
    html = html.replace(
        "</head>",
        '  <link rel="stylesheet" type="text/css" href="/static/swagger-custom.css">\n</head>',
    )
    return HTMLResponse(html)


@app.get(app.swagger_ui_oauth2_redirect_url, include_in_schema=False)
async def swagger_ui_redirect():
    return get_swagger_ui_oauth2_redirect_html()


@app.get("/redoc", include_in_schema=False)
async def redoc_html():
    return get_redoc_html(
        openapi_url=app.openapi_url,
        title=f"{app.title} ReDoc",
        redoc_favicon_url="/static/logo.svg",
    )


@app.get("/", tags=["system"], summary="API overview")
def api_root():
    return {
        "message": "PhishGuardAI API is running.",
        "docs": "/docs",
        "redoc": "/redoc",
        "health": "/health",
        "predict": "/api/v1/predict",
    }


@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    return FileResponse(STATIC_DIR / "logo.svg", media_type="image/svg+xml")


@app.get("/health", tags=["system"], summary="Service health check")
def health_check():
    return {
        "status": "ok",
        "service": "PhishGuardAI API",
        "version": app.version,
        "timestamp": datetime.now(UTC).isoformat(),
    }


app.include_router(predict_router, prefix="/api/v1")
