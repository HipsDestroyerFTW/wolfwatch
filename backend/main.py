"""Wolf Industries DarkWeb Monitor — FastAPI application entry point."""
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import os

from .database import init_db
from .services.scheduler import start_scheduler, stop_scheduler
from .routers import targets, scans, findings, dashboard
from .config import settings

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting Wolf Industries DarkWeb Monitor...")
    init_db()
    start_scheduler()
    yield
    logger.info("Shutting down...")
    stop_scheduler()


app = FastAPI(
    title="Wolf Industries DarkWeb Monitor",
    description="AI-assisted dark web threat intelligence platform",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API routes
app.include_router(targets.router, prefix="/api")
app.include_router(scans.router,   prefix="/api")
app.include_router(findings.router, prefix="/api")
app.include_router(dashboard.router, prefix="/api")

# Health check
@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "company": settings.COMPANY_NAME,
        "ai_enabled": bool(settings.ANTHROPIC_API_KEY),
        "tor_proxy": settings.tor_socks_url,
    }

# Serve frontend SPA
frontend_dir = os.path.join(os.path.dirname(__file__), "..", "frontend")
if os.path.isdir(frontend_dir):
    app.mount("/static", StaticFiles(directory=frontend_dir), name="static")

    @app.get("/", include_in_schema=False)
    @app.get("/{full_path:path}", include_in_schema=False)
    def serve_spa(full_path: str = ""):
        index = os.path.join(frontend_dir, "index.html")
        if os.path.exists(index):
            return FileResponse(index)
        return {"error": "Frontend not found"}
