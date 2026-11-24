"""FastAPI entry point for the local dashboard and authenticated Knowledge API."""

import logging
import os
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import TypeVar

import relate
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .dashboard import DashboardFinding, DashboardGraph, read_agents, read_graph, read_resources
from .knowledge_api import create_knowledge_app
from .knowledge_evidence import DEMO_DIGEST, EvidenceCatalog
from .models import Agent, Resource
from .store import GraphStore, GraphStoreError, UnsupportedSnapshotError

_REPOSITORY = Path(__file__).resolve().parent.parent
DEFAULT_DASHBOARD_DB = _REPOSITORY / "examples" / "synthetic-demo.rl"
DEFAULT_FRONTEND_DIR = _REPOSITORY / "frontend" / "dist"
_LOG = logging.getLogger(__name__)
_Result = TypeVar("_Result")


def create_app(
    db_path: str | Path | None = None,
    *,
    frontend_dir: Path = DEFAULT_FRONTEND_DIR,
    knowledge_db: Path | None = None,
    knowledge_identities: Path | None = None,
    knowledge_evidence: EvidenceCatalog | None = None,
) -> FastAPI:
    """Create an app targeting a Relate file opened separately by each request."""
    if db_path is None:
        db_path = os.environ.get("VARKHARD_DB_PATH") or DEFAULT_DASHBOARD_DB
    path = Path(db_path).expanduser().absolute()
    app = FastAPI(title="VARKHARD Security Dashboard", version="0.1.0")
    if knowledge_db is None and (configured_db := os.environ.get("VARKHARD_KNOWLEDGE_DB")):
        knowledge_db = Path(configured_db)
    if knowledge_identities is None and (configured_identities := os.environ.get("VARKHARD_LOCAL_IDENTITIES")):
        knowledge_identities = Path(configured_identities)
    app.mount("/api/knowledge", create_knowledge_app(
        knowledge_db, knowledge_identities, knowledge_evidence or EvidenceCatalog(DEFAULT_DASHBOARD_DB, DEMO_DIGEST),
    ))

    @app.middleware("http")
    async def prevent_api_caching(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        response = await call_next(request)
        if request.url.path == "/api" or request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    def read(operation: Callable[[GraphStore], _Result]) -> _Result:
        try:
            # Sync routes run in a worker. Keep connection open, use and close
            # inside this call so none of those operations can move to another thread.
            with GraphStore(path, read_only=True) as store:
                return operation(store)
        except (GraphStoreError, relate.Error, OSError, ValueError) as error:
            _LOG.warning("Could not read dashboard graph: %s", error)
            if isinstance(error, UnsupportedSnapshotError):
                detail = "The configured file is not a supported VARKHARD Relate snapshot."
            elif isinstance(error, GraphStoreError) and " is locked." in str(error):
                detail = "The Relate file is locked. Close the writer and try again."
            else:
                detail = "The Relate graph is unavailable. Check the configured Single File."
            raise HTTPException(status_code=503, detail=detail) from error

    @app.get("/api/graph")
    def graph() -> DashboardGraph:
        """Read the graph and its findings from one read-only connection."""
        return read(lambda store: read_graph(
            store, store.path.name, synthetic_demo=store.path == DEFAULT_DASHBOARD_DB,
        ))

    @app.get("/api/agents")
    def agents() -> list[Agent]:
        return read(read_agents)

    @app.get("/api/resources")
    def resources() -> list[Resource]:
        return read(read_resources)

    @app.get("/api/findings")
    def findings() -> list[DashboardFinding]:
        return graph().findings

    index = frontend_dir / "index.html"
    if index.is_file():
        @app.get("/", include_in_schema=False)
        def dashboard() -> FileResponse:
            return FileResponse(index)

    shield = frontend_dir / "varkhard-shield.svg"
    if shield.is_file():
        @app.get("/varkhard-shield.svg", include_in_schema=False)
        def dashboard_shield() -> FileResponse:
            return FileResponse(shield, media_type="image/svg+xml")

    assets = frontend_dir / "assets"
    if assets.is_dir():
        app.mount("/assets", StaticFiles(directory=assets), name="dashboard-assets")

    return app


app = create_app()
