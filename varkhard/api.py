"""Read-only FastAPI interface for the VARKHARD dashboard."""

import logging
import os
from collections.abc import Callable
from pathlib import Path
from typing import TypeVar

import relate
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .dashboard import DashboardFinding, DashboardGraph, read_agents, read_graph, read_resources
from .models import Agent, Resource
from .store import GraphStore, GraphStoreError

_REPOSITORY = Path(__file__).resolve().parent.parent
DEFAULT_DASHBOARD_DB = _REPOSITORY / "examples" / "synthetic-demo.rl"
DEFAULT_FRONTEND_DIR = _REPOSITORY / "frontend" / "dist"
_LOG = logging.getLogger(__name__)
_Result = TypeVar("_Result")


def create_app(
    db_path: str | Path | None = None,
    *,
    frontend_dir: Path = DEFAULT_FRONTEND_DIR,
) -> FastAPI:
    """Create an app targeting a Relate file opened separately by each request."""
    if db_path is None:
        db_path = os.environ.get("VARKHARD_DB_PATH") or DEFAULT_DASHBOARD_DB
    path = Path(db_path).expanduser().absolute()
    app = FastAPI(title="VARKHARD Security Dashboard", version="0.1.0")

    def read(operation: Callable[[GraphStore], _Result]) -> _Result:
        try:
            # Sync routes run in a worker. Keep connection open, use and close
            # inside this call so none of those operations can move to another thread.
            with GraphStore(path, read_only=True) as store:
                return operation(store)
        except (GraphStoreError, relate.Error, OSError, ValueError) as error:
            _LOG.warning("Could not read dashboard graph: %s", error)
            if isinstance(error, GraphStoreError) and " is locked." in str(error):
                detail = "The Relate file is locked. Close the writer and try again."
            else:
                detail = "The Relate graph is unavailable. Check the configured Single File."
            raise HTTPException(status_code=503, detail=detail) from error

    @app.get("/api/graph")
    def graph() -> DashboardGraph:
        """Read the graph and its findings from one read-only connection."""
        return read(lambda store: read_graph(store, path.name))

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

    assets = frontend_dir / "assets"
    if assets.is_dir():
        app.mount("/assets", StaticFiles(directory=assets), name="dashboard-assets")

    return app


app = create_app()
