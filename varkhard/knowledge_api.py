"""Authenticated, tenant-scoped API for the private Knowledge Engine."""

import hashlib
import hmac
import logging
import re
import sqlite3
from pathlib import Path
from typing import Annotated, Literal

from fastapi import Depends, FastAPI, HTTPException, Path as RoutePath, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, TypeAdapter

from .community_api import create_community_router
from .knowledge_evidence import EvidenceCatalog, EvidenceUnavailable
from .knowledge_store import KnowledgeError, KnowledgeStore

_LOG = logging.getLogger(__name__)
_BEARER = re.compile(r"(?i:Bearer) ([A-Za-z0-9_-]{43,128})")
_ID = Annotated[str, Field(min_length=1, max_length=256)]
_ACTOR_ID = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")]
_DIGEST = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
_VERSION = Annotated[int, Field(ge=1, le=2_147_483_647)]
_ROUTE_VERSION = Annotated[int, RoutePath(ge=1, le=2_147_483_647)]
_ROUTE_ID = Annotated[str, RoutePath(min_length=1, max_length=256)]


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class _Identity(_StrictModel):
    actor_id: _ACTOR_ID
    tenant_id: _ACTOR_ID
    role: Literal["analyst", "reviewer", "publisher", "validator"]
    token_sha256: _DIGEST
    community_recipients: list[_ACTOR_ID] = Field(default_factory=list, max_length=64)


class _RegisterIncident(_StrictModel):
    snapshot_id: _ID
    finding_id: _ID


class _CreateAdvisory(_StrictModel):
    incident_id: _ID


class _DigestRequest(_StrictModel):
    digest: _DIGEST


class _NewVersion(_DigestRequest):
    version: _VERSION


def _load_identities(path: Path) -> list[tuple[bytes, _Identity]]:
    try:
        with path.open("rb") as registry:
            body = registry.read(65_537)
        if len(body) > 65_536:
            raise ValueError
        entries = TypeAdapter(list[_Identity]).validate_json(body)
        hashes = {entry.token_sha256 for entry in entries}
        publishers = [(entry.tenant_id, entry.actor_id) for entry in entries if entry.role == "publisher"]
        validators = {entry.tenant_id for entry in entries if entry.role == "validator"}
        if not entries or len(hashes) != len(entries) or len(set(publishers)) != len(publishers):
            raise ValueError
        for entry in entries:
            recipients = set(entry.community_recipients)
            if recipients and (
                entry.role != "publisher" or entry.tenant_id in recipients
                or len(recipients) != len(entry.community_recipients) or not recipients <= validators
            ):
                raise ValueError
    except (OSError, ValueError):
        raise RuntimeError("Could not load the local Knowledge identity registry.") from None
    return [(bytes.fromhex(entry.token_sha256), entry) for entry in entries]


def _authenticate(request: Request, identities: list[tuple[bytes, _Identity]]) -> _Identity | None:
    values = request.headers.getlist("authorization")
    bearer = _BEARER.fullmatch(values[0]) if len(values) == 1 else None
    if bearer is None:
        return None
    digest = hashlib.sha256(bearer[1].encode("ascii")).digest()
    actor = None
    for token_digest, identity in identities:
        if hmac.compare_digest(digest, token_digest):
            actor = identity
    return actor


def _authenticated_actor(request: Request) -> _Identity:
    return request.state.knowledge_actor


def _analyst(request: Request) -> _Identity:
    actor = _authenticated_actor(request)
    if actor.role != "analyst":
        raise HTTPException(403, "Analyst permission required.")
    return actor


def _knowledge_reader(request: Request) -> _Identity:
    actor = _authenticated_actor(request)
    if actor.role not in ("analyst", "reviewer"):
        raise HTTPException(403, "Analyst or reviewer permission required.")
    return actor


_Actor = Annotated[_Identity, Depends(_authenticated_actor)]
_Analyst = Annotated[_Identity, Depends(_analyst)]
_KnowledgeReader = Annotated[_Identity, Depends(_knowledge_reader)]


def create_knowledge_app(
    db_path: Path | None, identity_path: Path | None, evidence: EvidenceCatalog,
) -> FastAPI:
    """Mount a separate boundary with local identities and no public private routes."""
    app = FastAPI(openapi_url=None)
    if (db_path is None) != (identity_path is None):
        raise RuntimeError("Configure both the Knowledge database and local identity registry.")
    identities = _load_identities(identity_path.expanduser()) if identity_path is not None else []
    store = KnowledgeStore(db_path.expanduser()) if db_path is not None else None

    @app.middleware("http")
    async def require_identity(request: Request, call_next):
        actor = _authenticate(request, identities)
        if actor is None:
            return JSONResponse(
                {"detail": "A valid Knowledge bearer token is required."}, status_code=401,
                headers={"Cache-Control": "no-store", "WWW-Authenticate": "Bearer"},
            )
        request.state.knowledge_actor = actor
        try:
            response = await call_next(request)
        except (EvidenceUnavailable, sqlite3.Error) as error:
            _LOG.warning("Knowledge data unavailable (%s)", type(error).__name__)
            response = JSONResponse({"detail": "Knowledge data is temporarily unavailable."}, status_code=503)
        except Exception as error:
            _LOG.error("Knowledge request failed (%s)", type(error).__name__)
            response = JSONResponse({"detail": "The Knowledge request failed."}, status_code=500)
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.exception_handler(RequestValidationError)
    async def invalid_request(_request: Request, _error: RequestValidationError):
        return JSONResponse({"detail": "Invalid Knowledge request."}, status_code=422)

    @app.exception_handler(KnowledgeError)
    async def invalid_operation(_request: Request, error: KnowledgeError):
        return JSONResponse({"detail": error.message}, status_code=error.status_code)

    if store is None:
        return app

    app.include_router(create_community_router(store, tuple(entry for _, entry in identities), _authenticated_actor))

    @app.get("/session")
    def session(actor: _Actor):
        return {"actor_id": actor.actor_id, "tenant_id": actor.tenant_id, "role": actor.role}

    @app.get("/candidates")
    def candidates(_actor: _KnowledgeReader):
        return evidence.candidates()

    @app.get("/incidents")
    def incidents(actor: _KnowledgeReader):
        return store.list_incidents(actor.tenant_id)

    @app.post("/incidents", status_code=201)
    def register_incident(data: _RegisterIncident, actor: _Analyst):
        incident = evidence.resolve(data.snapshot_id, data.finding_id)
        if incident is None:
            raise HTTPException(404, "No eligible validated finding was found.")
        return store.register_incident(actor.tenant_id, actor.actor_id, incident)

    @app.get("/advisories")
    def advisories(actor: _KnowledgeReader):
        return store.list_advisories(actor.tenant_id)

    @app.post("/advisories", status_code=201)
    def create_advisory(data: _CreateAdvisory, actor: _Analyst):
        return store.create_advisory(actor.tenant_id, actor.actor_id, data.incident_id)

    @app.get("/advisories/{knowledge_id}/versions/{version}")
    def advisory(knowledge_id: _ROUTE_ID, version: _ROUTE_VERSION, actor: _KnowledgeReader):
        return store.get_advisory(actor.tenant_id, knowledge_id, version)

    @app.post("/advisories/{knowledge_id}/versions", status_code=201)
    def new_version(knowledge_id: _ROUTE_ID, data: _NewVersion, actor: _Analyst):
        return store.new_version(actor.tenant_id, actor.actor_id, knowledge_id, data.version, data.digest)

    @app.post("/advisories/{knowledge_id}/versions/{version}/{action}")
    def review(
        knowledge_id: _ROUTE_ID, version: _ROUTE_VERSION, action: Literal["submit", "approve", "reject"],
        data: _DigestRequest, actor: _Actor,
    ):
        role = "analyst" if action == "submit" else "reviewer"
        if actor.role != role:
            raise HTTPException(403, f"{role.capitalize()} permission required.")
        return store.transition(actor.tenant_id, actor.actor_id, knowledge_id, version, data.digest, action)

    return app
