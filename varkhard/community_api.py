"""Community routes inside the authenticated local Knowledge application."""

from collections.abc import Callable, Iterable
from typing import Annotated, Protocol

from fastapi import APIRouter, Depends, HTTPException, Path, Request, Response
from pydantic import BaseModel, ConfigDict, Field

from .community_store import CommunityStore
from .community_validation import FixtureScenario
from .knowledge_store import KnowledgeStore

_Tenant = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")]
_ID = Annotated[str, Field(min_length=1, max_length=256)]
_PathID = Annotated[str, Path(min_length=1, max_length=256)]
_Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class CommunityIdentity(Protocol):
    tenant_id: str
    actor_id: str
    role: str
    community_recipients: list[str]


class _Send(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")

    recipient_tenant: _Tenant
    knowledge_id: _ID
    version: Annotated[int, Field(ge=1, le=2_147_483_647)]
    digest: _Digest
    ttl_hours: Annotated[int, Field(ge=1, le=168)] = 24


class _Fixture(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")

    scenario: FixtureScenario


class _Validate(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")

    fixture_id: _ID


class _Feedback(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")

    validation_id: _ID


def create_community_router(
    knowledge: KnowledgeStore, identities: Iterable[CommunityIdentity],
    authenticate: Callable[[Request], CommunityIdentity],
) -> APIRouter:
    audiences = {
        (identity.tenant_id, identity.actor_id): frozenset(identity.community_recipients)
        for identity in identities if identity.role == "publisher"
    }
    store = CommunityStore(knowledge, audiences)
    router = APIRouter(prefix="/community")
    Actor = Annotated[CommunityIdentity, Depends(authenticate)]

    def publisher(actor: Actor) -> CommunityIdentity:
        if actor.role != "publisher":
            raise HTTPException(403, "Publisher permission required.")
        return actor

    def validator(actor: Actor) -> CommunityIdentity:
        if actor.role != "validator":
            raise HTTPException(403, "Validator permission required.")
        return actor

    Publisher = Annotated[CommunityIdentity, Depends(publisher)]
    Validator = Annotated[CommunityIdentity, Depends(validator)]

    @router.get("/peers")
    def peers(actor: Publisher):
        return store.peers(actor.tenant_id, actor.actor_id)

    @router.get("/approved")
    def approved(actor: Publisher):
        return store.approved(actor.tenant_id)

    @router.get("/outbox")
    def outbox(actor: Publisher):
        return store.deliveries(actor.tenant_id, inbox=False)

    @router.post("/outbox", status_code=201)
    def send(data: _Send, actor: Publisher, response: Response):
        delivery, created = store.publish(
            actor.tenant_id, actor.actor_id, data.recipient_tenant, data.knowledge_id,
            data.version, data.digest, data.ttl_hours,
        )
        if not created:
            response.status_code = 200
        return delivery

    @router.post("/outbox/{delivery_id}/withdraw")
    def withdraw(delivery_id: _PathID, actor: Publisher):
        return store.withdraw(actor.tenant_id, actor.actor_id, delivery_id)

    @router.get("/inbox")
    def inbox(actor: Validator):
        return store.deliveries(actor.tenant_id, inbox=True)

    @router.post("/inbox/{delivery_id}/verify")
    def verify(delivery_id: _PathID, actor: Validator):
        return store.inbox_action(actor.tenant_id, actor.actor_id, delivery_id, "verify")

    @router.get("/fixtures")
    def fixtures(actor: Validator):
        return store.fixtures(actor.tenant_id)

    @router.post("/fixtures", status_code=201)
    def create_fixture(data: _Fixture, actor: Validator, response: Response):
        fixture, created = store.create_fixture(actor.tenant_id, actor.actor_id, data.scenario)
        if not created:
            response.status_code = 200
        return fixture

    @router.post("/inbox/{delivery_id}/validate")
    def validate(delivery_id: _PathID, data: _Validate, actor: Validator):
        return store.inbox_action(actor.tenant_id, actor.actor_id, delivery_id, "validate", data.fixture_id)

    @router.post("/inbox/{delivery_id}/feedback")
    def feedback(delivery_id: _PathID, data: _Feedback, actor: Validator):
        return store.inbox_action(actor.tenant_id, actor.actor_id, delivery_id, "feedback", data.validation_id)

    return router
