"""Domain records for the agent security graph."""

from dataclasses import dataclass
from typing import Literal, get_args

Action = Literal["read", "write", "delete", "handoff", "export"]
Classification = Literal["public", "internal", "restricted"]
Boundary = Literal["internal", "external"]
PermissionKind = Literal["grant", "baseline"]
Outcome = Literal["success", "denied"]

# The last whole Unix second representable by Python's datetime.
MAX_TIMESTAMP = 253_402_300_799


def _require_text(*values: str) -> None:
    if any(not isinstance(value, str) or not value.strip() for value in values):
        raise ValueError("IDs and names must be non-empty strings.")


@dataclass(frozen=True)
class Agent:
    id: str
    name: str

    def __post_init__(self) -> None:
        _require_text(self.id, self.name)


@dataclass(frozen=True)
class Resource:
    id: str
    name: str
    classification: Classification
    boundary: Boundary

    def __post_init__(self) -> None:
        _require_text(self.id, self.name)
        if self.classification not in get_args(Classification):
            raise ValueError("Unknown resource classification.")
        if self.boundary not in get_args(Boundary):
            raise ValueError("Unknown resource boundary.")


@dataclass(frozen=True)
class Permission:
    id: str
    agent_id: str
    resource_id: str
    action: Action
    kind: PermissionKind

    def __post_init__(self) -> None:
        _require_text(self.id, self.agent_id, self.resource_id)
        if self.action not in get_args(Action):
            raise ValueError("Unknown permission action.")
        if self.kind not in get_args(PermissionKind):
            raise ValueError("Unknown permission kind.")


@dataclass(frozen=True)
class Interaction:
    id: str
    agent_id: str
    resource_id: str
    action: Action
    outcome: Outcome
    occurred_at: int
    parent_id: str | None = None
    recipient_id: str | None = None

    def __post_init__(self) -> None:
        _require_text(self.id, self.agent_id, self.resource_id)
        if self.action not in get_args(Action):
            raise ValueError("Unknown interaction action.")
        if self.outcome not in get_args(Outcome):
            raise ValueError("Unknown interaction outcome.")
        if type(self.occurred_at) is not int or not 0 <= self.occurred_at <= MAX_TIMESTAMP:
            raise ValueError("Interaction time must be a whole Unix second in the supported range.")
        if self.parent_id is not None:
            _require_text(self.parent_id)
            if self.parent_id == self.id:
                raise ValueError("An interaction cannot be its own parent.")
        if (self.action == "handoff") != (self.recipient_id is not None):
            raise ValueError("A recipient is required exactly for handoff interactions.")
        if self.recipient_id is not None:
            _require_text(self.recipient_id)
