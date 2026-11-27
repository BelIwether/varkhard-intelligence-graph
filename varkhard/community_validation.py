"""Repository-owned checks of inert, synthetic observation records."""

import json
from typing import Any, Literal

from .knowledge_store import KnowledgeError, _canonical_json, _digest

FixtureScenario = Literal["positive", "negative", "inconclusive"]
Result = Literal["pattern_observed", "pattern_not_observed", "inconclusive"]

# Dispatch is pinned to the advisory's observed pattern and suite identifier. A
# revision must add a new entry or retain the existing version's result wording.
SUITE_ID = "synthetic-suspicious-chain-v1"
SUITE_VERSION = 1
_PATTERN = ("suspicious_chain", 1, SUITE_ID)
_EVENT_KINDS = ("restricted_read", "handoff", "external_transfer")
_OBSERVATION_WINDOW_SECONDS = 600

_SUMMARIES = {
    ("synthetic-suspicious-chain-v1", 1): {
        "pattern_observed": "The rule found the advisory pattern in the selected synthetic observations.",
        "pattern_not_observed": "The rule did not find the advisory pattern in the selected synthetic observations.",
        "inconclusive": "The selected synthetic observations do not cover the full observation window.",
    },
}


def fixture_payload(scenario: FixtureScenario, fixture_id: str) -> str:
    complete = scenario != "inconclusive"
    offset = int(_digest(fixture_id)[:2], 16)
    observations = [
        {"kind": "restricted_read", "second": offset + 12, "linked_to_previous": False},
        {"kind": "handoff", "second": offset + 83, "linked_to_previous": True},
    ]
    if complete:
        observations.append({
            "kind": "external_transfer", "second": offset + 157, "linked_to_previous": scenario == "positive",
        })
    return _canonical_json({
        "schema_version": 1,
        "fixture_id": fixture_id,
        "evidence_classification": "synthetic",
        "scenario": scenario,
        "complete": complete,
        "observations": observations,
    })


def suite_for(advisory: dict[str, Any]) -> tuple[str, int]:
    if (advisory["pattern_id"], advisory["pattern_version"], advisory["validation_suite_id"]) != _PATTERN:
        raise KnowledgeError(422, "No repository-owned validation suite supports this advisory.")
    return SUITE_ID, SUITE_VERSION


def verify_fixture(scenario: FixtureScenario, fixture_id: str, payload: str, digest: str) -> dict[str, Any]:
    if payload != fixture_payload(scenario, fixture_id) or _digest(payload) != digest:
        raise KnowledgeError(422, "The recipient fixture could not be verified.")
    return json.loads(payload)


def run_suite(fixture: dict[str, Any]) -> Result:
    # The closed fixture format contains recorded categories, relative times and
    # links. It contains no executable input, targets, or live operations.
    if not fixture["complete"]:
        return "inconclusive"
    observations = fixture["observations"]
    first, middle, last = (event["second"] for event in observations)
    matched = (
        tuple(event["kind"] for event in observations) == _EVENT_KINDS
        and all(event["linked_to_previous"] for event in observations[1:])
        and first < middle < last
        and last - first <= _OBSERVATION_WINDOW_SECONDS
    )
    return "pattern_observed" if matched else "pattern_not_observed"


def result_summary(suite_id: str, suite_version: int, result: str) -> dict[str, Any]:
    summaries = _SUMMARIES.get((suite_id, suite_version), {})
    if result not in summaries:
        raise KnowledgeError(503, "The recorded validation summary could not be verified.")
    return {
        "suite_id": suite_id,
        "suite_version": suite_version,
        "result": result,
        "protection_effectiveness": "unmeasured",
        "limitations": [
            summaries[result],
            "Root cause remains undetermined.",
            "Real-world protection remains unmeasured.",
        ],
    }
