from hashlib import sha256
from pathlib import Path

import pytest

from varkhard.demo import seed_demo
from varkhard.knowledge_evidence import DEMO_DIGEST, SNAPSHOT_ID, EvidenceCatalog, EvidenceUnavailable
from varkhard.store import GraphStore

_DEMO = Path(__file__).resolve().parents[1] / "examples" / "synthetic-demo.rl"


def test_catalog_resolves_only_a_known_finding_from_the_pinned_snapshot(tmp_path):
    source = tmp_path / "snapshot.rl"
    source.write_bytes(_DEMO.read_bytes())
    catalog = EvidenceCatalog(source, DEMO_DIGEST)
    candidate, = catalog.candidates()
    evidence = catalog.resolve(SNAPSHOT_ID, candidate["finding_id"])

    assert evidence is not None
    assert evidence["snapshot_digest"] == sha256(source.read_bytes()).hexdigest()
    assert evidence["root_cause_status"] == "not_established"
    assert [item["action"] for item in evidence["observed_behavior"]] == ["read", "handoff", "export"]
    assert catalog.resolve("unknown-snapshot", candidate["finding_id"]) is None
    assert catalog.resolve(SNAPSHOT_ID, "caller-evidence") is None

    with source.open("ab") as changed:
        changed.write(b"different snapshot")
    with pytest.raises(EvidenceUnavailable, match="verified evidence snapshot"):
        catalog.resolve(SNAPSHOT_ID, candidate["finding_id"])


def test_partial_evidence_is_ineligible_even_when_file_digest_matches(tmp_path):
    source = tmp_path / "partial.rl"
    with GraphStore(source) as store:
        seed_demo(store)
        store.query(
            "MATCH (:Interaction {id: 'interaction-ledger-handoff'})-[edge:HANDED_TO]->(:AIAgent) DELETE edge",
        )

    catalog = EvidenceCatalog(source, sha256(source.read_bytes()).hexdigest())
    assert catalog.candidates() == []
