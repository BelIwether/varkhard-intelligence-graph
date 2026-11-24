import json
import subprocess
import sys
from pathlib import Path

from varkhard.demo import seed_demo
from varkhard.store import GraphStore


ROOT = Path(__file__).resolve().parents[1]


def test_cli_seeds_then_reads_graph_in_separate_process(tmp_path):
    path = tmp_path / "graph.rl"
    command = [sys.executable, "-m", "varkhard", "--db", str(path)]
    missing = subprocess.run([*command, "analyze"], cwd=ROOT, capture_output=True, text=True, timeout=10)
    assert missing.returncode == 1
    assert missing.stderr.strip()
    assert not path.exists()

    subprocess.run([*command, "seed"], cwd=ROOT, check=True, capture_output=True, text=True, timeout=10)
    analysis = subprocess.run(
        [*command, "analyze"], cwd=ROOT, check=True, capture_output=True, text=True, timeout=10
    )
    findings = json.loads(analysis.stdout)
    assert {finding["rule_id"] for finding in findings} == {
        "unauthorized_access",
        "excessive_permission",
        "suspicious_chain",
    }
    assert all(finding["explanation"] and finding["evidence"] for finding in findings)

    snapshot = ROOT / "examples" / "synthetic-demo.rl"
    snapshot_before = snapshot.read_bytes()
    shipped = subprocess.run(
        [sys.executable, "-m", "varkhard", "--db", str(snapshot), "analyze"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert json.loads(shipped.stdout) == findings

    nodes = """
        MATCH (n)
        RETURN n.id AS node_id, labels(n) AS labels, properties(n) AS properties
        ORDER BY node_id
    """
    edges = """
        MATCH (source)-[edge]->(target)
        RETURN source.id AS source_id, type(edge) AS relation, target.id AS target_id,
               properties(edge) AS properties
        ORDER BY source_id, relation, target_id
    """
    with GraphStore(path, read_only=True) as generated, GraphStore(snapshot, read_only=True) as bundled:
        assert bundled.query(nodes) == generated.query(nodes)
        assert bundled.query(edges) == generated.query(edges)
    assert snapshot.read_bytes() == snapshot_before


def test_cli_reports_incomplete_evidence_separately_from_findings_json(tmp_path):
    path = tmp_path / "partial.rl"
    with GraphStore(path) as store:
        seed_demo(store)
        store.query("""
            MATCH (event:Interaction {id: 'interaction-catalog-write-denied'})
            SET event.outcome = 'unknown'
        """)

    analysis = subprocess.run(
        [sys.executable, "-m", "varkhard", "--db", str(path), "analyze"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert "incomplete evidence" in analysis.stderr.lower()
    assert {finding["rule_id"] for finding in json.loads(analysis.stdout)} == {"excessive_permission", "suspicious_chain"}
