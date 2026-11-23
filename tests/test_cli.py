import json
import subprocess
import sys
from pathlib import Path


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
