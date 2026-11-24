"""Resolve an incident from the server-pinned synthetic Relate snapshot."""

import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory

import relate

from .dashboard import DashboardFinding, read_graph
from .store import GraphStore, GraphStoreError

SNAPSHOT_ID = "synthetic-demo-v1"
DEMO_DIGEST = "2e8d889eec811658872660f90fef234e1ab2bef90da188c387540ab3b6a7620c"
RULE_ID = "suspicious_chain"
RULE_VERSION = 1
_MAX_SNAPSHOT_BYTES = 1024 * 1024


class EvidenceUnavailable(RuntimeError):
    """The pinned evidence source could not be verified or read."""


class EvidenceCatalog:
    """Expose only complete findings of the supported rule from one pinned snapshot."""

    def __init__(self, path: Path, digest: str) -> None:
        self.path = path
        self.digest = digest

    def _findings(self) -> list[DashboardFinding]:
        try:
            with self.path.open("rb") as source:
                data = source.read(_MAX_SNAPSHOT_BYTES + 1)
            if len(data) > _MAX_SNAPSHOT_BYTES or hashlib.sha256(data).hexdigest() != self.digest:
                raise EvidenceUnavailable("The verified evidence snapshot is unavailable.")
            # Validate precisely the bytes that were hashed, even if the source path changes.
            with TemporaryDirectory(prefix="varkhard-evidence-") as directory:
                local = Path(directory) / "snapshot.rl"
                local.write_bytes(data)
                with GraphStore(local, read_only=True) as store:
                    graph = read_graph(store, local.name)
        except (GraphStoreError, relate.Error, OSError, ValueError) as error:
            raise EvidenceUnavailable("The verified evidence snapshot is unavailable.") from error

        if graph.evidence_quality.status != "complete":
            return []
        nodes = {node.id for node in graph.nodes}
        edges = {edge.id: edge for edge in graph.edges}
        supported = []
        for finding in graph.findings:
            if finding.rule_id != RULE_ID or not finding.investigation.complete:
                continue
            trace = finding.investigation
            trace_nodes = set(trace.node_ids)
            if not trace_nodes <= nodes or not set(trace.edge_ids) <= edges.keys():
                continue
            if any(not {edges[key].source, edges[key].target} <= trace_nodes for key in trace.edge_ids):
                continue
            supported.append(finding)
        return supported

    def _provenance(self, finding: DashboardFinding) -> dict:
        return {
            "snapshot_id": SNAPSHOT_ID,
            "snapshot_digest": self.digest,
            "finding_id": finding.id,
            "rule_id": RULE_ID,
            "rule_version": RULE_VERSION,
            "evidence_complete": True,
        }

    def candidates(self) -> list[dict]:
        return [self._provenance(finding) for finding in self._findings()]

    def resolve(self, snapshot_id: str, finding_id: str) -> dict | None:
        if snapshot_id != SNAPSHOT_ID:
            return None
        for finding in self._findings():
            if finding.id != finding_id:
                continue
            trace = finding.investigation
            return {
                **self._provenance(finding),
                "evidence_node_ids": trace.node_ids,
                "evidence_edge_ids": trace.edge_ids,
                "observed_behavior": [{"action": step.action, "outcome": step.outcome} for step in trace.steps],
                "root_cause_status": "not_established",
            }
        return None
