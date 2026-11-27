"""Opt-in Chromium smoke test against an isolated local Knowledge workspace."""

import argparse
import hashlib
import json
import os
import secrets
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.request import urlopen

from playwright.sync_api import Browser, Locator, Page, Response, expect, sync_playwright

from dashboard_smoke import check_no_store, exact_button, watch_errors


REPOSITORY = Path(__file__).resolve().parents[2]
PREFIX = "/api/knowledge"


@dataclass(frozen=True)
class Identity:
    actor_id: str
    tenant_id: str
    role: str
    token: str = field(repr=False)

    def config_record(self) -> dict[str, str]:
        return {
            "actor_id": self.actor_id,
            "tenant_id": self.tenant_id,
            "role": self.role,
            "token_sha256": hashlib.sha256(self.token.encode()).hexdigest(),
        }

    def headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"}


def free_loopback_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def wait_for_app(process: subprocess.Popen, base_url: str) -> None:
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"Isolated Uvicorn exited with status {process.returncode}")
        try:
            with urlopen(f"{base_url}/api/graph", timeout=0.5) as response:
                if response.status == 200:
                    return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError("Isolated Uvicorn did not serve the demo graph")


@contextmanager
def isolated_app(identities: tuple[Identity, ...]) -> Iterator[str]:
    with TemporaryDirectory(prefix="varkhard-knowledge-smoke-") as directory:
        artifact_dir = Path(directory)
        config = artifact_dir / "identities.json"
        config.write_text(json.dumps([identity.config_record() for identity in identities]), encoding="utf-8")
        env = {
            **os.environ,
            "VARKHARD_DB_PATH": str(REPOSITORY / "examples" / "synthetic-demo.rl"),
            "VARKHARD_KNOWLEDGE_DB": str(artifact_dir / "knowledge.sqlite3"),
            "VARKHARD_LOCAL_IDENTITIES": str(config),
        }
        port = free_loopback_port()
        base_url = f"http://127.0.0.1:{port}"
        command = [
            sys.executable, "-m", "uvicorn", "varkhard.api:app",
            "--host", "127.0.0.1", "--port", str(port), "--log-level", "warning",
        ]
        process = subprocess.Popen(command, cwd=REPOSITORY, env=env)
        try:
            wait_for_app(process, base_url)
            yield base_url
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


def knowledge_response(response: Response, method: str, path: str) -> bool:
    return response.url.split("?", 1)[0].endswith(path) and response.request.method == method


def open_knowledge(page: Page, base_url: str) -> None:
    page.goto(f"{base_url}/")
    page.get_by_role("navigation", name="Primary navigation").get_by_role(
        "link", name="Knowledge", exact=True,
    ).click()
    expect(page.get_by_role("heading", name="Knowledge", exact=True)).to_be_visible()


def token_field(page: Page) -> Locator:
    return page.get_by_label("Knowledge access token", exact=True)


def check_token_not_persisted(page: Page, *identities: Identity) -> None:
    state = page.context.storage_state(indexed_db=True)
    session = page.evaluate("Object.entries(sessionStorage)")
    locations = json.dumps([state, session, page.url])
    for identity in identities:
        fingerprint = identity.config_record()["token_sha256"]
        assert not any(value in locations for value in (identity.token, fingerprint)), (
            "Knowledge credential persisted in browser storage or URL"
        )
    assert not state["cookies"], "The local authorization flow stored a browser cookie"


def connect(page: Page, identity: Identity) -> None:
    token = token_field(page)
    expect(token).to_have_attribute("type", "password")
    token.fill(identity.token)
    with page.expect_response(lambda response: knowledge_response(response, "GET", f"{PREFIX}/session")) as pending:
        exact_button(page, "Connect").click()
    response = pending.value
    assert response.status == 200, response.status
    check_no_store(response)
    assert response.request.header_value("authorization") == identity.headers()["Authorization"]
    assert identity.token not in response.url and identity.token not in response.text()
    session = response.json()
    for field_name in ("actor_id", "tenant_id", "role"):
        assert session[field_name] == getattr(identity, field_name), field_name
    expect(exact_button(page, "Disconnect")).to_be_visible()
    check_token_not_persisted(page, identity)


def click_mutation(page: Page, scope: Page | Locator, name: str, path: str, status: int) -> dict:
    with page.expect_response(lambda response: knowledge_response(response, "POST", path)) as pending:
        exact_button(scope, name).click()
    response = pending.value
    assert response.status == status, (path, response.status)
    check_no_store(response)
    return response.json()


def get_version(page: Page, base_url: str, identity: Identity, knowledge_id: str, version: int) -> dict:
    path = f"{PREFIX}/advisories/{knowledge_id}/versions/{version}"
    response = page.request.get(f"{base_url}{path}", headers=identity.headers())
    assert response.status == 200, (path, response.status)
    check_no_store(response)
    return response.json()


def advisory_preview(page: Page) -> Locator:
    return page.get_by_role("region", name="Advisory preview", exact=True)


def open_preview(page: Page) -> None:
    cards = page.get_by_role("region", name="Advisories", exact=True)
    exact_button(cards, "Preview advisory").click()
    expect(advisory_preview(page)).to_be_visible()


def refresh_knowledge(page: Page) -> None:
    with page.expect_response(lambda response: knowledge_response(response, "GET", f"{PREFIX}/advisories")) as pending:
        exact_button(page, "Refresh knowledge").click()
    assert pending.value.ok, pending.value.status
    check_no_store(pending.value)


def verify_history(record: dict, status: str, actions: list[tuple[str, Identity]]) -> None:
    assert record["status"] == status, record["status"]
    envelope = record["advisory"]
    version, digest = envelope["version"], envelope["digest"]
    audit = record["audit"]
    assert [(entry["action"], entry["actor_id"]) for entry in audit] == [
        (action, identity.actor_id) for action, identity in actions
    ]
    assert all(entry["version"] == version and entry["digest"] == digest for entry in audit)
    assert audit[-1]["to_status"] == status


def show_review(page: Page, status: str, envelope: dict, *actors: Identity) -> None:
    preview = advisory_preview(page)
    expect(preview.locator(":scope > header").get_by_text(status, exact=True)).to_be_visible()
    sanitized = preview.get_by_label("Sanitized advisory", exact=True)
    digest = envelope["digest"]
    expect(sanitized).to_contain_text(digest)
    assert json.loads(sanitized.inner_text()) == envelope
    canonical = {key: value for key, value in envelope.items() if key != "digest"}
    encoded = json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    assert hashlib.sha256(encoded).hexdigest() == digest
    assert envelope["evidence_classification"] == "synthetic"
    assert envelope["root_cause_status"] == "not_established"
    assert "incident_id" not in envelope and "finding_id" not in envelope and "author_id" not in envelope
    history = page.get_by_role("region", name="Audit history", exact=True)
    for actor in actors:
        expect(history).to_contain_text(actor.actor_id)


def check_viewport_width(page: Page, expected: int) -> None:
    widths = page.evaluate("() => [window.innerWidth, document.documentElement.scrollWidth]")
    assert widths == [expected, expected], (expected, widths)


def check_workflow(browser: Browser, base_url: str, analyst: Identity, reviewer: Identity) -> None:
    desktop = browser.new_page(viewport={"width": 1440, "height": 1100}, reduced_motion="reduce")
    desktop_errors = watch_errors(desktop)
    session_url = f"{base_url}{PREFIX}/session"
    private = desktop.request.get(session_url)
    assert private.status == 401, private.status
    check_no_store(private)

    open_knowledge(desktop, base_url)
    connect(desktop, analyst)
    candidates = desktop.get_by_role("region", name="Candidates", exact=True)
    candidate = candidates.get_by_role("article").filter(has_text="Suspicious Chain")
    expect(candidate).to_have_count(1)
    incident = click_mutation(desktop, candidate, "Create incident", f"{PREFIX}/incidents", 201)
    incidents = desktop.get_by_role("region", name="Incidents", exact=True)
    assert incident["registered_by"] == analyst.actor_id
    assert incident["snapshot_id"] == "synthetic-demo-v1"
    assert incident["rule_id"] == "suspicious_chain" and incident["evidence_complete"] is True
    draft = click_mutation(desktop, incidents, "Create draft advisory", f"{PREFIX}/advisories", 201)
    assert draft["incident_id"] == incident["id"]
    envelope = draft["advisory"]
    knowledge_id, digest = envelope["knowledge_id"], envelope["digest"]
    assert envelope["version"] == 1
    path = f"{PREFIX}/advisories/{knowledge_id}/versions"
    show_review(desktop, "Draft", envelope, analyst)

    click_mutation(desktop, advisory_preview(desktop), "Submit for review", f"{path}/1/submit", 200)
    show_review(desktop, "In review", envelope, analyst)
    expect(exact_button(desktop, "Approve")).to_have_count(0)
    expect(exact_button(desktop, "Reject")).to_have_count(0)
    denial = desktop.request.post(f"{base_url}{path}/1/approve", headers=analyst.headers(), data={"digest": digest})
    assert denial.status == 403, denial.status
    check_no_store(denial)
    verify_history(get_version(desktop, base_url, analyst, knowledge_id, 1), "in_review", [
        ("create", analyst), ("submit", analyst),
    ])
    refresh_knowledge(desktop)
    expect(desktop.get_by_role("region", name="Advisories", exact=True)).to_contain_text("In review")
    check_token_not_persisted(desktop, analyst, reviewer)
    desktop.reload()
    expect(token_field(desktop)).to_have_value("")
    expect(exact_button(desktop, "Disconnect")).to_have_count(0)
    print("Verified analyst registration, draft and submission, with approval denied and no retained credential.")

    mobile = browser.new_page(
        viewport={"width": 390, "height": 844}, is_mobile=True, has_touch=True, reduced_motion="reduce",
    )
    mobile_errors = watch_errors(mobile)
    open_knowledge(mobile, base_url)
    connect(mobile, reviewer)
    expect(exact_button(mobile, "Create incident")).to_have_count(0)
    expect(exact_button(mobile, "Create draft advisory")).to_have_count(0)
    open_preview(mobile)
    show_review(mobile, "In review", envelope, analyst)
    click_mutation(mobile, advisory_preview(mobile), "Approve", f"{path}/1/approve", 200)
    show_review(mobile, "Approved", envelope, analyst, reviewer)
    approved_history = [("create", analyst), ("submit", analyst), ("approve", reviewer)]
    approved = get_version(mobile, base_url, reviewer, knowledge_id, 1)
    verify_history(approved, "approved", approved_history)
    refresh_knowledge(mobile)
    expect(mobile.get_by_role("region", name="Advisories", exact=True)).to_contain_text("Approved")
    check_viewport_width(mobile, 390)
    check_token_not_persisted(mobile, analyst, reviewer)
    print("Verified reviewer approval, immutable digest, persisted audit, and mobile layout at 390×844.")

    connect(desktop, analyst)
    open_preview(desktop)
    show_review(desktop, "Approved", envelope, analyst, reviewer)
    next_version = click_mutation(desktop, advisory_preview(desktop), "New version", path, 201)
    assert next_version["incident_id"] == incident["id"]
    next_envelope = next_version["advisory"]
    assert next_envelope["knowledge_id"] == knowledge_id
    assert next_envelope["version"] == 2 and next_envelope["digest"] != digest
    show_review(desktop, "Draft", next_envelope, analyst)
    click_mutation(desktop, advisory_preview(desktop), "Submit for review", f"{path}/2/submit", 200)
    show_review(desktop, "In review", next_envelope, analyst)

    refresh_knowledge(mobile)
    open_preview(mobile)
    mobile.get_by_role("combobox", name="Advisory version").select_option("2")
    show_review(mobile, "In review", next_envelope, analyst)
    click_mutation(mobile, advisory_preview(mobile), "Reject", f"{path}/2/reject", 200)
    show_review(mobile, "Rejected", next_envelope, analyst, reviewer)
    verify_history(get_version(mobile, base_url, reviewer, knowledge_id, 2), "rejected", [
        ("new_version", analyst), ("submit", analyst), ("reject", reviewer),
    ])
    previous = get_version(mobile, base_url, reviewer, knowledge_id, 1)
    verify_history(previous, "approved", approved_history)
    assert previous["advisory"] == approved["advisory"] and previous["audit"] == approved["audit"]
    mobile.set_viewport_size({"width": 320, "height": 844})
    show_review(mobile, "Rejected", next_envelope, analyst, reviewer)
    check_viewport_width(mobile, 320)

    for page in (desktop, mobile):
        exact_button(page, "Disconnect").click()
        expect(token_field(page)).to_have_value("")
        expect(exact_button(page, "Preview advisory")).to_have_count(0)
        check_token_not_persisted(page, analyst, reviewer)
    assert not desktop_errors and not mobile_errors, desktop_errors + mobile_errors
    print("Verified version 2 rejection, unchanged approved version 1, 320×844 preview, and cleared previews on disconnect.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--browser-executable", help="optional path to an existing Chromium executable")
    args = parser.parse_args()
    if not (REPOSITORY / "frontend" / "dist" / "index.html").is_file():
        parser.error("Build the frontend with npm run build --prefix frontend before running the smoke test.")
    analyst = Identity("demo-analyst", "demo-knowledge", "analyst", secrets.token_urlsafe(32))
    reviewer = Identity("demo-reviewer", analyst.tenant_id, "reviewer", secrets.token_urlsafe(32))
    with isolated_app((analyst, reviewer)) as base_url, sync_playwright() as playwright:
        browser = playwright.chromium.launch(executable_path=args.browser_executable)
        check_workflow(browser, base_url, analyst, reviewer)
        browser.close()
    print("Knowledge browser smoke passed.")


if __name__ == "__main__":
    main()
