"""Opt-in Chromium test of the local two-tenant Community exchange."""

import argparse
import json
import secrets
from dataclasses import dataclass

from playwright.sync_api import Browser, Page, expect, sync_playwright

from dashboard_smoke import check_no_store, exact_button, watch_errors
from knowledge_smoke import (
    PREFIX,
    REPOSITORY,
    Identity,
    advisory_preview,
    check_token_not_persisted,
    check_viewport_width,
    click_mutation,
    connect,
    isolated_app,
    knowledge_response,
    open_knowledge,
    open_preview,
)

COMMUNITY = f"{PREFIX}/community"


@dataclass(frozen=True)
class PublisherIdentity(Identity):
    recipient: str

    def config_record(self) -> dict[str, str | list[str]]:
        return {**super().config_record(), "community_recipients": [self.recipient]}


def connect_community(page: Page, base_url: str, identity: Identity) -> None:
    page.goto(f"{base_url}/")
    page.get_by_role("navigation", name="Primary navigation").get_by_role(
        "link", name="Community", exact=True,
    ).click()
    expect(page.get_by_role("heading", name="Community", exact=True)).to_be_visible()
    token = page.get_by_label("Community access token", exact=True)
    expect(token).to_have_attribute("type", "password")
    token.fill(identity.token)
    with page.expect_response(lambda response: knowledge_response(response, "GET", f"{PREFIX}/session")) as pending:
        exact_button(page, "Connect").click()
    session = pending.value
    assert session.ok and session.json()["tenant_id"] == identity.tenant_id
    assert session.request.header_value("authorization") == identity.headers()["Authorization"]
    check_no_store(session)
    expect(exact_button(page, "Disconnect")).to_be_visible()
    check_token_not_persisted(page, identity)


def prepare_approved_advisory(
    author_page: Page, review_page: Page, base_url: str, author: Identity, reviewer: Identity,
) -> tuple[dict, dict]:
    open_knowledge(author_page, base_url)
    connect(author_page, author)
    candidates = author_page.get_by_role("region", name="Candidates", exact=True)
    candidate = candidates.get_by_role("article").filter(has_text="Suspicious Chain")
    incident = click_mutation(author_page, candidate, "Create incident", f"{PREFIX}/incidents", 201)
    incidents = author_page.get_by_role("region", name="Incidents", exact=True)
    draft = click_mutation(author_page, incidents, "Create draft advisory", f"{PREFIX}/advisories", 201)
    version_url = f"{PREFIX}/advisories/{draft['id']}/versions/{draft['version']}"
    click_mutation(author_page, advisory_preview(author_page), "Submit for review", f"{version_url}/submit", 200)

    # Candidate evidence availability is independent of review of stored versions.
    review_page.route(
        f"**{PREFIX}/candidates",
        lambda route: route.fulfill(status=503, json={"detail": "Candidates are unavailable."}),
    )
    open_knowledge(review_page, base_url)
    connect(review_page, reviewer)
    expect(review_page.get_by_text("Finding candidates are temporarily unavailable.", exact=True)).to_be_visible()
    open_preview(review_page)
    approved = click_mutation(review_page, advisory_preview(review_page), "Approve", f"{version_url}/approve", 200)
    expect(advisory_preview(review_page)).to_contain_text("Approved")
    assert approved["advisory"] == draft["advisory"]
    assert approved["audit"][-1]["actor_id"] == reviewer.actor_id
    return incident, approved


def refresh(page: Page, box: str) -> list[dict]:
    with page.expect_response(lambda response: knowledge_response(response, "GET", f"{COMMUNITY}/{box}")) as pending:
        exact_button(page, "Refresh Community").click()
    response = pending.value
    assert response.ok, response.status
    check_no_store(response)
    return response.json()


def check_workflow(browser: Browser, base_url: str, identities: tuple[Identity, ...]) -> None:
    author, reviewer, publisher, validator = identities
    author_page = browser.new_page(reduced_motion="reduce")
    reviewer_page = browser.new_page(reduced_motion="reduce")
    publisher_page = browser.new_page(viewport={"width": 1440, "height": 1100}, reduced_motion="reduce")
    validator_page = browser.new_page(
        viewport={"width": 390, "height": 844}, is_mobile=True, has_touch=True, reduced_motion="reduce",
    )
    errors = [watch_errors(page) for page in (author_page, publisher_page, validator_page)]
    validation_requests = []
    validator_page.on("request", lambda request: validation_requests.append(request)
                      if request.method == "POST" and request.url.endswith("/validate") else None)

    incident, approved = prepare_approved_advisory(author_page, reviewer_page, base_url, author, reviewer)
    connect_community(publisher_page, base_url, publisher)
    connect_community(validator_page, base_url, validator)
    inbox = validator_page.get_by_role("region", name="Community Inbox", exact=True)
    outbox = publisher_page.get_by_role("region", name="Delivery status", exact=True)
    publish = publisher_page.get_by_role("region", name="Publish advisory", exact=True)
    expect(inbox).to_contain_text("No advisories received.")
    expect(outbox).to_contain_text("No deliveries sent.")
    expect(validator_page.get_by_role("region", name="Publish advisory", exact=True)).to_have_count(0)
    expect(publisher_page.get_by_role("region", name="Community Inbox", exact=True)).to_have_count(0)

    publish.get_by_role("combobox", name="Approved advisory", exact=True).select_option(f"{approved['id']}:{approved['version']}")
    expect(publish).to_contain_text(approved["advisory"]["digest"])
    publish.get_by_role("combobox", name="Recipient tenant", exact=True).select_option(validator.tenant_id)
    sent = click_mutation(publisher_page, publish, "Send advisory", f"{COMMUNITY}/outbox", 201)
    assert sent["digest"] == approved["advisory"]["digest"]
    assert sent["recipient_tenant"] == validator.tenant_id
    expect(outbox).to_contain_text("Awaiting verification")

    received, = refresh(validator_page, "inbox")
    assert received["id"] == sent["id"] and received.get("advisory") is None
    assert received["validations"] == received["feedback"] == []
    expect(inbox).to_contain_text("Awaiting verification")
    envelope = inbox.get_by_label("Verified advisory envelope", exact=True)
    expect(envelope).to_have_count(0)
    expect(exact_button(inbox, "Run validation")).to_have_count(0)
    assert validation_requests == []

    delivery_path = f"{COMMUNITY}/inbox/{sent['id']}"
    verified = click_mutation(validator_page, inbox, "Verify advisory", f"{delivery_path}/verify", 200)
    expect(envelope).to_be_visible()
    assert json.loads(envelope.inner_text()) == approved["advisory"] == verified["advisory"]
    assert incident["id"] not in json.dumps(verified)
    expect(inbox).to_contain_text("No validations recorded.")
    assert validation_requests == []

    fixtures = validator_page.get_by_role("region", name="Synthetic fixtures", exact=True)
    fixture = click_mutation(validator_page, fixtures, "Create synthetic fixture", f"{COMMUNITY}/fixtures", 201)
    expect(fixtures).to_contain_text(fixture["id"])
    inbox.get_by_role("combobox", name="Validation fixture", exact=True).select_option(fixture["id"])
    validated = click_mutation(validator_page, inbox, "Run validation", f"{delivery_path}/validate", 200)
    result, = validated["validations"]
    assert result["fixture_id"] == fixture["id"] and result["fixture_digest"] == fixture["digest"]
    assert result["result"] == "pattern_observed"
    assert result["protection_effectiveness"] == "unmeasured"
    assert len(validation_requests) == 1

    results = inbox.get_by_role("region", name="Validation results", exact=True)
    expect(results).to_contain_text("Pattern observed")
    expect(results).to_contain_text("Unmeasured")
    expect(results).to_contain_text(result["suite_id"])
    expect(results).to_contain_text(fixture["digest"])
    outgoing, = refresh(publisher_page, "outbox")
    assert outgoing["validations"] == outgoing["feedback"] == []

    click_mutation(validator_page, results, "Share feedback", f"{delivery_path}/feedback", 200)
    expect(results).to_contain_text("Feedback shared")
    outgoing, = refresh(publisher_page, "outbox")
    history = outbox.get_by_role("region", name="Feedback history", exact=True)
    expect(history).to_contain_text("Pattern observed")
    feedback, = outgoing["feedback"]
    assert feedback["suite_version"] == result["suite_version"] and feedback["limitations"] == result["limitations"]
    assert outgoing["validations"] == []
    assert all(secret not in json.dumps(outgoing) for secret in (fixture["id"], fixture["digest"], incident["id"]))
    check_viewport_width(validator_page, 390)

    click_mutation(publisher_page, outbox, "Withdraw delivery", f"{COMMUNITY}/outbox/{sent['id']}/withdraw", 200)
    withdrawn, = refresh(validator_page, "inbox")
    assert withdrawn["status"] == "withdrawn" and withdrawn.get("advisory") is None
    expect(inbox).to_contain_text("Withdrawn")
    expect(envelope).to_have_count(0)
    expect(exact_button(inbox, "Run validation")).to_have_count(0)

    for page in (publisher_page, validator_page):
        exact_button(page, "Disconnect").click()
        expect(page.get_by_label("Community access token", exact=True)).to_have_value("")
        check_token_not_persisted(page, *identities)
    assert not any(errors), errors


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--browser-executable", help="optional path to an existing Chromium executable")
    args = parser.parse_args()
    if not (REPOSITORY / "frontend" / "dist" / "index.html").is_file():
        parser.error("Build the frontend with npm run build --prefix frontend before running the smoke test.")
    identities = (
        Identity("community-author", "tenant-a", "analyst", secrets.token_urlsafe(32)),
        Identity("community-reviewer", "tenant-a", "reviewer", secrets.token_urlsafe(32)),
        PublisherIdentity("community-publisher", "tenant-a", "publisher", secrets.token_urlsafe(32), "tenant-b"),
        Identity("community-validator", "tenant-b", "validator", secrets.token_urlsafe(32)),
    )
    with isolated_app(identities) as base_url, sync_playwright() as playwright:
        browser = playwright.chromium.launch(executable_path=args.browser_executable)
        check_workflow(browser, base_url, identities)
        browser.close()
    print("Community browser smoke passed. Verified two tenants, independent review, explicit validation and feedback, and withdrawal.")


if __name__ == "__main__":
    main()
