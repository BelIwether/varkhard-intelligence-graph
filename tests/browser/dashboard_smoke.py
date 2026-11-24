"""Opt-in Chromium regression checks against a running VARKHARD demo."""

import argparse
import re
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

from playwright.sync_api import Browser, ConsoleMessage, Locator, Page, Response, Route, expect, sync_playwright


GRAPH_NAME = "Interactive intelligence graph"
DEMO_FINDINGS = {
    "unauthorized_access",
    "excessive_permission",
    "suspicious_chain",
}


def graph_response(response: Response) -> bool:
    return response.url.endswith("/api/graph") and response.ok


def exact_button(scope: Page | Locator, name: str) -> Locator:
    return scope.get_by_role("button", name=name, exact=True)


def inspector_heading(page: Page, name: str) -> Locator:
    return page.locator("#inspector").get_by_role("heading", name=name, exact=True)


def graph_ids(graph: Locator, selector: str) -> set[str]:
    return set(graph.locator(selector).evaluate_all("items => items.map(item => item.dataset.id)"))


def graph_state(graph: Locator) -> dict[str, float]:
    return graph.locator(".react-flow__viewport").evaluate("""element => {
        const matrix = new DOMMatrixReadOnly(getComputedStyle(element).transform);
        return { zoom: matrix.a, x: matrix.e };
    }""")


def check_graph_geometry(
    graph: Locator, node_ids: list[str], numbered_triggers: list[int], state: str,
) -> None:
    geometry = graph.evaluate(r"""async (graph, nodeIds) => {
        await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)));
        const frame = graph.getBoundingClientRect();
        const issues = [];
        const inside = box =>
            box.width > 0 && box.height > 0 &&
            box.left >= frame.left - 1 && box.right <= frame.right + 1 &&
            box.top >= frame.top - 1 && box.bottom <= frame.bottom + 1;
        const overlaps = (a, b) =>
            Math.min(a.right, b.right) > Math.max(a.left, b.left) + 0.5 &&
            Math.min(a.bottom, b.bottom) > Math.max(a.top, b.top) + 0.5;

        const cards = new Map();
        const obstacles = [];
        for (const node of graph.querySelectorAll('.react-flow__node')) {
            const id = node.dataset.id;
            const card = node.querySelector('.graph-record');
            if (card) cards.set(id, card);
            for (const element of node.querySelectorAll('.graph-record, .graph-record__marker, .graph-lane')) {
                obstacles.push({ id, box: element.getBoundingClientRect() });
            }
        }
        for (const id of nodeIds) {
            const card = cards.get(id);
            if (!card) {
                issues.push(`missing card ${id}`);
                continue;
            }
            for (const element of [card, ...card.querySelectorAll('.graph-record__marker')]) {
                if (!inside(element.getBoundingClientRect())) issues.push(`clipped card ${id}`);
            }
        }

        const labels = [];
        for (const label of graph.querySelectorAll('.graph-edge-label')) {
            const match = label.textContent.match(/^\s*(\d+)\s*[·.]\s*Triggers\s*$/i);
            if (!match) continue;
            const name = label.textContent.trim();
            const box = label.getBoundingClientRect();
            if (!inside(box) || getComputedStyle(label).visibility === 'hidden') {
                issues.push(`clipped label ${name}`);
            }
            for (const obstacle of obstacles) {
                if (overlaps(box, obstacle.box)) issues.push(`${name} overlaps ${obstacle.id}`);
            }
            for (const previous of labels) {
                if (overlaps(box, previous.box)) issues.push(`${name} overlaps ${previous.name}`);
            }
            labels.push({ name, box, order: Number(match[1]) });
        }
        return { issues, labels: labels.map(({ order }) => order).sort((a, b) => a - b) };
    }""", node_ids)
    assert geometry["labels"] == numbered_triggers, (state, geometry)
    assert not geometry["issues"], (state, geometry["issues"])


def check_zoom(page: Page, graph: Locator, *, touch: bool = False) -> None:
    initial_zoom = graph_state(graph)["zoom"]
    zoom_in = exact_button(graph, "Zoom in")
    if touch:
        zoom_in.tap()
    else:
        zoom_in.click()
    expect_zoom = """([previous, direction]) => {
        const viewport = document.querySelector('.react-flow__viewport');
        const zoom = new DOMMatrixReadOnly(getComputedStyle(viewport).transform).a;
        return direction * (zoom - previous) > 0.001;
    }"""
    page.wait_for_function(expect_zoom, arg=[initial_zoom, 1])

    enlarged = graph_state(graph)["zoom"]
    exact_button(graph, "Zoom out").click()
    page.wait_for_function(expect_zoom, arg=[enlarged, -1])
    exact_button(graph, "Fit graph").click()


def zoom_in_twice(page: Page, graph: Locator, *, touch: bool = False) -> float:
    initial_zoom = graph_state(graph)["zoom"]
    button = exact_button(graph, "Zoom in")
    for _ in range(2):
        if touch:
            button.tap()
        else:
            button.click()
    page.wait_for_function("""previous => {
        const viewport = document.querySelector('.react-flow__viewport');
        return new DOMMatrixReadOnly(getComputedStyle(viewport).transform).a > previous + .001;
    }""", arg=initial_zoom)
    return graph_state(graph)["zoom"]


def check_header(page: Page) -> None:
    header = page.get_by_role("banner")
    navigation = header.get_by_role("navigation", name="Primary navigation")
    expect(navigation.get_by_role("link")).to_have_text(["Overview", "Intelligence Graph", "Findings"])
    expect(header.get_by_text("Relate", exact=True)).to_be_visible()
    expect(exact_button(header, "Refresh")).to_be_visible()
    for name in ("Overview", "Intelligence Graph", "Findings"):
        link = navigation.get_by_role("link", name=name, exact=True)
        target = link.evaluate("element => element.hash")
        link.click()
        expect(page).to_have_url(re.compile(re.escape(target) + "$"))
        expect(page.locator(target)).to_be_visible()


def check_logo(page: Page, url: str) -> None:
    response = page.request.get(f"{url}/varkhard-shield.svg")
    assert response.status == 200, response.status
    assert response.headers["content-type"].split(";", 1)[0] == "image/svg+xml"
    shield = Path(__file__).resolve().parents[2] / "frontend/public/varkhard-shield.svg"
    assert response.body() == shield.read_bytes()
    logo = page.get_by_role("banner").locator("img[src$='/varkhard-shield.svg']")
    expect(logo).to_be_visible()
    page.wait_for_function("""() => {
        const logo = document.querySelector("img[src$='/varkhard-shield.svg']");
        return logo?.complete && logo.naturalWidth > 0 && logo.naturalHeight > 0;
    }""")


def select_finding(page: Page, finding: dict) -> None:
    category = finding["category"]
    button = page.locator("#findings").get_by_role("button", name=re.compile(re.escape(category)))
    button.click()
    expect(button).to_have_attribute("aria-pressed", "true")
    expect(inspector_heading(page, category)).to_be_visible()


def check_investigation(page: Page, graph: Locator, finding: dict, edges: list[dict]) -> None:
    investigation = finding["investigation"]
    select_finding(page, finding)
    inspector = page.locator("#inspector")
    expect(inspector.get_by_text(finding["explanation"], exact=True)).to_be_visible()
    expect(inspector.get_by_text("Root cause not established", exact=True)).to_be_visible()
    for heading in ("Earliest supported evidence", "Trigger", "Recorded context"):
        expect(inspector_heading(page, heading)).to_be_visible()
    expect(inspector.get_by_role("heading", name=re.compile(r"^Evidence steps\b"))).to_be_visible()

    toolbar = page.get_by_role("group", name="Investigation controls")
    trace_origin = exact_button(toolbar, "Trace Origin")
    trace_origin.click()
    expect(trace_origin).to_have_attribute("aria-pressed", "true")
    origin = investigation["origin"]
    assert origin and origin["record_node_id"], finding["rule_id"]
    assert graph_ids(graph, ".react-flow__node:has(.graph-record--origin)") == {origin["record_node_id"]}
    expect(graph.locator(".react-flow__edge.graph-edge--origin")).to_have_count(0)

    full_path = exact_button(toolbar, "Highlight Full Path")
    full_path.click()
    expect(full_path).to_have_attribute("aria-pressed", "true")
    assert graph_ids(graph, ".react-flow__node:has(.graph-record--finding)") == set(investigation["node_ids"])
    assert graph_ids(graph, ".react-flow__edge.graph-edge--finding") == set(investigation["edge_ids"])
    is_chain = finding["rule_id"] == "suspicious_chain"
    if is_chain:
        check_recorded_chain(graph, investigation, edges)
    check_graph_geometry(graph, investigation["node_ids"], [1, 2] if is_chain else [], f"{finding['category']} path")

    affected = exact_button(toolbar, "Show Affected Nodes")
    affected.click()
    expect(affected).to_have_attribute("aria-pressed", "true")
    affected_nodes = set(investigation["affected_node_ids"])
    path_edges = set(investigation["edge_ids"])
    affected_edges = {
        edge["id"]
        for edge in edges
        if edge["id"] in path_edges and edge["source"] in affected_nodes and edge["target"] in affected_nodes
    }
    assert graph_ids(graph, ".react-flow__node:has(.graph-record--affected)") == affected_nodes
    assert graph_ids(graph, ".react-flow__edge.graph-edge--affected") == affected_edges
    assert graph.locator(".graph-record--muted").count() > 0

    exact_button(toolbar, "Step Through Evidence").click()
    previous_step = exact_button(toolbar, "Previous evidence step")
    next_step = exact_button(toolbar, "Next evidence step")
    expect(previous_step).to_be_disabled()
    steps = inspector.locator(".inspect-step")
    expect(steps).to_have_count(len(investigation["steps"]))
    for index, evidence_step in enumerate(investigation["steps"]):
        step = steps.nth(index)
        button = step.get_by_role("button", name=evidence_step["title"], exact=True)
        expect(button).to_have_attribute("aria-pressed", "true")
        expect(toolbar.get_by_role("status")).to_contain_text(f"Step {index + 1} of {len(investigation['steps'])}")
        assert graph_ids(graph, ".react-flow__node:has(.graph-record--step)") == set(evidence_step["node_ids"])
        assert graph_ids(graph, ".react-flow__edge.graph-edge--step") == set(evidence_step["edge_ids"])
        record_node_id = evidence_step["record_node_id"]
        if record_node_id:
            assert graph_ids(graph, ".react-flow__node:has(.graph-record--selected)") == {record_node_id}
        check_graph_geometry(
            graph, evidence_step["node_ids"], [index] if is_chain and index else [],
            f"{finding['category']} step {index + 1}",
        )
        if index < len(investigation["steps"]) - 1:
            next_step.click()
    expect(next_step).to_be_disabled()
    if len(investigation["steps"]) > 1:
        previous_step.click()
        expect(steps.nth(len(investigation["steps"]) - 2).get_by_role("button")).to_have_attribute(
            "aria-pressed", "true",
        )
        steps.first.get_by_role("button").click()
        expect(steps.first.get_by_role("button")).to_have_attribute("aria-pressed", "true")

    exact_button(page.locator("#graph"), "Reset Graph").click()
    expect(page.locator("#findings button[aria-pressed='true']")).to_have_count(0)
    expect(graph.locator(".graph-record--muted")).to_have_count(0)
    for mode in ("origin", "finding", "affected", "step", "selected"):
        expect(graph.locator(f".graph-record--{mode}")).to_have_count(0)
    print(f"Verified origin, full path, affected nodes, all steps and reset for {finding['category']}.")


def check_recorded_chain(graph: Locator, investigation: dict, edges: list[dict]) -> None:
    read, handoff, export = (step["record_node_id"] for step in investigation["steps"])
    expected = {
        ("TRIGGERS", read, handoff),
        ("TRIGGERS", handoff, export),
        ("HANDED_TO", handoff, "agent:agent-relay"),
    }
    highlighted = graph_ids(graph, ".react-flow__edge.graph-edge--finding")
    recorded = {
        (edge["kind"], edge["source"], edge["target"])
        for edge in edges
        if edge["id"] in highlighted and edge["kind"] in {"TRIGGERS", "HANDED_TO"}
    }
    assert recorded == expected, recorded
    labels = graph.locator(".graph-edge-label").filter(has_text="Triggers")
    expect(labels).to_have_count(2)


def check_evidence_timeline(page: Page, finding: dict, data: dict) -> None:
    inspector = page.locator("#inspector")
    events = inspector.get_by_role("region", name="Recorded event timeline")
    policy = inspector.get_by_role("region", name="Policy comparison")
    interactions = {item["id"]: item for item in data["interactions"]}
    permissions = {item["id"]: item for item in data["permissions"]}
    agents = {item["id"]: item["name"] for item in data["agents"]}
    resources = {item["id"]: item["name"] for item in data["resources"]}
    steps = finding["investigation"]["steps"]
    events_in_trace = [step for step in steps if step["record_node_id"].startswith("interaction:")]
    permissions_in_trace = [step for step in steps if step["record_node_id"].startswith("permission:")]
    expect(events.locator(".inspect-step")).to_have_count(len(events_in_trace))
    expect(policy.locator(".inspect-step")).to_have_count(len(permissions_in_trace))

    timestamps = []
    for index, step in enumerate(events_in_trace):
        record_id = step["record_node_id"].split(":", 1)[1]
        record = interactions[record_id]
        timestamp = datetime.fromtimestamp(record["occurred_at"], timezone.utc).isoformat().replace("+00:00", "Z")
        timestamps.append(timestamp)
        row = events.locator(".inspect-step").nth(index)
        expect(row.get_by_text(record_id, exact=True)).to_be_visible()
        expect(row.locator("time")).to_have_attribute("datetime", timestamp)
        values = [agents[record["agent_id"]], resources[record["resource_id"]], record["action"], record["outcome"]]
        if record["recipient_id"]:
            values.append(agents[record["recipient_id"]])
        for value in values:
            expect(row.get_by_text(value, exact=True).first).to_be_visible()
    assert timestamps == sorted(timestamps), timestamps

    for step in permissions_in_trace:
        record_id = step["record_node_id"].split(":", 1)[1]
        row = policy.locator(".inspect-step").filter(has=page.get_by_text(record_id, exact=True))
        permission = permissions[record_id]
        policy_label = "Baseline approval" if permission["kind"] == "baseline" else "Current grant"
        expect(row.locator(".inspect-step-policy")).to_have_text(f"Policy record · {policy_label}")
        for field in ("Event time", "Outcome"):
            value = row.locator("dl > div").filter(has=page.get_by_text(field, exact=True)).locator("dd")
            expect(value).to_have_text("Unavailable")
        expect(row.locator("time")).to_have_count(0)


def check_record_details(page: Page, finding: dict, data: dict) -> None:
    select_finding(page, finding)
    check_evidence_timeline(page, finding, data)
    inspector = page.locator("#inspector")
    evidence = finding["evidence"]
    rule_id = finding["rule_id"]
    if rule_id == "unauthorized_access":
        assert evidence["outcome"] == "denied"
        expected_ids = [evidence["interaction_id"], *evidence["related_grant_ids"]]
        expected_values = [evidence["agent_id"], evidence["resource_id"], "write", "denied"]
    elif rule_id == "excessive_permission":
        assert all(step["outcome"] is None for step in finding["investigation"]["steps"])
        expected_ids = [evidence["permission_id"], *evidence["related_baseline_ids"]]
        expected_values = [evidence["agent_id"], evidence["resource_id"], "delete"]
    else:
        assert evidence["elapsed_seconds"] == 180
        assert evidence["window_seconds"] == 600
        expected_ids = evidence["interaction_ids"]
        expected_values = [evidence["source_resource_id"], evidence["destination_resource_id"]]
        steps = [step for step in finding["investigation"]["steps"] if step["occurred_at"] is not None]
        assert [step["action"] for step in steps] == ["read", "handoff", "export"]
        assert [step["outcome"] for step in steps] == ["success", "success", "success"]
        assert [step["record_node_id"] for step in steps] == [
            f"interaction:{record_id}" for record_id in expected_ids
        ]
        for event in evidence["interactions"]:
            expect(inspector.get_by_text(event["occurred_at"], exact=True).filter(visible=True).first).to_be_visible()

    supporting_records = inspector.get_by_text("Supporting records", exact=True)
    supporting_records.click()
    for value in [*expected_ids, *expected_values]:
        expect(inspector.get_by_text(value, exact=True).filter(visible=True).first).to_be_visible()
    supporting_records.click()


def check_search(page: Page, graph: Locator) -> None:
    search = page.get_by_role("searchbox", name="Search graph records")
    category = page.get_by_role("combobox", name="Search category")
    results = page.get_by_role("region", name="Search results")

    category.select_option(label="All records")
    search.fill("record-that-does-not-exist")
    expect(results.get_by_text("No graph records match your search.", exact=True)).to_be_visible()
    search.fill("Preview Agent")
    expect(results.get_by_role("button", name=re.compile("Preview Agent"))).to_be_visible()
    search.press("Escape")
    expect(results).to_be_hidden()
    expect(search).to_have_value("Preview Agent")
    search.press("Enter")
    first_match = results.get_by_role("button", name=re.compile("Preview Agent"))
    expect(first_match).to_be_visible()
    search.press("ArrowDown")
    expect(first_match).to_be_focused()
    first_match.press("Enter")
    expect(inspector_heading(page, "Preview Agent")).to_be_visible()

    queries = (
        ("AI agents", "Preview Agent", "Preview Agent", "Preview Agent"),
        ("AI agents", "agent-preview", "Preview Agent", "Preview Agent"),
        ("Resources", "Sample Catalog", "Sample Catalog", "Sample Catalog"),
        ("Resources", "resource-sample-catalog", "Sample Catalog", "Sample Catalog"),
        ("Actions", "DELETE", "delete", "delete grant"),
        ("Finding types", "suspicious_chain", "Suspicious Chain", "Suspicious Chain"),
        ("Interactions", "interaction-outbox-export", "export", "export"),
    )
    for scope, query, result_name, selected_name in queries:
        category.select_option(label=scope)
        search.fill(query)
        result = results.get_by_role("button", name=re.compile(re.escape(result_name), re.I))
        expect(result).to_have_count(1)
        result.click()
        expect(inspector_heading(page, selected_name)).to_be_visible()
        emphasized = ".graph-record--finding" if scope == "Finding types" else ".graph-record--selected"
        expect(graph.locator(emphasized).first).to_be_visible()
    print("Verified search across all five categories, name and ID queries, empty results and keyboard selection.")


def drag_card(page: Page, card: Locator, destination: tuple[float, float] | None = None) -> None:
    card.scroll_into_view_if_needed()
    box = card.bounding_box()
    assert box
    x, y = box["x"] + box["width"] / 2, box["y"] + box["height"] / 2
    page.mouse.move(x, y)
    page.mouse.down()
    page.mouse.move(*(destination or (x + 45, y + 35)), steps=10)
    page.mouse.up()


def check_graph_movement(page: Page, graph: Locator) -> None:
    page.get_by_role("combobox", name="Select an AI agent").select_option("agent:agent-preview")
    expect(inspector_heading(page, "Preview Agent")).to_be_visible()
    check_zoom(page, graph)

    pick = exact_button(graph, "AI agent: Research Agent")
    pick.click()
    expect(inspector_heading(page, "Research Agent")).to_be_visible()
    exact_button(graph, "Fit graph").click()
    preview = exact_button(graph, "AI agent: Preview Agent")
    preview.press("Enter")
    expect(inspector_heading(page, "Preview Agent")).to_be_visible()
    exact_button(graph, "Fit graph").click()

    pane = graph.locator(".react-flow__pane")
    point = pane.evaluate("""pane => {
        const box = pane.getBoundingClientRect();
        for (let y = 20; y < Math.min(box.height - 50, 300); y += 20) {
            for (let x = 30; x < Math.min(box.width - 70, 500); x += 20) {
                const point = [box.left + x, box.top + y];
                if (document.elementFromPoint(...point) === pane) return point;
            }
        }
        throw new Error('No unobstructed portion of the graph canvas is visible');
    }""")
    initial_x = graph_state(graph)["x"]
    page.mouse.move(*point)
    page.mouse.down()
    page.mouse.move(point[0] + 43, point[1] + 29, steps=8)
    page.mouse.up()
    panned = graph_state(graph)["x"]
    assert abs(panned - initial_x) > 15

    exact_button(graph, "Fit graph").click()
    page.wait_for_function(
        """panned => {
            const viewport = document.querySelector('.react-flow__viewport');
            return Math.abs(new DOMMatrixReadOnly(getComputedStyle(viewport).transform).e - panned) > 15;
        }""",
        arg=panned,
    )
    node = graph.locator('.react-flow__node[data-id="agent:agent-preview"]')
    initial_position = node.evaluate("node => node.style.transform")
    drag_card(page, preview)
    assert node.evaluate("node => node.style.transform") != initial_position
    exact_button(page.locator("#graph"), "Reset Graph").click()
    expect(node).to_have_attribute("style", re.compile(re.escape(initial_position)))
    print("Verified graph selection with picker, mouse and keyboard, plus pan, zoom, fit, drag and layout reset.")


def check_label_collision_after_drag(page: Page, graph: Locator, finding: dict) -> None:
    select_finding(page, finding)
    agent = exact_button(graph, "AI agent: Research Agent")
    agent.scroll_into_view_if_needed()
    node = graph.locator('.react-flow__node[data-id="agent:agent-research"]')
    label = graph.locator(".graph-edge-label").filter(has_text=re.compile(r"^1\s*·\s*Triggers$"))
    box = label.bounding_box()
    assert box
    before = node.evaluate("node => node.style.transform")
    drag_card(page, agent, (box["x"] + box["width"] / 2, box["y"] + box["height"] / 2))
    assert node.evaluate("node => node.style.transform") != before
    check_graph_geometry(graph, finding["investigation"]["node_ids"], [1, 2], "dragged card across trigger label")
    exact_button(page.locator("#graph"), "Reset Graph").click()
    print("Verified trigger labels avoid a graph card dragged into their former position.")


def check_focus_mode(
    page: Page, graph: Locator, finding: dict, screenshots: Path | None, *, touch: bool = False,
) -> None:
    select_finding(page, finding)
    toolbar = page.get_by_role("group", name="Investigation controls")

    def activate(button: Locator) -> None:
        if touch:
            button.tap()
        else:
            button.click()

    activate(exact_button(toolbar, "Step Through Evidence"))
    activate(exact_button(toolbar, "Next evidence step"))
    step = finding["investigation"]["steps"][1]
    selected = graph.locator(".react-flow__node:has(.graph-record--selected)")
    expect(selected).to_have_attribute("data-id", step["record_node_id"])
    node_position = selected.evaluate("node => node.style.transform")
    if not touch:
        drag_card(page, selected.get_by_role("button"))
        assert selected.evaluate("node => node.style.transform") != node_position

    zoom_in_twice(page, graph, touch=touch)
    viewport = graph.locator(".react-flow__viewport")
    original_viewport = viewport.element_handle()
    original_position = selected.evaluate("node => node.style.transform")
    inspector = page.locator("#inspector")
    workspace = page.get_by_role("region", name="Investigation workspace")
    expand = exact_button(workspace, "Expand Investigation")
    exit_focus = exact_button(workspace, "Exit Focus Mode")

    def assert_retained(state: str) -> None:
        check_graph_geometry(graph, step["node_ids"], [1], state)
        assert viewport.evaluate("(element, original) => element === original", original_viewport)
        assert selected.evaluate("node => node.style.transform") == original_position
        assert graph_ids(graph, ".react-flow__node:has(.graph-record--step)") == set(step["node_ids"])
        assert graph_ids(graph, ".react-flow__edge.graph-edge--step") == set(step["edge_ids"])
        expect(toolbar.get_by_role("status")).to_contain_text(step["title"])

    def check_chain_frames(state: str) -> None:
        investigation = finding["investigation"]
        activate(exact_button(toolbar, "Highlight Full Path"))
        check_graph_geometry(graph, investigation["node_ids"], [1, 2], f"{state} full path")
        activate(exact_button(toolbar, "Step Through Evidence"))
        for index, evidence_step in enumerate(investigation["steps"]):
            check_graph_geometry(
                graph, evidence_step["node_ids"], [index] if index else [], f"{state} step {index + 1}",
            )
            if index < len(investigation["steps"]) - 1:
                activate(exact_button(toolbar, "Next evidence step"))
        activate(exact_button(toolbar, "Previous evidence step"))

    def assert_expanded() -> None:
        expect(exit_focus).to_be_visible()
        expect(page.get_by_role("banner")).to_be_visible()
        expect(page.get_by_role("heading", level=1, name="Security Intelligence Overview")).to_be_hidden()
        bounds = workspace.bounding_box()
        viewport_size = page.viewport_size
        assert bounds and viewport_size
        assert bounds["width"] >= viewport_size["width"] * 0.89, bounds
        assert bounds["height"] >= viewport_size["height"] * 0.72, bounds

    active_step = exact_button(inspector, step["title"])
    expect(active_step).to_have_attribute("aria-pressed", "true")
    activate(expand)
    assert_expanded()
    assert_retained("entered Focus Mode after manual zoom")
    check_chain_frames("Focus Mode initial Inspector state")

    if touch:
        expect(inspector).to_be_hidden()
        if screenshots is not None:
            page.screenshot(path=screenshots / f"focus-mobile-{page.viewport_size['width']}-graph.png")
    else:
        expect(active_step).to_have_attribute("aria-pressed", "true")
        activate(exact_button(workspace, "Hide Inspector"))
        expect(inspector).to_be_hidden()
        assert_retained("hidden Inspector")
        check_chain_frames("Focus Mode Inspector hidden")

    activate(exact_button(workspace, "Show Inspector"))
    expect(active_step).to_have_attribute("aria-pressed", "true")
    assert_retained("restored Inspector")
    check_chain_frames("Focus Mode Inspector restored")
    if screenshots is not None:
        mode = f"mobile-{page.viewport_size['width']}" if touch else "desktop"
        page.screenshot(path=screenshots / f"focus-{mode}.png")

    page.keyboard.press("Escape")
    expect(expand).to_be_focused()
    expect(active_step).to_have_attribute("aria-pressed", "true")
    assert_retained("exited Focus Mode with Escape")
    activate(expand)
    assert_expanded()
    activate(exit_focus)
    expect(expand).to_be_focused()
    expect(active_step).to_have_attribute("aria-pressed", "true")
    assert_retained("exited Focus Mode with button")

    activate(expand)
    activate(exact_button(toolbar, "Next evidence step"))
    last_step = finding["investigation"]["steps"][2]
    expect(toolbar.get_by_role("status")).to_contain_text(last_step["title"])
    assert graph_ids(graph, ".react-flow__edge.graph-edge--step") == set(last_step["edge_ids"])
    activate(exit_focus)
    expect(exact_button(inspector, last_step["title"])).to_have_attribute("aria-pressed", "true")
    check_graph_geometry(graph, last_step["node_ids"], [2], "continued evidence step after exit")
    assert page.evaluate("document.documentElement.scrollWidth === window.innerWidth")


def watch_errors(page: Page) -> list[str]:
    errors: list[str] = []
    page.on("pageerror", lambda error: errors.append(str(error)))

    def console(message: ConsoleMessage) -> None:
        if message.type == "error":
            location = message.location.get("url")
            errors.append(f"{location} {message.text}" if location else message.text)

    def response_failure(response: Response) -> None:
        if response.status >= 400:
            errors.append(f"HTTP {response.status} {response.url}")

    page.on("console", console)
    page.on("response", response_failure)
    return errors


def capture(page: Page, directory: Path | None, filename: str) -> None:
    if directory is not None:
        page.evaluate("window.scrollTo({top: 0, behavior: 'instant'})")
        page.wait_for_function("window.scrollY === 0")
        page.screenshot(path=directory / filename, full_page=True)


def check_desktop(browser: Browser, url: str, screenshots: Path | None) -> dict:
    page = browser.new_page(viewport={"width": 1440, "height": 1100}, reduced_motion="reduce")
    errors = watch_errors(page)
    with page.expect_response(graph_response) as response:
        document = page.goto(f"{url}/")
    assert document and document.ok
    data = response.value.json()
    assert data["source"]["filename"] == "synthetic-demo.rl"
    assert data["source"]["read_only"] is True
    findings = {finding["rule_id"]: finding for finding in data["findings"]}
    assert set(findings) == DEMO_FINDINGS

    graph = page.get_by_role("region", name=GRAPH_NAME)
    expect(graph).to_be_visible()
    expect(graph.locator(".react-flow__node:has(.graph-record)")).to_have_count(len(data["nodes"]))
    expect(graph.locator(".react-flow__edge")).to_have_count(len(data["edges"]))
    expect(page.get_by_role("heading", level=1, name="Security Intelligence Overview")).to_be_visible()
    check_logo(page, url)
    overview = page.locator("#overview")
    expect(overview.get_by_text("Synthetic Relate snapshot", exact=True)).to_be_visible()
    expect(overview.get_by_text(data["source"]["filename"], exact=True)).to_be_visible()
    capture(page, screenshots, "desktop.png")
    check_header(page)

    for finding in findings.values():
        check_investigation(page, graph, finding, data["edges"])
        check_record_details(page, finding, data)
    capture(page, screenshots, "desktop-chain.png")
    check_label_collision_after_drag(page, graph, findings["suspicious_chain"])
    check_focus_mode(page, graph, findings["suspicious_chain"], screenshots)
    print("Verified desktop Focus Mode refits evidence while retaining selection and a dragged position.")

    check_search(page, graph)
    check_graph_movement(page, graph)
    with page.expect_response(graph_response) as refreshed:
        exact_button(page.get_by_role("banner"), "Refresh").click()
    assert refreshed.value.json()["findings"] == data["findings"]
    expect(graph).to_be_visible()
    assert not errors, errors
    page.close()
    return data


def check_mobile(browser: Browser, url: str, width: int, finding: dict, screenshots: Path | None) -> None:
    page = browser.new_page(
        viewport={"width": width, "height": 844},
        is_mobile=True,
        has_touch=True,
        reduced_motion="reduce",
    )
    errors = watch_errors(page)
    page.goto(f"{url}/")
    graph = page.get_by_role("region", name=GRAPH_NAME)
    expect(graph).to_be_visible()
    check_header(page)
    check_zoom(page, graph, touch=True)
    select_finding(page, finding)
    toolbar = page.get_by_role("group", name="Investigation controls")
    exact_button(toolbar, "Step Through Evidence").tap()
    exact_button(toolbar, "Next evidence step").tap()
    expect(inspector_heading(page, finding["category"])).to_be_visible()
    assert page.evaluate("document.documentElement.scrollWidth") == width
    assert page.evaluate("window.innerWidth") == width
    capture(page, screenshots, f"mobile-{width}.png")
    check_focus_mode(page, graph, finding, screenshots, touch=True)
    assert not errors, errors
    page.close()
    print(f"Verified navigation, touch zoom, evidence steps and Focus Mode without overflow at {width}px.")


def check_short_viewport(
    browser: Browser, url: str, width: int, height: int, finding: dict, screenshots: Path | None,
) -> None:
    page = browser.new_page(
        viewport={"width": width, "height": height},
        is_mobile=True,
        has_touch=True,
        reduced_motion="reduce",
    )
    errors = watch_errors(page)
    page.goto(f"{url}/")
    select_finding(page, finding)
    graph = page.get_by_role("region", name=GRAPH_NAME)
    workspace = page.get_by_role("region", name="Investigation workspace")
    expand = exact_button(workspace, "Expand Investigation")
    exit_focus = exact_button(workspace, "Exit Focus Mode")
    inspector = page.locator("#inspector")
    expand.tap()
    expect(exit_focus).to_be_visible()
    expect(inspector).to_be_hidden()
    toolbar = page.get_by_role("group", name="Investigation controls")
    path_ids = finding["investigation"]["node_ids"]
    manual_zoom = None

    for inspector_state in ("hidden", "shown"):
        if inspector_state == "shown":
            exact_button(workspace, "Show Inspector").tap()
            expect(inspector_heading(page, finding["category"])).to_be_visible()
        graph.scroll_into_view_if_needed()
        bounds = graph.bounding_box()
        assert bounds and bounds["height"] >= 220, (width, height, inspector_state, bounds)
        visible_height = graph.evaluate("""canvas => new Promise(resolve => {
            const observer = new IntersectionObserver(([entry]) => {
                observer.disconnect();
                resolve(entry.intersectionRect.height);
            });
            observer.observe(canvas);
        })""")
        assert visible_height >= 214, (width, height, inspector_state, visible_height)
        assert page.evaluate("document.documentElement.scrollWidth") == width
        check_graph_geometry(graph, path_ids, [1, 2], f"short viewport Inspector {inspector_state}")
        if manual_zoom is not None:
            assert graph_state(graph)["zoom"] < manual_zoom - 0.001, (width, height, inspector_state)
        if screenshots is not None:
            page.screenshot(path=screenshots / f"focus-short-{width}x{height}-{inspector_state}.png")
        check_zoom(page, graph, touch=True)
        exact_button(toolbar, "Trace Origin").tap()
        exact_button(toolbar, "Highlight Full Path").tap()
        check_graph_geometry(graph, path_ids, [1, 2], "short viewport before manual zoom")
        manual_zoom = zoom_in_twice(page, graph, touch=True)

    exact_button(workspace, "Hide Inspector").tap()
    expect(inspector).to_be_hidden()
    check_graph_geometry(graph, path_ids, [1, 2], "short viewport Inspector hidden again")
    assert graph_state(graph)["zoom"] < manual_zoom - 0.001, (width, height, "hidden again")
    navigation = page.get_by_role("navigation", name="Primary navigation")
    navigation.get_by_role("link", name="Findings", exact=True).tap()
    expect(expand).to_be_visible()
    expect(page).to_have_url(re.compile(r"#findings$"))
    expect(inspector_heading(page, finding["category"])).to_be_visible()
    expand.tap()
    exit_focus.tap()
    expect(expand).to_be_visible()
    expect(inspector_heading(page, finding["category"])).to_be_visible()
    assert not errors, errors
    page.close()
    print(f"Verified scrollable Focus Mode and usable canvas with Inspector hidden or shown at {width}×{height}.")


def check_partial_trace(browser: Browser, url: str, data: dict) -> None:
    partial_data = deepcopy(data)
    finding = next(value for value in partial_data["findings"] if value["rule_id"] == "suspicious_chain")
    trace = finding["investigation"]
    trace.update(origin=None, trigger=None, steps=[], complete=False)

    page = browser.new_page()
    errors = watch_errors(page)
    page.route("**/api/graph", lambda route: route.fulfill(json=partial_data))
    page.goto(f"{url}/")
    select_finding(page, finding)
    inspector = page.locator("#inspector")
    expect(inspector.get_by_text("Partial evidence trace", exact=True)).to_be_visible()
    expect(inspector.get_by_text("Root cause not established", exact=True)).to_be_visible()
    expect(inspector.get_by_text("Unavailable in this snapshot.", exact=True)).to_have_count(2)
    toolbar = page.get_by_role("group", name="Investigation controls")
    expect(exact_button(toolbar, "Trace Origin")).to_be_disabled()
    expect(exact_button(toolbar, "Step Through Evidence")).to_be_disabled()
    assert not errors, errors
    page.close()
    print("Verified partial trace display and unavailable history controls.")


def check_error_recovery(browser: Browser, url: str) -> None:
    page = browser.new_page()
    pending: list[Route] = []
    def hold_request(route: Route) -> None:
        pending.append(route)

    page.route("**/api/graph", hold_request, times=1)
    with page.expect_request("**/api/graph"):
        page.goto(f"{url}/", wait_until="domcontentloaded")
    expect(page.get_by_text(re.compile(r"Loading graph", re.I)).first).to_be_visible()
    assert pending, "The API request was not intercepted"
    message = "The Relate graph is unavailable. Check the configured Single File."
    pending[0].fulfill(status=503, json={"detail": message})
    expect(page.get_by_role("alert").get_by_text(message, exact=True)).to_be_visible()
    exact_button(page.get_by_role("alert"), "Retry").click()
    expect(page.get_by_role("region", name=GRAPH_NAME)).to_be_visible()
    page.close()
    print("Loading state, API failure message, and Retry recovery")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:8010", help="running demo dashboard URL")
    parser.add_argument("--browser-executable", help="optional path to a local Chromium executable")
    parser.add_argument("--screenshots", type=Path, help="directory to save optional browser screenshots")
    args = parser.parse_args()
    url = args.base_url.rstrip("/")
    if args.screenshots:
        args.screenshots.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(executable_path=args.browser_executable)
        data = check_desktop(browser, url, args.screenshots)
        chain = next(finding for finding in data["findings"] if finding["rule_id"] == "suspicious_chain")
        for width in (390, 320):
            check_mobile(browser, url, width, chain, args.screenshots)
        for width, height in ((320, 568), (667, 375)):
            check_short_viewport(browser, url, width, height, chain, args.screenshots)
        check_partial_trace(browser, url, data)
        check_error_recovery(browser, url)
        browser.close()
    print("Dashboard browser regression checks passed.")


if __name__ == "__main__":
    main()
