import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState, type MouseEvent, type RefObject } from 'react'
import {
  ArrowDown, ArrowLeft, ArrowRight, Bot, Box, ChevronRight, Crosshair, Database, GitBranch, GitFork,
  KeyRound, Link2, LoaderCircle, Maximize2, Minimize2, PanelRightClose, PanelRightOpen, RefreshCw, RotateCcw, ScanLine,
  ShieldAlert, ShieldCheck, TriangleAlert, Workflow,
} from 'lucide-react'
import { getDashboard } from './api'
import type { Dashboard, Finding, GraphEdge, GraphNode, Investigation } from './api'
import { IntelligenceGraph } from './IntelligenceGraph'
import type { GraphFocus } from './IntelligenceGraph'
import { Inspector } from './Inspector'
import { Community } from './Community'
import { Knowledge } from './Knowledge'
import { RecordSearch } from './RecordSearch'

const navigation = [
  { id: 'overview', label: 'Overview' },
  { id: 'graph', label: 'Intelligence Graph' },
  { id: 'findings', label: 'Findings' },
  { id: 'knowledge', label: 'Knowledge' },
  { id: 'community', label: 'Community' },
]

const legend = [
  { kind: 'agent', label: 'AI agent', Icon: Bot },
  { kind: 'resource', label: 'Resource', Icon: Box },
  { kind: 'permission', label: 'Permission', Icon: KeyRound },
  { kind: 'interaction', label: 'Interaction', Icon: GitBranch },
]

const findingIcons = { unauthorized_access: ShieldAlert, excessive_permission: KeyRound, suspicious_chain: GitFork }

type RequestState = { status: 'loading' } | { status: 'loaded'; data: Dashboard } | { status: 'error'; message: string }
type FindingView = { mode: 'path' | 'origin' | 'affected' } | { mode: 'step'; index: number }
type FindingSelection = { kind: 'finding'; finding: Finding; view: FindingView }
type Selection = { kind: 'node'; node: GraphNode } | FindingSelection

function sectionFromHash() {
  const hash = window.location.hash.slice(1)
  if (hash === 'investigation-tools') return 'graph'
  return navigation.find(({ id }) => id === hash)?.id ?? (hash === 'inspector' ? 'findings' : 'overview')
}

function isPrivateSection(section: string) {
  return section === 'knowledge' || section === 'community'
}

function supportingEdge(edge: GraphEdge, node: GraphNode, neighbors: Set<string>) {
  if (node.kind === 'agent') {
    return neighbors.has(edge.source) && ['ON_RESOURCE', 'TARGETS', 'HANDED_TO'].includes(edge.kind)
  }
  if (node.kind === 'resource') {
    return neighbors.has(edge.target) && ['HAS_PERMISSION', 'PERFORMED'].includes(edge.kind)
  }
  return false
}

function orderedTriggerEdges(investigation: Investigation, edges: GraphEdge[]) {
  const sequence = new Map<string, { next: string; index: number }>()
  investigation.steps.slice(0, -1).forEach(({ record_node_id: id }, index) => {
    const next = investigation.steps[index + 1].record_node_id
    if (id && next) sequence.set(id, { next, index })
  })
  const supported = new Set(investigation.edge_ids)
  return edges.flatMap((edge) => {
    const step = sequence.get(edge.source)
    return step && edge.kind === 'TRIGGERS' && edge.target === step.next && supported.has(edge.id)
      ? [{ id: edge.id, index: step.index }]
      : []
  }).sort((left, right) => left.index - right.index).map(({ id }) => id)
}

function findAmbiguousTriggers({ nodes, edges, interactions }: Dashboard) {
  const timestampsByRecord = new Map(interactions.map(({ id, occurred_at }) => [id, occurred_at]))
  const timestampsByNode = new Map(nodes.filter(({ kind }) => kind === 'interaction')
    .map(({ id, record_id }) => [id, timestampsByRecord.get(record_id)]))
  return new Set(edges.filter(({ kind, source, target }) => {
    if (kind !== 'TRIGGERS') return false
    const timestamp = timestampsByNode.get(source)
    return timestamp !== undefined && timestamp === timestampsByNode.get(target)
  }).map(({ id }) => id))
}

function investigationFocus({ finding, view }: FindingSelection, edges: GraphEdge[]): GraphFocus {
  const trace = finding.investigation
  if (!trace) return { nodeIds: finding.node_ids, edgeIds: finding.edge_ids, tone: 'finding' }

  const originNodeId = trace.origin?.record_node_id ?? undefined
  if (view.mode === 'origin' && originNodeId) {
    return { nodeIds: [originNodeId], edgeIds: [], originNodeId, tone: 'origin' }
  }

  if (view.mode === 'affected') {
    const relevant = new Set(trace.affected_node_ids)
    const evidenceEdges = new Set(trace.edge_ids)
    const edgeIds = edges.filter(({ id, source, target }) => evidenceEdges.has(id) && relevant.has(source) && relevant.has(target))
      .map(({ id }) => id)
    return { nodeIds: trace.affected_node_ids, edgeIds, tone: 'affected' }
  }

  if (view.mode === 'step') {
    const step = trace.steps[view.index]
    if (step) return {
      nodeIds: step.node_ids,
      edgeIds: step.edge_ids,
      selectedNodeId: step.record_node_id ?? undefined,
      stepNumber: view.index + 1,
      orderedEdgeIds: orderedTriggerEdges(trace, edges),
      tone: 'step',
    }
  }

  return {
    nodeIds: trace.node_ids,
    edgeIds: trace.edge_ids,
    originNodeId,
    orderedEdgeIds: orderedTriggerEdges(trace, edges),
    tone: 'finding',
  }
}

function graphFocus(selection: Selection | null, edges: GraphEdge[]): GraphFocus | undefined {
  if (selection?.kind === 'finding') return investigationFocus(selection, edges)
  if (!selection) return undefined

  const { node } = selection
  const direct = edges.filter(({ source, target }) => source === node.id || target === node.id)
  const neighbors = new Set(direct.map(({ source, target }) => source === node.id ? target : source))
  const related = edges.filter((edge) => supportingEdge(edge, node, neighbors))
  const relevant = [...direct, ...related]
  return {
    nodeIds: [...new Set([node.id, ...relevant.flatMap(({ source, target }) => [source, target])])],
    edgeIds: [...new Set(relevant.map(({ id }) => id))],
    selectedNodeId: node.id,
    tone: 'entity',
  }
}

function Overview({ data, hidden }: { data?: Dashboard; hidden: boolean }) {
  const metrics = data ? [
    { label: 'AI agents', count: data.agents.length, Icon: Bot },
    { label: 'Resources', count: data.resources.length, Icon: Box },
    { label: 'Relationships', count: data.edges.length, Icon: Link2 },
  ] : []

  return (
    <section className="overview" id="overview" aria-labelledby="overview-title" hidden={hidden}>
      <div className="overview-intro">
        <div className="overview-heading">
          <h1 id="overview-title">Security Intelligence Overview</h1>
          <p>Investigate agent access, permissions, and the recorded events behind security findings.</p>
        </div>
        {data && (
          <div className="snapshot">
            <Database size={16} aria-hidden="true" />
            <div>
              <strong>{data.source.synthetic_demo ? 'Synthetic Relate snapshot' : 'Relate snapshot'}</strong>
              <span title={data.source.filename}>{data.source.filename}</span>
            </div>
          </div>
        )}
      </div>
      {data && (
        <div className="overview-metrics">
          <dl className="inventory" aria-label="Graph inventory">
            {metrics.map(({ label, count, Icon }) => (
              <div className="metric" key={label}>
                <dt><Icon size={17} aria-hidden="true" />{label}</dt>
                <dd>{count.toLocaleString('en')}</dd>
              </div>
            ))}
          </dl>
          <a className="finding-metric" href="#findings" data-has-findings={data.findings.length ? '' : undefined}>
            <span className="finding-metric-label"><ShieldAlert size={17} aria-hidden="true" /> Security findings</span>
            <span className="metric-total">{data.findings.length.toLocaleString('en')}</span>
            <ArrowDown className="finding-metric-arrow" size={17} aria-hidden="true" />
          </a>
        </div>
      )}
    </section>
  )
}

function FindingCard({ finding, data, selected, onSelect }: {
  finding: Finding
  data: Dashboard
  selected: boolean
  onSelect: () => void
}) {
  const Icon = findingIcons[finding.rule_id] ?? ShieldAlert
  const agentName = (id: unknown) => data.agents.find((agent) => agent.id === id)?.name
  const agent = agentName(finding.evidence.agent_id)
  const resource = data.resources.find(({ id }) => id === finding.evidence.resource_id)?.name
  const sender = agentName(finding.evidence.sender_agent_id)
  const recipient = agentName(finding.evidence.recipient_agent_id)
  const summary = sender && recipient ? `${sender} → ${recipient}` : [agent, resource].filter(Boolean).join(' · ')

  return (
    <button className="finding-card" type="button" onClick={onSelect} aria-pressed={selected} aria-controls="graph inspector">
      <span className="finding-icon"><Icon size={17} aria-hidden="true" /></span>
      <span className="finding-label">
        <strong>{finding.category}</strong>
        {summary && <span>{summary}</span>}
      </span>
      <ChevronRight className="finding-arrow" size={16} aria-hidden="true" />
    </button>
  )
}

function InvestigationToolbar({ selection, onViewChange, onInspect }: {
  selection: FindingSelection
  onViewChange: (view: FindingView) => void
  onInspect: () => void
}) {
  const { finding, view } = selection
  const trace = finding.investigation
  const steps = trace?.steps ?? []
  const currentStep = view.mode === 'step' ? view.index : undefined
  const label = view.mode === 'origin' ? 'Earliest supported record'
    : view.mode === 'affected' ? 'Affected nodes'
      : view.mode === 'step' ? `Step ${view.index + 1} of ${steps.length}`
        : trace?.complete ? 'Evidence path' : 'Partial evidence graph'
  const detail = view.mode === 'origin' ? trace?.origin?.title
    : view.mode === 'step' ? steps[view.index]?.title : finding.category

  return (
    <div className="investigation-toolbar" id="investigation-tools" role="group" aria-label="Investigation controls">
      <div className="investigation-actions">
        <button type="button" aria-pressed={view.mode === 'origin'} disabled={!trace?.origin?.record_node_id}
          onClick={() => onViewChange({ mode: 'origin' })}>
          <Crosshair size={14} aria-hidden="true" /> Trace Origin
        </button>
        <button type="button" aria-pressed={view.mode === 'path'}
          onClick={() => onViewChange({ mode: 'path' })}>
          <Workflow size={14} aria-hidden="true" /> Highlight Full Path
        </button>
        <button type="button" aria-pressed={view.mode === 'affected'} disabled={!trace?.affected_node_ids.length}
          onClick={() => onViewChange({ mode: 'affected' })}>
          <ScanLine size={14} aria-hidden="true" /> Show Affected Nodes
        </button>
        <button type="button" aria-pressed={view.mode === 'step'} disabled={!steps.length}
          onClick={() => onViewChange({ mode: 'step', index: 0 })}>
          <ArrowRight size={14} aria-hidden="true" /> Step Through Evidence
        </button>
      </div>
      <div className="graph-selection" data-tone="finding">
        <p role="status"><span>{label}</span> {detail}</p>
        {currentStep !== undefined && (
          <div className="step-actions">
            <button type="button" aria-label="Previous evidence step" disabled={currentStep === 0}
              onClick={() => onViewChange({ mode: 'step', index: currentStep - 1 })}>
              <ArrowLeft size={15} aria-hidden="true" />
            </button>
            <button type="button" aria-label="Next evidence step" disabled={currentStep >= steps.length - 1}
              onClick={() => onViewChange({ mode: 'step', index: currentStep + 1 })}>
              <ArrowRight size={15} aria-hidden="true" />
            </button>
          </div>
        )}
        <a href="#inspector" onClick={onInspect}>Inspect finding <ChevronRight size={14} aria-hidden="true" /></a>
      </div>
    </div>
  )
}

function DashboardContent({ data, expanded, hidden, onExpandedChange, expandButton }: {
  data: Dashboard
  expanded: boolean
  hidden: boolean
  onExpandedChange: (expanded: boolean) => void
  expandButton: RefObject<HTMLButtonElement | null>
}) {
  const [selection, setSelection] = useState<Selection | null>(null)
  const [graphRevision, setGraphRevision] = useState(0)
  const [inspectorCollapsed, setInspectorCollapsed] = useState<boolean | null>(null)
  const focus = useMemo(() => graphFocus(selection, data.edges), [selection, data.edges])
  const ambiguousTriggerIds = useMemo(() => findAmbiguousTriggers(data), [data])
  const selectedFinding = selection?.kind === 'finding' ? selection : undefined
  const selectedNode = selection?.kind === 'node' ? selection.node : undefined
  const selectedAgent = selectedNode?.kind === 'agent' ? selectedNode.id : ''
  const inspectorHidden = expanded && inspectorCollapsed === true
  const evidenceIncomplete = data.evidence_quality?.status === 'incomplete'
  const onNodeSelect = useCallback((node: GraphNode) => setSelection({ kind: 'node', node }), [])
  const onFindingSelect = useCallback((finding: Finding) => setSelection({ kind: 'finding', finding, view: { mode: 'path' } }), [])

  function changeView(view: FindingView) {
    setSelection((current) => {
      if (current?.kind !== 'finding') return current
      if (view.mode === 'step' && !current.finding.investigation?.steps[view.index]) return current
      return { ...current, view }
    })
  }

  function resetGraph() {
    setSelection(null)
    setGraphRevision((current) => current + 1)
  }

  function toggleExpanded() {
    if (!expanded && inspectorCollapsed === null) {
      setInspectorCollapsed(window.matchMedia('(max-width: 900px)').matches)
    }
    onExpandedChange(!expanded)
  }

  function revealInspector() {
    if (inspectorHidden) setInspectorCollapsed(false)
  }

  return (
    <div className="analysis-workspace" hidden={hidden}>
      {evidenceIncomplete && !expanded && (
        <aside className="evidence-notice" role="alert" aria-labelledby="evidence-notice-title">
          <TriangleAlert size={16} aria-hidden="true" />
          <div>
            <strong id="evidence-notice-title">Incomplete evidence</strong>
            <p>Some evidence records or links could not be validated. Available findings may be limited.</p>
          </div>
        </aside>
      )}
      <section className="findings-panel panel" id="findings" aria-labelledby="findings-title" hidden={expanded}>
        <header className="findings-heading">
          <h2 id="findings-title">Findings <span className="panel-counter">{data.findings.length}</span></h2>
          {(!evidenceIncomplete || data.findings.length > 0) && <p>Select a finding to trace its evidence.</p>}
        </header>
        {data.findings.length ? (
          <ul className="findings-list">
            {data.findings.map((finding) => (
              <li key={finding.id}>
                <FindingCard
                  data={data}
                  finding={finding}
                  selected={selectedFinding?.finding.id === finding.id}
                  onSelect={() => onFindingSelect(finding)}
                />
              </li>
            ))}
          </ul>
        ) : (
          <p className="empty-message">
            {evidenceIncomplete ? <TriangleAlert size={18} aria-hidden="true" /> : <ShieldCheck size={18} aria-hidden="true" />}
            {evidenceIncomplete ? 'No findings were reported for this incomplete snapshot.' : 'The rules returned no findings.'}
          </p>
        )}
      </section>

      <div className="analysis-layout" id="investigation-workspace" role="region" aria-label="Investigation workspace"
        data-expanded={expanded ? '' : undefined} data-inspector-hidden={inspectorHidden ? '' : undefined}>
        <section className="panel graph-panel" id="graph" aria-labelledby="graph-title">
          <header className="graph-heading">
            <div className="graph-titlebar">
              <div>
                <h2 id="graph-title">Intelligence Graph</h2>
                <p>{data.nodes.length.toLocaleString('en')} nodes <span aria-hidden="true">·</span> {data.edges.length.toLocaleString('en')} relationships</p>
              </div>
              <div className="workspace-controls">
                {expanded && (
                  <button className="workspace-button" type="button" aria-expanded={!inspectorHidden} aria-controls="inspector"
                    onClick={() => setInspectorCollapsed(!inspectorHidden)}>
                    {inspectorHidden ? <PanelRightOpen size={14} aria-hidden="true" /> : <PanelRightClose size={14} aria-hidden="true" />}
                    {inspectorHidden ? 'Show Inspector' : 'Hide Inspector'}
                  </button>
                )}
                <button ref={expandButton} className="workspace-button" type="button" aria-expanded={expanded}
                  aria-controls="investigation-workspace" onClick={toggleExpanded}>
                  {expanded ? <Minimize2 size={14} aria-hidden="true" /> : <Maximize2 size={14} aria-hidden="true" />}
                  {expanded ? 'Exit Focus Mode' : 'Expand Investigation'}
                </button>
              </div>
            </div>
            <div className="graph-actions">
              <RecordSearch key={graphRevision} data={data} onNodeSelect={onNodeSelect} onFindingSelect={onFindingSelect} />
              <select
                className="agent-picker"
                aria-label="Select an AI agent"
                aria-controls="graph inspector"
                value={selectedAgent}
                disabled={!data.agents.length}
                onChange={(event) => {
                  const node = data.nodes.find(({ id }) => id === event.target.value)
                  if (node) onNodeSelect(node)
                  else setSelection(null)
                }}
              >
                <option value="">Select an AI agent</option>
                {data.agents.map((agent) => <option key={agent.id} value={`agent:${agent.id}`}>{agent.name}</option>)}
              </select>
              <button className="reset-button" type="button" onClick={resetGraph}>
                <RotateCcw size={14} aria-hidden="true" /> Reset Graph
              </button>
            </div>
          </header>
          {selectedFinding && <InvestigationToolbar selection={selectedFinding} onViewChange={changeView} onInspect={revealInspector} />}
          {selectedNode && (
            <div className="graph-selection entity-selection">
              <p role="status"><span>Selected entity</span> {selectedNode.label}</p>
              <a href="#inspector" onClick={revealInspector}>Inspect entity <ChevronRight size={14} aria-hidden="true" /></a>
            </div>
          )}
          <div className="graph-viewport">
            {data.nodes.length ? (
              <IntelligenceGraph
                key={graphRevision}
                nodes={data.nodes}
                edges={data.edges}
                ambiguousTriggerIds={ambiguousTriggerIds}
                focus={focus}
                onNodeSelect={onNodeSelect}
                expanded={expanded}
                inspectorHidden={inspectorHidden}
              />
            ) : (
              <p className="graph-empty">
                {evidenceIncomplete ? 'No verified graph records to display.' : 'The Relate file contains no graph records.'}
              </p>
            )}
          </div>
          <ul className="legend" aria-label="Graph node types">
            {legend.map(({ kind, label, Icon }) => (
              <li key={kind} data-kind={kind}><Icon size={15} aria-hidden="true" /> {label}</li>
            ))}
          </ul>
        </section>

        <Inspector
          data={data}
          ambiguousTriggerIds={ambiguousTriggerIds}
          hidden={inspectorHidden}
          node={selectedNode}
          finding={selectedFinding?.finding}
          activeStepIndex={selectedFinding?.view.mode === 'step' ? selectedFinding.view.index : undefined}
          onStepSelect={(index) => changeView({ mode: 'step', index })}
          onNodeSelect={onNodeSelect}
        />
      </div>
    </div>
  )
}

export default function App() {
  const [request, setRequest] = useState<RequestState>({ status: 'loading' })
  const [revision, setRevision] = useState(0)
  const [activeSection, setActiveSection] = useState(sectionFromHash)
  const [expanded, setExpanded] = useState(false)
  const expandButton = useRef<HTMLButtonElement>(null)
  const returnScroll = useRef<number | null>(null)
  const navigationTarget = useRef<string | null>(null)
  const wasPrivateSection = useRef(false)
  const privateSection = isPrivateSection(activeSection)

  function changeExpanded(next: boolean) {
    if (next) returnScroll.current = window.scrollY
    setExpanded(next)
  }

  useLayoutEffect(() => {
    if (expanded) {
      expandButton.current?.focus({ preventScroll: true })
      window.scrollTo(0, 0)
      return
    }
    if (navigationTarget.current) {
      const id = navigationTarget.current
      navigationTarget.current = null
      if (window.location.hash !== `#${id}`) window.location.hash = id
      else document.getElementById(id)?.scrollIntoView()
    } else if (returnScroll.current !== null) {
      window.scrollTo(0, returnScroll.current)
      expandButton.current?.focus({ preventScroll: true })
    }
    returnScroll.current = null
  }, [expanded])

  useEffect(() => {
    if (!expanded) return

    function handleEscape(event: KeyboardEvent) {
      if (event.key === 'Escape' && !event.defaultPrevented) setExpanded(false)
    }
    document.addEventListener('keydown', handleEscape)
    return () => document.removeEventListener('keydown', handleEscape)
  }, [expanded])

  useEffect(() => {
    const updateSection = () => {
      const section = sectionFromHash()
      if (isPrivateSection(section)) setExpanded(false)
      setActiveSection(section)
    }
    window.addEventListener('hashchange', updateSection)
    return () => window.removeEventListener('hashchange', updateSection)
  }, [])

  useLayoutEffect(() => {
    if (isPrivateSection(activeSection) || wasPrivateSection.current) {
      document.getElementById(window.location.hash.slice(1) || 'overview')?.scrollIntoView()
    }
    wasPrivateSection.current = isPrivateSection(activeSection)
  }, [activeSection])

  useEffect(() => {
    const controller = new AbortController()
    getDashboard(controller.signal)
      .then((data) => {
        if (!controller.signal.aborted) setRequest({ status: 'loaded', data })
      })
      .catch((error: unknown) => {
        if (!controller.signal.aborted) {
          setRequest({ status: 'error', message: error instanceof Error ? error.message : 'The API request failed.' })
        }
      })
    return () => controller.abort()
  }, [revision])

  useEffect(() => {
    if (request.status === 'loaded' && window.location.hash) {
      document.getElementById(window.location.hash.slice(1))?.scrollIntoView()
    }
  }, [request.status])

  function refresh() {
    returnScroll.current = null
    setExpanded(false)
    setRequest({ status: 'loading' })
    setRevision((current) => current + 1)
  }

  const sourceStatus = request.status === 'loaded'
    ? (request.data.source.read_only ? 'Read-only' : 'Connected')
    : request.status === 'loading' ? 'Loading' : 'Unavailable'
  const availableSections = request.status === 'loaded'
    ? navigation
    : navigation.filter(({ id }) => id === 'overview' || isPrivateSection(id))
  const currentSection = expanded ? 'graph' : activeSection

  function navigateFromWorkspace(id: string, event: MouseEvent<HTMLAnchorElement>) {
    if (!expanded || id === 'graph' || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) return
    event.preventDefault()
    navigationTarget.current = id
    setExpanded(false)
  }

  return (
    <div className="dashboard-shell" data-workspace-expanded={expanded ? '' : undefined}>
      <a className="skip-link" href="#main">Skip to dashboard</a>
      <header className="site-header">
        <div className="site-header-inner">
          <a className="brand" href="#overview" aria-label="VARKHARD overview" onClick={(event) => navigateFromWorkspace('overview', event)}>
            <img className="brand-emblem" src="/varkhard-shield.svg" alt="" width="24" height="28" />
            <span>VARKHARD</span>
          </a>
          <nav className="top-navigation" aria-label="Primary navigation">
            {availableSections.map(({ id, label }) => (
              <a key={id} href={`#${id}`} aria-current={currentSection === id ? 'location' : undefined}
                onClick={(event) => navigateFromWorkspace(id, event)}>{label}</a>
            ))}
          </nav>
          {!privateSection && <div className="header-actions">
            <span className="source-status" data-status={request.status} title={`Relate · ${sourceStatus}`}>
              <span className="source-dot" aria-hidden="true" />
              <span>Relate</span>
              <span className="source-mode">{sourceStatus}</span>
            </span>
            <button className="refresh-button" type="button" onClick={refresh} disabled={request.status === 'loading'}>
              <RefreshCw className={request.status === 'loading' ? 'spinner' : undefined} size={15} aria-hidden="true" />
              Refresh
            </button>
          </div>}
        </div>
      </header>

      <main id="main" className="main-content" tabIndex={-1}>
        <Overview data={request.status === 'loaded' ? request.data : undefined} hidden={expanded || privateSection} />

        {request.status === 'loaded' && (
          <DashboardContent data={request.data} expanded={expanded} hidden={privateSection}
            onExpandedChange={changeExpanded} expandButton={expandButton} />
        )}
        {!privateSection && request.status === 'loading' && (
          <div className="panel request-state" role="status">
            <LoaderCircle className="spinner" size={22} aria-hidden="true" /> Loading graph from Relate…
          </div>
        )}
        {!privateSection && request.status === 'error' && (
          <div className="panel request-state" role="alert">
            <TriangleAlert size={24} aria-hidden="true" />
            <strong>Couldn’t load the graph</strong>
            <p>{request.message}</p>
            <button className="refresh-button" type="button" onClick={refresh}>Retry</button>
          </div>
        )}
        {activeSection === 'knowledge' && <Knowledge />}
        {activeSection === 'community' && <Community />}
      </main>
    </div>
  )
}
