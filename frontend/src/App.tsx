import { useEffect, useMemo, useState } from 'react'
import {
  ArrowDown, Bot, Box, ChevronRight, Database, GitFork, History, KeyRound,
  Link2, LoaderCircle, RefreshCw, ShieldAlert, ShieldCheck, TriangleAlert, X,
} from 'lucide-react'
import { getDashboard } from './api'
import type { Dashboard, Finding, GraphEdge, GraphNode } from './api'
import { IntelligenceGraph } from './IntelligenceGraph'
import { Inspector } from './Inspector'

const navigation = [
  { id: 'overview', label: 'Overview' },
  { id: 'graph', label: 'Intelligence Graph' },
  { id: 'findings', label: 'Findings' },
]

const legend = [
  { kind: 'agent', label: 'AI agent', Icon: Bot },
  { kind: 'resource', label: 'Resource', Icon: Box },
  { kind: 'permission', label: 'Permission', Icon: KeyRound },
  { kind: 'interaction', label: 'Action', Icon: History },
]

const findingIcons = { unauthorized_access: ShieldAlert, excessive_permission: KeyRound, suspicious_chain: GitFork }

type RequestState = { status: 'loading' } | { status: 'loaded'; data: Dashboard } | { status: 'error'; message: string }
type Selection = { kind: 'node'; node: GraphNode } | { kind: 'finding'; finding: Finding }

function sectionFromHash() {
  const hash = window.location.hash.slice(1)
  return navigation.find(({ id }) => id === hash)?.id ?? (hash === 'inspector' ? 'findings' : 'overview')
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

function graphFocus(selection: Selection | null, edges: GraphEdge[]) {
  if (selection?.kind === 'finding') {
    return { nodeIds: selection.finding.node_ids, edgeIds: selection.finding.edge_ids, tone: 'finding' as const }
  }
  if (!selection) return undefined

  const { node } = selection
  const direct = edges.filter(({ source, target }) => source === node.id || target === node.id)
  const neighbors = new Set(direct.map(({ source, target }) => source === node.id ? target : source))
  const related = edges.filter((edge) => supportingEdge(edge, node, neighbors))
  const relevant = [...direct, ...related]
  return {
    nodeIds: [...new Set([node.id, ...relevant.flatMap(({ source, target }) => [source, target])])],
    edgeIds: [...new Set(relevant.map(({ id }) => id))],
    tone: 'entity' as const,
  }
}

function Overview({ data }: { data?: Dashboard }) {
  const metrics = data ? [
    { label: 'AI agents', count: data.agents.length, Icon: Bot },
    { label: 'Resources', count: data.resources.length, Icon: Box },
    { label: 'Relationships', count: data.edges.length, Icon: Link2 },
  ] : []

  return (
    <section className="overview" id="overview" aria-labelledby="overview-title">
      <div className="overview-intro">
        <div className="overview-heading">
          <h1 id="overview-title">Security Intelligence Overview</h1>
          <p>Trace agent access, examine permissions, and follow the evidence behind each finding.</p>
        </div>
        {data && (
          <div className="snapshot">
            <Database size={16} aria-hidden="true" />
            <div>
              <strong>Relate snapshot</strong>
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
          <a className="finding-metric" href="#findings">
            <span className="finding-metric-icon"><ShieldAlert size={21} aria-hidden="true" /></span>
            <span className="metric-total">{data.findings.length.toLocaleString('en')}</span>
            <span className="finding-metric-label">Security findings</span>
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

function DashboardContent({ data }: { data: Dashboard }) {
  const [selection, setSelection] = useState<Selection | null>(null)
  const focus = useMemo(() => graphFocus(selection, data.edges), [selection, data.edges])
  const selectedAgent = selection?.kind === 'node' && selection.node.kind === 'agent' ? selection.node.id : ''
  const onNodeSelect = (node: GraphNode) => setSelection({ kind: 'node', node })

  return (
    <div className="analysis-workspace">
      <section className="findings-panel panel" id="findings" aria-labelledby="findings-title">
        <header className="findings-heading">
          <h2 id="findings-title">Findings <span className="panel-counter">{data.findings.length}</span></h2>
          <p>Select a finding to trace its evidence.</p>
        </header>
        {data.findings.length ? (
          <ul className="findings-list">
            {data.findings.map((finding) => (
              <li key={finding.id}>
                <FindingCard
                  data={data}
                  finding={finding}
                  selected={selection?.kind === 'finding' && selection.finding.id === finding.id}
                  onSelect={() => setSelection({ kind: 'finding', finding })}
                />
              </li>
            ))}
          </ul>
        ) : <p className="empty-message"><ShieldCheck size={18} aria-hidden="true" /> The rules returned no findings.</p>}
      </section>

      <div className="analysis-layout">
        <section className="panel graph-panel" id="graph" aria-labelledby="graph-title">
          <header className="graph-heading">
            <div>
              <h2 id="graph-title">Intelligence Graph</h2>
              <p>{data.nodes.length.toLocaleString('en')} nodes <span aria-hidden="true">·</span> {data.edges.length.toLocaleString('en')} relationships</p>
            </div>
            <div className="graph-actions">
              {selection && (
                <button className="icon-button" type="button" onClick={() => setSelection(null)} aria-label="Clear highlight" title="Clear highlight">
                  <X size={17} aria-hidden="true" />
                </button>
              )}
              <select
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
            </div>
          </header>
          {selection && (
            <div className="graph-selection" data-tone={selection.kind}>
              <p role="status"><span>{selection.kind === 'finding' ? 'Evidence path' : 'Selected entity'}</span> {selection.kind === 'finding' ? selection.finding.category : selection.node.label}</p>
              <a href="#inspector">Inspect selection <ChevronRight size={14} aria-hidden="true" /></a>
            </div>
          )}
          <div className="graph-viewport">
            {data.nodes.length ? (
              <IntelligenceGraph nodes={data.nodes} edges={data.edges} focus={focus} onNodeSelect={onNodeSelect} />
            ) : <p className="graph-empty">The Relate file contains no graph records.</p>}
          </div>
          <ul className="legend" aria-label="Graph node types">
            {legend.map(({ kind, label, Icon }) => (
              <li key={kind} data-kind={kind}><Icon size={15} aria-hidden="true" /> {label}</li>
            ))}
          </ul>
        </section>

        <Inspector
          data={data}
          node={selection?.kind === 'node' ? selection.node : undefined}
          finding={selection?.kind === 'finding' ? selection.finding : undefined}
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

  useEffect(() => {
    const updateSection = () => setActiveSection(sectionFromHash())
    window.addEventListener('hashchange', updateSection)
    return () => window.removeEventListener('hashchange', updateSection)
  }, [])

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
    setRequest({ status: 'loading' })
    setRevision((current) => current + 1)
  }

  const sourceStatus = request.status === 'loaded'
    ? (request.data.source.read_only ? 'Read-only' : 'Connected')
    : request.status === 'loading' ? 'Loading' : 'Unavailable'
  const availableSections = request.status === 'loaded' ? navigation : navigation.slice(0, 1)

  return (
    <>
      <a className="skip-link" href="#main">Skip to dashboard</a>
      <header className="site-header">
        <div className="site-header-inner">
          <a className="brand" href="#overview" aria-label="VARKHARD overview">
            <img className="brand-emblem" src="/varkhard-shield.svg" alt="" width="29" height="33" />
            <span>VARKHARD</span>
          </a>
          <nav className="top-navigation" aria-label="Primary navigation">
            {availableSections.map(({ id, label }) => (
              <a key={id} href={`#${id}`} aria-current={activeSection === id ? 'location' : undefined}>{label}</a>
            ))}
          </nav>
          <div className="header-actions">
            <span className="source-status" data-status={request.status} title={`Relate · ${sourceStatus}`}>
              <span className="source-dot" aria-hidden="true" />
              <span>Relate</span>
              <span className="source-mode">{sourceStatus}</span>
            </span>
            <button className="refresh-button" type="button" onClick={refresh} disabled={request.status === 'loading'}>
              <RefreshCw className={request.status === 'loading' ? 'spinner' : undefined} size={15} aria-hidden="true" />
              Refresh
            </button>
          </div>
        </div>
      </header>

      <main id="main" className="main-content" tabIndex={-1}>
        <Overview data={request.status === 'loaded' ? request.data : undefined} />

        {request.status === 'loaded' && <DashboardContent data={request.data} />}
        {request.status === 'loading' && (
          <div className="panel request-state" role="status">
            <LoaderCircle className="spinner" size={22} aria-hidden="true" /> Loading graph from Relate…
          </div>
        )}
        {request.status === 'error' && (
          <div className="panel request-state" role="alert">
            <TriangleAlert size={24} aria-hidden="true" />
            <strong>Couldn’t load the graph</strong>
            <p>{request.message}</p>
            <button className="refresh-button" type="button" onClick={refresh}>Retry</button>
          </div>
        )}
      </main>
    </>
  )
}
