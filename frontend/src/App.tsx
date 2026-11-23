import { useEffect, useState } from 'react'
import {
  ArrowUpRight, Bot, Box, Database, GitFork, History, KeyRound, Link2,
  LoaderCircle, Network, RefreshCw, ShieldAlert, ShieldCheck, TriangleAlert,
} from 'lucide-react'
import { getDashboard } from './api'
import type { Dashboard, Finding, GraphEdge, GraphNode, GraphNodeKind } from './api'
import { IntelligenceGraph } from './IntelligenceGraph'
import { Inspector } from './Inspector'

const nodeIcons = { agent: Bot, resource: Box, permission: KeyRound, interaction: History }
const nodeLabels = { agent: 'Agent', resource: 'Resource', permission: 'Permission', interaction: 'Action' }
const findingIcons = { unauthorized_access: ShieldAlert, excessive_permission: KeyRound, suspicious_chain: GitFork }

type RequestState = { status: 'loading' } | { status: 'loaded'; data: Dashboard } | { status: 'error'; message: string }
type Selection = { kind: 'node'; node: GraphNode } | { kind: 'finding'; finding: Finding }

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

function FindingCard({ finding, data, selected, onSelect }: {
  finding: Finding
  data: Dashboard
  selected: boolean
  onSelect: () => void
}) {
  const Icon = findingIcons[finding.rule_id] ?? ShieldAlert
  const agentName = (id: unknown) => data.agents.find((agent) => agent.id === id)?.name
  const agent = agentName(finding.evidence.agent_id)
  const action = finding.evidence.action
  const sender = agentName(finding.evidence.sender_agent_id)
  const recipient = agentName(finding.evidence.recipient_agent_id)
  const summary = sender && recipient ? `${sender} → ${recipient}`
    : agent && typeof action === 'string' ? `${agent} · ${action}` : undefined

  return (
    <button className="finding-card" type="button" onClick={onSelect} aria-pressed={selected} aria-controls="inspector">
      <span className="finding-icon"><Icon size={17} aria-hidden="true" /></span>
      <span className="finding-label">
        <strong>{finding.category}</strong>
        {summary && <span>{summary}</span>}
      </span>
    </button>
  )
}

function DashboardContent({ data }: { data: Dashboard }) {
  const [selection, setSelection] = useState<Selection | null>(null)
  const focus = graphFocus(selection, data.edges)
  const selectedAgent = selection?.kind === 'node' && selection.node.kind === 'agent' ? selection.node.id : ''
  const onNodeSelect = (node: GraphNode) => setSelection({ kind: 'node', node })

  return (
    <>
      <dl className="metrics" aria-label="Graph summary">
        {[
          { label: 'AI agents', count: data.agents.length, Icon: Bot },
          { label: 'Resources', count: data.resources.length, Icon: Box },
          { label: 'Relationships', count: data.edges.length, Icon: Link2 },
          { label: 'Security findings', count: data.findings.length, Icon: ShieldAlert },
        ].map(({ label, count, Icon }) => (
          <div className="metric" key={label}>
            <dt><Icon size={17} aria-hidden="true" /> {label}</dt>
            <dd>{count.toLocaleString('en')}</dd>
          </div>
        ))}
      </dl>

      <div className="workspace">
        <section className="panel graph-panel" id="graph" aria-labelledby="graph-title">
          <header className="panel-heading graph-heading">
            <div>
              <h2 id="graph-title"><Network size={19} aria-hidden="true" /> Intelligence graph</h2>
              <p>Explore relationships between agents, resources, and records.</p>
            </div>
            <select
              aria-label="Select an AI agent"
              aria-controls="inspector"
              value={selectedAgent}
              disabled={!data.agents.length}
              onChange={(event) => {
                const node = data.nodes.find(({ id }) => id === event.target.value)
                if (node) onNodeSelect(node)
                else setSelection(null)
              }}
            >
              <option value="">Select an agent</option>
              {data.agents.map((agent) => <option key={agent.id} value={`agent:${agent.id}`}>{agent.name}</option>)}
            </select>
          </header>
          <div className="graph-viewport">
            {data.nodes.length ? (
              <IntelligenceGraph nodes={data.nodes} edges={data.edges} focus={focus} onNodeSelect={onNodeSelect} />
            ) : <p className="graph-empty">The Relate file contains no graph records.</p>}
          </div>
          <div className="graph-footer">
            <ul className="legend" aria-label="Graph node types">
              {(Object.keys(nodeIcons) as GraphNodeKind[]).map((kind) => {
                const Icon = nodeIcons[kind]
                return <li key={kind}><Icon size={15} aria-hidden="true" /> {nodeLabels[kind]}</li>
              })}
            </ul>
            {selection && (
              <div className="selection-actions">
                <a className="text-button inspect-selection" href="#inspector">Inspect selection <ArrowUpRight size={13} aria-hidden="true" /></a>
                <button className="text-button" type="button" onClick={() => setSelection(null)}>Clear highlight</button>
              </div>
            )}
          </div>
        </section>

        <aside className="side-panels" aria-label="Findings and details">
          <section className="panel findings-panel" id="findings" aria-labelledby="findings-title">
            <header className="panel-heading findings-heading">
              <h2 id="findings-title"><ShieldAlert size={19} aria-hidden="true" /> Security findings</h2>
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

          <Inspector
            data={data}
            node={selection?.kind === 'node' ? selection.node : undefined}
            finding={selection?.kind === 'finding' ? selection.finding : undefined}
            onNodeSelect={onNodeSelect}
          />
        </aside>
      </div>
    </>
  )
}

export default function App() {
  const [request, setRequest] = useState<RequestState>({ status: 'loading' })
  const [revision, setRevision] = useState(0)

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

  function refresh() {
    setRequest({ status: 'loading' })
    setRevision((current) => current + 1)
  }

  return (
    <>
      <a className="skip-link" href="#main">Skip to dashboard</a>
      <header className="site-header">
        <div className="site-header-inner">
          <a className="brand" href="#main">
            <span className="brand-logo-slot" aria-hidden="true" />
            VARKHARD
          </a>
          {request.status === 'loaded' && (
            <nav aria-label="Dashboard">
              <a href="#graph">Graph</a>
              <a href="#findings">Findings</a>
            </nav>
          )}
          <button className="refresh-button" type="button" onClick={refresh} disabled={request.status === 'loading'}>
            <RefreshCw size={15} aria-hidden="true" /> Refresh
          </button>
        </div>
      </header>

      <main id="main" className="main-content">
        <div className="page-intro">
          <div>
            <h1>Security dashboard</h1>
            <p>Trace AI agent activity, review permissions, and investigate findings.</p>
          </div>
          {request.status === 'loaded' && (
            <div className="source-status">
              <Database size={17} aria-hidden="true" />
              <div><strong>Relate Single File</strong><span>{request.data.source.filename}</span></div>
              {request.data.source.read_only && <span className="source-mode">Read-only</span>}
            </div>
          )}
        </div>

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
