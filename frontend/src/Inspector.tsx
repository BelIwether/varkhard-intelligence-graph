import {
  ArrowDownRight, ArrowRight, ArrowUpRight, Bot, Box, ChevronDown, Crosshair,
  GitFork, History, KeyRound, Link2, ShieldAlert,
} from 'lucide-react'
import type { Dashboard, EvidenceValue, Finding, GraphNode, GraphNodeKind } from './api'
import './inspector.css'

const nodeKinds = {
  agent: { label: 'AI agent', Icon: Bot },
  resource: { label: 'Resource', Icon: Box },
  permission: { label: 'Permission', Icon: KeyRound },
  interaction: { label: 'Action', Icon: History },
}

const ruleIcons = { unauthorized_access: ShieldAlert, excessive_permission: KeyRound, suspicious_chain: GitFork }

const relationshipLabels = {
  HAS_PERMISSION: 'Has permission',
  ON_RESOURCE: 'On resource',
  PERFORMED: 'Performed',
  TARGETS: 'Targets',
  HANDED_TO: 'Handed to',
  TRIGGERS: 'Triggers',
}

const referenceKinds: Partial<Record<string, GraphNodeKind>> = {
  agent_id: 'agent',
  sender_agent_id: 'agent',
  recipient_agent_id: 'agent',
  resource_id: 'resource',
  source_resource_id: 'resource',
  destination_resource_id: 'resource',
  permission_id: 'permission',
  related_grant_ids: 'permission',
  related_baseline_ids: 'permission',
  interaction_id: 'interaction',
  interaction_ids: 'interaction',
}

const evidenceLabels: Partial<Record<string, string>> = {
  granted_actions: 'Granted actions',
  approved_actions: 'Baseline-approved actions',
  related_grant_ids: 'Related grants',
  related_baseline_ids: 'Related baseline approvals',
  elapsed_seconds: 'Elapsed time (seconds)',
  window_seconds: 'Rule window (seconds)',
  occurred_at: 'Recorded at (UTC)',
}

type NodesById = ReadonlyMap<string, GraphNode>

function labelFor(key: string, rule?: Finding['rule_id']) {
  if (key === 'action' && rule === 'unauthorized_access') return 'Requested action'
  if (key === 'action' && rule === 'excessive_permission') return 'Granted action'

  const spaced = key.replaceAll('_', ' ').replace(/\bid(s?)\b/g, 'ID$1')
  return evidenceLabels[key] ?? (spaced.charAt(0).toUpperCase() + spaced.slice(1))
}

function formatTime(seconds: number) {
  return new Date(seconds * 1000).toISOString().replace('.000Z', 'Z')
}

function EvidenceEntry({ field, value, nodes }: { field: string; value: EvidenceValue; nodes: NodesById }) {
  if (value === null) return <span className="inspect-muted">None recorded</span>
  if (Array.isArray(value)) {
    if (!value.length) return <span className="inspect-muted">None recorded</span>
    return (
      <ul className="inspect-evidence-list">
        {value.map((item, index) => (
          <li key={index}><EvidenceEntry field={field} value={item} nodes={nodes} /></li>
        ))}
      </ul>
    )
  }
  if (typeof value === 'object') return <EvidenceFields evidence={value} nodes={nodes} />
  if (typeof value === 'string' && field === 'occurred_at') {
    return <time className="inspect-time" dateTime={value}>{value}</time>
  }
  if (typeof value === 'string' && /(^|_)ids?$/.test(field)) {
    const kind = referenceKinds[field]
    const node = kind ? nodes.get(`${kind}:${value}`) : undefined
    return (
      <span className="inspect-reference">
        {node && node.label !== value && <span>{node.label}</span>}
        <code>{value}</code>
      </span>
    )
  }
  return <span>{String(value)}</span>
}

function EvidenceFields({ evidence, nodes, rule }: {
  evidence: Record<string, EvidenceValue>
  nodes: NodesById
  rule?: Finding['rule_id']
}) {
  return (
    <dl className="inspect-fields">
      {Object.entries(evidence).map(([key, value]) => (
        <div key={key}>
          <dt>{labelFor(key, rule)}</dt>
          <dd><EvidenceEntry field={key} value={value} nodes={nodes} /></dd>
        </div>
      ))}
    </dl>
  )
}

function InteractionSequence({ events, nodes }: { events: EvidenceValue; nodes: NodesById }) {
  if (!Array.isArray(events) || !events.length) {
    return <EvidenceEntry field="interactions" value={events} nodes={nodes} />
  }

  return (
    <ol className="inspect-timeline">
      {events.map((event, index) => {
        if (event === null || typeof event !== 'object' || Array.isArray(event)) {
          return <li key={index}><EvidenceEntry field="interactions" value={event} nodes={nodes} /></li>
        }

        const { action, occurred_at, ...fields } = event
        return (
          <li key={typeof event.interaction_id === 'string' ? event.interaction_id : index}>
            <details className="inspect-event">
              <summary>
                <span className="inspect-event-label">
                  <strong>{typeof action === 'string' ? action : 'Action record'}</strong>
                  {typeof occurred_at === 'string' && (
                    <time className="inspect-time" dateTime={occurred_at}>{occurred_at}</time>
                  )}
                </span>
                <ChevronDown size={15} aria-hidden="true" />
              </summary>
              <EvidenceFields evidence={fields} nodes={nodes} />
            </details>
          </li>
        )
      })}
    </ol>
  )
}

function FindingDetails({ finding, nodes }: { finding: Finding; nodes: NodesById }) {
  const { interactions, ...fields } = finding.evidence
  const Icon = ruleIcons[finding.rule_id] ?? ShieldAlert
  const nodeCount = finding.node_ids.length
  const edgeCount = finding.edge_ids.length
  const hasFields = Object.keys(fields).length > 0

  return (
    <>
      <div className="inspect-focus inspect-focus--finding">
        <div className="inspect-kind"><Icon size={15} aria-hidden="true" /> Security finding</div>
        <h3>{finding.category}</h3>
        <p>{finding.explanation}</p>
        <div className="inspect-path">
          <Link2 size={16} aria-hidden="true" />
          <div>
            <strong>Graph evidence</strong>
            <span>{nodeCount} {nodeCount === 1 ? 'node' : 'nodes'} · {edgeCount} {edgeCount === 1 ? 'relationship' : 'relationships'}</span>
          </div>
          <a href="#graph" aria-label="View highlighted evidence in graph"><ArrowUpRight size={16} aria-hidden="true" /></a>
        </div>
      </div>
      <section className="inspect-section" aria-labelledby="evidence-title">
        <h4 id="evidence-title">Evidence</h4>
        {interactions !== undefined && (
          <div className="inspect-sequence">
            <h5>Interaction sequence</h5>
            <InteractionSequence events={interactions} nodes={nodes} />
          </div>
        )}
        {hasFields && <EvidenceFields evidence={fields} nodes={nodes} rule={finding.rule_id} />}
        {interactions === undefined && !hasFields && <p className="inspect-muted">No evidence records.</p>}
      </section>
    </>
  )
}

function RecordRow({ title, scope, recordId, tag, time, denied, node, onNodeSelect }: {
  title: string
  scope: string
  recordId: string
  tag: string
  time?: string
  denied?: boolean
  node?: GraphNode
  onNodeSelect: (node: GraphNode) => void
}) {
  return (
    <li className="inspect-record">
      <div className="inspect-record-label">
        <strong>{title}</strong>
        <span>{scope}</span>
        <code>{recordId}</code>
        {time && <time className="inspect-time" dateTime={time}>{time}</time>}
      </div>
      <span className={denied ? 'inspect-tag inspect-tag--denied' : 'inspect-tag'}>{tag}</span>
      {node && (
        <button type="button" className="inspect-record-action" onClick={() => onNodeSelect(node)} aria-label={`Inspect ${recordId}`}>
          <ArrowUpRight size={16} aria-hidden="true" />
        </button>
      )}
    </li>
  )
}

function NodeDetails({ data, node, nodes, onNodeSelect }: {
  data: Dashboard
  node: GraphNode
  nodes: NodesById
  onNodeSelect: (node: GraphNode) => void
}) {
  const id = node.record_id
  const permissions = data.permissions.filter((permission) =>
    (node.kind === 'agent' && permission.agent_id === id)
    || (node.kind === 'resource' && permission.resource_id === id)
    || (node.kind === 'permission' && permission.id === id))
  const interactions = data.interactions.filter((interaction) =>
    (node.kind === 'agent' && (interaction.agent_id === id || interaction.recipient_id === id))
    || (node.kind === 'resource' && interaction.resource_id === id)
    || (node.kind === 'interaction' && interaction.id === id))
    .sort((first, second) => second.occurred_at - first.occurred_at)

  const relationships = data.edges.flatMap((edge) => {
    if (edge.source !== node.id && edge.target !== node.id) return []
    const outgoing = edge.source === node.id
    const other = nodes.get(outgoing ? edge.target : edge.source)
    return other ? [{ edge, other, outgoing }] : []
  })
  const resource = node.kind === 'resource' ? data.resources.find((entry) => entry.id === id) : undefined
  const { label, Icon } = nodeKinds[node.kind]

  return (
    <>
      <div className="inspect-focus">
        <div className="inspect-kind"><Icon size={15} aria-hidden="true" /> {label}</div>
        <h3>{node.label}</h3>
        <code>{id}</code>
        {resource && (
          <EvidenceFields evidence={{ classification: resource.classification, boundary: resource.boundary }} nodes={nodes} />
        )}
      </div>
      {node.kind !== 'interaction' && (
        <section className="inspect-section" aria-labelledby="permission-title">
          <h4 id="permission-title"><KeyRound size={15} aria-hidden="true" /> Permissions <span>{permissions.length}</span></h4>
          {permissions.length ? (
            <ul className="inspect-records">
              {permissions.map((permission) => {
                const scope = node.kind === 'resource'
                  ? nodes.get(`agent:${permission.agent_id}`)?.label ?? permission.agent_id
                  : nodes.get(`resource:${permission.resource_id}`)?.label ?? permission.resource_id
                return (
                  <RecordRow
                    key={permission.id}
                    title={permission.action}
                    scope={scope}
                    recordId={permission.id}
                    tag={permission.kind}
                    onNodeSelect={onNodeSelect}
                    node={node.kind !== 'permission' ? nodes.get(`permission:${permission.id}`) : undefined}
                  />
                )
              })}
            </ul>
          ) : <p className="inspect-muted">No permission records.</p>}
        </section>
      )}
      {node.kind !== 'permission' && (
        <section className="inspect-section" aria-labelledby="action-title">
          <h4 id="action-title"><History size={15} aria-hidden="true" /> Recorded actions <span>{interactions.length}</span></h4>
          {interactions.length ? (
            <ul className="inspect-records">
              {interactions.map((interaction) => {
                const showAgent = node.kind === 'resource' || (node.kind === 'agent' && interaction.recipient_id === id)
                const scope = showAgent
                  ? nodes.get(`agent:${interaction.agent_id}`)?.label ?? interaction.agent_id
                  : nodes.get(`resource:${interaction.resource_id}`)?.label ?? interaction.resource_id
                return (
                  <RecordRow
                    key={interaction.id}
                    title={interaction.action}
                    scope={scope}
                    recordId={interaction.id}
                    tag={interaction.outcome}
                    time={formatTime(interaction.occurred_at)}
                    denied={interaction.outcome === 'denied'}
                    onNodeSelect={onNodeSelect}
                    node={node.kind !== 'interaction' ? nodes.get(`interaction:${interaction.id}`) : undefined}
                  />
                )
              })}
            </ul>
          ) : <p className="inspect-muted">No action records.</p>}
        </section>
      )}
      <section className="inspect-section" aria-labelledby="relationship-title">
        <h4 id="relationship-title"><Link2 size={15} aria-hidden="true" /> Relationships <span>{relationships.length}</span></h4>
        {relationships.length ? (
          <ul className="inspect-relationships">
            {relationships.map(({ edge, other, outgoing }) => (
              <li key={edge.id}>
                <button type="button" onClick={() => onNodeSelect(other)}>
                  <span>
                    <span className="inspect-muted">{outgoing ? 'Outgoing' : 'Incoming'} · {relationshipLabels[edge.kind]}</span>
                    <strong>{other.label}</strong>
                  </span>
                  <ArrowUpRight size={16} aria-hidden="true" />
                </button>
              </li>
            ))}
          </ul>
        ) : <p className="inspect-muted">No relationships.</p>}
      </section>
    </>
  )
}

export function Inspector({ data, node, finding, onNodeSelect }: {
  data: Dashboard
  node?: GraphNode
  finding?: Finding
  onNodeSelect: (node: GraphNode) => void
}) {
  const nodes = new Map(data.nodes.map((entry) => [entry.id, entry]))
  const shortcuts = data.nodes.filter((entry) => entry.kind === 'agent').slice(0, 3)

  return (
    <section className="panel investigation-inspector" id="inspector" aria-labelledby="inspector-title">
      <header className="inspect-header">
        <div className="inspect-heading">
          <span className="inspect-header-icon"><Crosshair size={17} aria-hidden="true" /></span>
          <h2 id="inspector-title">Inspector</h2>
        </div>
        {node && <a href="#graph" className="inspect-graph-link">View graph <ArrowUpRight size={14} aria-hidden="true" /></a>}
      </header>
      {finding && <FindingDetails finding={finding} nodes={nodes} />}
      {node && <NodeDetails data={data} node={node} nodes={nodes} onNodeSelect={onNodeSelect} />}
      {!node && !finding && (
        <>
          <div className="inspect-empty">
            <ArrowDownRight size={18} aria-hidden="true" />
            <div>
              <h3>Select a finding or node</h3>
              <p>Review evidence for a finding or inspect a node’s records and relationships.</p>
            </div>
          </div>
          {shortcuts.length > 0 && (
            <section className="inspect-section" aria-labelledby="inspect-agents-title">
              <h4 id="inspect-agents-title">Explore AI agents</h4>
              <ul className="inspect-shortcuts">
                {shortcuts.map((agent) => (
                  <li key={agent.id}>
                    <button type="button" onClick={() => onNodeSelect(agent)}>
                      <Bot size={15} aria-hidden="true" />
                      <span>{agent.label}</span>
                      <ArrowRight size={15} aria-hidden="true" />
                    </button>
                  </li>
                ))}
              </ul>
            </section>
          )}
        </>
      )}
    </section>
  )
}
