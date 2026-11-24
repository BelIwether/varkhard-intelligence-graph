import { Crosshair, History, KeyRound, Link2 } from 'lucide-react'
import type { ReactNode } from 'react'
import type { Dashboard, EvidenceValue, Finding, GraphNode, Interaction, Permission } from './api'

const nodeKinds = { agent: 'AI agent', resource: 'Resource', permission: 'Permission', interaction: 'Action' }
const relationshipLabels = {
  HAS_PERMISSION: 'Has permission',
  ON_RESOURCE: 'On resource',
  PERFORMED: 'Performed',
  TARGETS: 'Targets',
  HANDED_TO: 'Handed to',
  TRIGGERS: 'Triggers',
}

function labelFor(key: string) {
  const spaced = key.replaceAll('_', ' ').replace(/\bid(s?)\b/g, 'ID$1')
  return spaced.charAt(0).toUpperCase() + spaced.slice(1)
}

function formatTime(seconds: number) {
  return new Date(seconds * 1000).toISOString().replace('.000Z', 'Z')
}

function EvidenceEntry({ value }: { value: EvidenceValue }): ReactNode {
  if (value === null) return <span className="muted">None</span>
  if (Array.isArray(value)) {
    if (!value.length) return <span className="muted">None recorded</span>
    return <ol className="evidence-list">{value.map((entry, index) => <li key={index}><EvidenceEntry value={entry} /></li>)}</ol>
  }
  if (typeof value === 'object') return <EvidenceFields evidence={value} />
  return <span>{String(value)}</span>
}

function EvidenceFields({ evidence }: { evidence: Record<string, EvidenceValue> }) {
  return (
    <dl className="evidence-fields">
      {Object.entries(evidence).map(([key, value]) => (
        <div key={key} className={key.endsWith('_id') || key.endsWith('_ids') ? 'evidence-id' : undefined}>
          <dt>{labelFor(key)}</dt>
          <dd><EvidenceEntry value={value} /></dd>
        </div>
      ))}
    </dl>
  )
}

function PermissionDetails({ permission, scope, onSelect }: {
  permission: Permission
  scope: string
  onSelect?: () => void
}) {
  return (
    <div className="record-row">
      <div><strong>{permission.action}</strong><span>{scope}</span></div>
      <span className="record-tag">{permission.kind}</span>
      {onSelect && <button type="button" className="icon-button" onClick={onSelect} aria-label={`Inspect permission ${permission.id}`}><Crosshair size={15} aria-hidden="true" /></button>}
    </div>
  )
}

function InteractionDetails({ interaction, scope, onSelect }: {
  interaction: Interaction
  scope: string
  onSelect?: () => void
}) {
  const time = formatTime(interaction.occurred_at)
  return (
    <div className="record-row">
      <div><strong>{interaction.action}</strong><span>{scope}</span><time dateTime={time}>{time}</time></div>
      <span className={`record-tag ${interaction.outcome === 'denied' ? 'record-denied' : ''}`}>{interaction.outcome}</span>
      {onSelect && <button type="button" className="icon-button" onClick={onSelect} aria-label={`Inspect action ${interaction.id}`}><Crosshair size={15} aria-hidden="true" /></button>}
    </div>
  )
}

function NodeDetails({ data, node, onNodeSelect }: {
  data: Dashboard
  node: GraphNode
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
  const edges = data.edges.filter(({ source, target }) => source === node.id || target === node.id)
  const nodes = new Map(data.nodes.map((entry) => [entry.id, entry]))
  const agents = new Map(data.agents.map(({ id, name }) => [id, name]))
  const resources = new Map(data.resources.map(({ id, name }) => [id, name]))
  const resource = node.kind === 'resource' ? data.resources.find((entry) => entry.id === id) : undefined
  const standalone = node.kind === 'permission' || node.kind === 'interaction'
  function selectRecord(record: GraphNode | undefined) {
    if (record) onNodeSelect(record)
  }

  return (
    <>
      <div className="detail-title">
        <p>{nodeKinds[node.kind]}</p>
        <h3>{node.label}</h3>
        <code>{id}</code>
      </div>
      {resource && (
        <dl className="evidence-fields">
          <div><dt>Classification</dt><dd>{resource.classification}</dd></div>
          <div><dt>Boundary</dt><dd>{resource.boundary}</dd></div>
        </dl>
      )}
      {node.kind !== 'interaction' && (
        <section className="detail-section" aria-labelledby="permission-title">
          <h4 id="permission-title"><KeyRound size={15} aria-hidden="true" /> Permissions</h4>
          {permissions.length ? permissions.map((permission) => (
            <PermissionDetails
              key={permission.id}
              permission={permission}
              scope={node.kind === 'resource'
                ? agents.get(permission.agent_id) ?? permission.agent_id
                : resources.get(permission.resource_id) ?? permission.resource_id}
              onSelect={standalone ? undefined : () => selectRecord(nodes.get(`permission:${permission.id}`))}
            />
          )) : <p className="muted">No permission records.</p>}
        </section>
      )}
      {node.kind !== 'permission' && (
        <section className="detail-section" aria-labelledby="action-title">
          <h4 id="action-title"><History size={15} aria-hidden="true" /> Actions</h4>
          {interactions.length ? interactions.map((interaction) => (
            <InteractionDetails
              key={interaction.id}
              interaction={interaction}
              scope={node.kind === 'resource' || (node.kind === 'agent' && interaction.recipient_id === id)
                ? agents.get(interaction.agent_id) ?? interaction.agent_id
                : resources.get(interaction.resource_id) ?? interaction.resource_id}
              onSelect={standalone ? undefined : () => selectRecord(nodes.get(`interaction:${interaction.id}`))}
            />
          )) : <p className="muted">No action records.</p>}
        </section>
      )}
      <section className="detail-section" aria-labelledby="relationship-title">
        <h4 id="relationship-title"><Link2 size={15} aria-hidden="true" /> Relationships</h4>
        {edges.length ? (
          <ul className="relationship-list">
            {edges.map((edge) => {
              const outgoing = edge.source === node.id
              const other = nodes.get(outgoing ? edge.target : edge.source)
              if (!other) return null
              return (
                <li key={edge.id}>
                  <span>{outgoing ? '→' : '←'} {relationshipLabels[edge.kind]}</span>
                  <button type="button" className="text-button" onClick={() => onNodeSelect(other)}>{other.label}</button>
                </li>
              )
            })}
          </ul>
        ) : <p className="muted">No relationships.</p>}
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
  return (
    <section className="panel inspector" id="inspector" aria-labelledby="inspector-title">
      <header className="panel-heading inspector-heading">
        <h2 id="inspector-title"><Crosshair size={19} aria-hidden="true" /> Inspector</h2>
        {(finding || node) && <a href="#graph" className="text-button">View graph</a>}
      </header>
      <div className="inspector-content">
        {finding && (
          <>
            <div className="detail-title finding-detail">
              <h3>{finding.category}</h3>
              <p>{finding.explanation}</p>
            </div>
            <section className="detail-section" aria-labelledby="evidence-title">
              <h4 id="evidence-title">Evidence</h4>
              <EvidenceFields evidence={finding.evidence} />
            </section>
          </>
        )}
        {node && <NodeDetails data={data} node={node} onNodeSelect={onNodeSelect} />}
        {!node && !finding && (
          <div className="inspector-welcome">
            <span className="inspector-overline">INVESTIGATION CONSOLE</span>
            <div className="inspector-welcome-icon"><Crosshair size={22} aria-hidden="true" /></div>
            <h3>Start an investigation</h3>
            <p>Choose a graph node or a security finding to examine its records, relationships and evidence.</p>
            <div className="inspector-snapshot">
              <div><span>AI agents</span><strong>{data.agents.length}</strong></div>
              <div><span>Recorded actions</span><strong>{data.interactions.length}</strong></div>
              <div><span>Findings</span><strong>{data.findings.length}</strong></div>
            </div>
            {data.agents.length > 0 && (
              <div className="inspector-shortcuts">
                <span className="inspector-overline">QUICK ACCESS / AGENTS</span>
                {data.agents.slice(0, 3).map((agent) => {
                  const graphNode = data.nodes.find((entry) => entry.id === `agent:${agent.id}`)
                  return graphNode && (
                    <button key={agent.id} type="button" onClick={() => onNodeSelect(graphNode)}>
                      <span>{agent.name}</span><span aria-hidden="true">↗</span>
                    </button>
                  )
                })}
              </div>
            )}
          </div>
        )}
      </div>
    </section>
  )
}
