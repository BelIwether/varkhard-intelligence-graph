import {
  ArrowDownRight, ArrowRight, ArrowUpRight, Bot, Box, ChevronDown, CircleHelp, Crosshair,
  GitFork, History, KeyRound, Link2, Route, ShieldAlert,
} from 'lucide-react'
import { useMemo } from 'react'
import type { Dashboard, EvidenceValue, Finding, GraphEdge, GraphNode, GraphNodeKind, Interaction, Permission } from './api'
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
  granted_actions: 'Current grants',
  approved_actions: 'Baseline-approved actions',
  related_grant_ids: 'Related grants',
  related_baseline_ids: 'Related baseline approvals',
  kind: 'Permission record type',
  outcome: 'Recorded outcome',
  elapsed_seconds: 'Elapsed time (seconds)',
  window_seconds: 'Rule window (seconds)',
  occurred_at: 'Recorded at (UTC)',
}

const contextFields = {
  unauthorized_access: ['agent_id', 'resource_id', 'action', 'outcome', 'granted_actions'],
  excessive_permission: ['agent_id', 'resource_id', 'action', 'kind', 'approved_actions'],
  suspicious_chain: ['sender_agent_id', 'recipient_agent_id', 'source_resource_id', 'destination_resource_id', 'elapsed_seconds', 'window_seconds'],
}

type NodesById = ReadonlyMap<string, GraphNode>
type Investigation = NonNullable<Finding['investigation']>
type InvestigationStep = Investigation['steps'][number]
type StepSelection = { activeStepIndex?: number; onStepSelect?: (index: number) => void }
type StepRecords = {
  nodes: NodesById
  interactions: ReadonlyMap<string, Interaction>
  permissions: ReadonlyMap<string, Permission>
}

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

function stepFacts(step: InvestigationStep, { nodes, interactions, permissions }: StepRecords) {
  const node = step.record_node_id ? nodes.get(step.record_node_id) : undefined
  const kind = node?.kind === 'interaction' || node?.kind === 'permission' ? node.kind : 'unknown'
  const interaction = node?.kind === 'interaction' ? interactions.get(node.record_id) : undefined
  const permission = node?.kind === 'permission' ? permissions.get(node.record_id) : undefined
  const record = interaction ?? permission

  return {
    kind,
    recordId: node?.record_id ?? step.record_node_id,
    agent: record ? nodes.get(`agent:${record.agent_id}`)?.label ?? record.agent_id : null,
    resource: record ? nodes.get(`resource:${record.resource_id}`)?.label ?? record.resource_id : null,
    recipient: interaction?.recipient_id
      ? nodes.get(`agent:${interaction.recipient_id}`)?.label ?? interaction.recipient_id
      : null,
    action: record?.action ?? step.action,
    occurredAt: kind === 'permission' ? null : interaction?.occurred_at ?? step.occurred_at,
    outcome: kind === 'permission' ? null : interaction?.outcome ?? step.outcome,
    permissionKind: permission?.kind,
  }
}

type StepFacts = ReturnType<typeof stepFacts>

function StepRecord({ facts }: { facts: StepFacts }) {
  const occurredAt = facts.occurredAt === null ? null : formatTime(facts.occurredAt)
  const policyLabel = facts.permissionKind === 'baseline' ? 'Baseline approval' : 'Current grant'

  return (
    <div className="inspect-step-facts">
      {facts.kind === 'permission' && (
        <div className="inspect-step-policy">Policy record{facts.permissionKind && <> · {policyLabel}</>}</div>
      )}
      {facts.recordId && <code>{facts.recordId}</code>}
      <dl className="inspect-step-fields">
        <div><dt>Agent</dt><dd>{facts.agent ?? 'Unavailable'}</dd></div>
        <div><dt>Resource</dt><dd>{facts.resource ?? 'Unavailable'}</dd></div>
        <div><dt>Action</dt><dd>{facts.action ?? 'Unavailable'}</dd></div>
        <div>
          <dt>Outcome</dt>
          <dd className={facts.outcome === 'denied' ? 'inspect-denied' : undefined}>
            {facts.outcome ?? 'Unavailable'}
          </dd>
        </div>
        {facts.recipient && <div><dt>Recipient</dt><dd>{facts.recipient}</dd></div>}
        <div className="inspect-step-time">
          <dt>{facts.kind === 'permission' ? 'Event time' : 'Time (UTC)'}</dt>
          <dd>{occurredAt ? <time className="inspect-time" dateTime={occurredAt}>{occurredAt}</time> : 'Unavailable'}</dd>
        </div>
      </dl>
    </div>
  )
}

function TraceAnchor({ label, step, records }: {
  label: string
  step: InvestigationStep | null
  records: StepRecords
}) {
  const facts = step ? stepFacts(step, records) : null
  const occurredAt = facts?.occurredAt != null ? formatTime(facts.occurredAt) : null
  return (
    <div className="inspect-trace-anchor">
      <h5>{label}</h5>
      {step && facts ? (
        <>
          <strong>{step.title}</strong>
          <p>{step.description}</p>
          {facts.recordId && <code>{facts.recordId}</code>}
          {occurredAt && <time className="inspect-time" dateTime={occurredAt}>{occurredAt}</time>}
        </>
      ) : <p>Unavailable in this snapshot.</p>}
    </div>
  )
}

type EvidenceItem = { step: InvestigationStep; index: number; facts: StepFacts }

function EvidenceItems({ items, timeline, activeStepIndex, onStepSelect }: {
  items: EvidenceItem[]
  timeline?: boolean
} & StepSelection) {
  const List = timeline ? 'ol' : 'ul'
  return (
    <List className={timeline ? 'inspect-timeline' : 'inspect-step-list'} role="list">
      {items.map(({ step, index, facts }, row) => {
        const active = index === activeStepIndex
        const title = (
          <>
            {timeline && <span className="inspect-step-number" aria-hidden="true">{row + 1}</span>}
            {facts.kind === 'permission' && <KeyRound size={14} aria-hidden="true" />}
            {facts.kind === 'unknown' && <CircleHelp size={14} aria-hidden="true" />}
            <strong>{step.title}</strong>
            {onStepSelect && <Crosshair size={14} aria-hidden="true" />}
          </>
        )
        return (
          <li className="inspect-step" data-step-kind={facts.kind} data-active={active} key={index}>
            {onStepSelect ? (
              <button className="inspect-step-action" type="button" aria-pressed={active} aria-controls="graph" onClick={() => onStepSelect(index)}>
                {title}
              </button>
            ) : <div className="inspect-step-action">{title}</div>}
            <div className="inspect-step-content">
              <StepRecord facts={facts} />
            </div>
          </li>
        )
      })}
    </List>
  )
}

function EvidenceSteps({ steps, records, activeStepIndex, onStepSelect }: {
  steps: InvestigationStep[]
  records: StepRecords
} & StepSelection) {
  if (!steps.length) return <p className="inspect-muted">No documented evidence steps were established.</p>

  const items = steps.map((step, index) => ({ step, index, facts: stepFacts(step, records) }))
  const events = items.filter(({ facts }) => facts.kind === 'interaction').sort((first, second) => {
    const firstTime = first.facts.occurredAt ?? Number.POSITIVE_INFINITY
    const secondTime = second.facts.occurredAt ?? Number.POSITIVE_INFINITY
    return firstTime === secondTime ? first.index - second.index : firstTime - secondTime
  })
  const policies = items.filter(({ facts }) => facts.kind === 'permission')
  const other = items.filter(({ facts }) => facts.kind === 'unknown')
  const selection = { activeStepIndex, onStepSelect }

  return (
    <div className="inspect-evidence-groups">
      {events.length > 0 && (
        <section className="inspect-evidence-group" aria-labelledby="recorded-event-timeline-title">
          <h5 id="recorded-event-timeline-title">Recorded event timeline</h5>
          <EvidenceItems items={events} timeline {...selection} />
        </section>
      )}
      {policies.length > 0 && (
        <section className="inspect-evidence-group" aria-labelledby="policy-comparison-title">
          <h5 id="policy-comparison-title">Policy comparison</h5>
          <EvidenceItems items={policies} {...selection} />
        </section>
      )}
      {other.length > 0 && (
        <section className="inspect-evidence-group" aria-labelledby="other-evidence-title">
          <h5 id="other-evidence-title">Other evidence</h5>
          <EvidenceItems items={other} {...selection} />
        </section>
      )}
    </div>
  )
}

function TraceRecords({ investigation, nodes, edges }: {
  investigation: Investigation
  nodes: NodesById
  edges: ReadonlyMap<string, GraphEdge>
}) {
  const entities = investigation.affected_node_ids.flatMap((id) => {
    const node = nodes.get(id)
    return node ? [node] : []
  })
  const relationships = investigation.edge_ids.flatMap((id) => {
    const edge = edges.get(id)
    return edge ? [edge] : []
  })

  return (
    <>
      <details className="inspect-disclosure">
        <summary>
          Affected entities <span>{entities.length}</span>
          <ChevronDown size={15} aria-hidden="true" />
        </summary>
        {entities.length ? (
          <ul className="inspect-trace-records">
            {entities.map((node) => {
              const { label, Icon } = nodeKinds[node.kind]
              return (
                <li key={node.id}>
                  <Icon size={15} aria-hidden="true" />
                  <div>
                    <strong>{node.label}</strong>
                    <span>{label}</span>
                    <code>{node.record_id}</code>
                  </div>
                </li>
              )
            })}
          </ul>
        ) : <p className="inspect-muted">No affected entities resolved.</p>}
      </details>
      <details className="inspect-disclosure">
        <summary>
          Path relationships <span>{relationships.length}</span>
          <ChevronDown size={15} aria-hidden="true" />
        </summary>
        {relationships.length ? (
          <ul className="inspect-trace-records">
            {relationships.map((edge) => (
              <li key={edge.id}>
                <ArrowRight size={15} aria-hidden="true" />
                <div>
                  <strong>{relationshipLabels[edge.kind]}</strong>
                  <span>{nodes.get(edge.source)?.label ?? edge.source} → {nodes.get(edge.target)?.label ?? edge.target}</span>
                  <code>{edge.id}</code>
                </div>
              </li>
            ))}
          </ul>
        ) : <p className="inspect-muted">No graph relationships resolved.</p>}
      </details>
    </>
  )
}

function FindingDetails({ finding, records, edges, activeStepIndex, onStepSelect }: {
  finding: Finding
  records: StepRecords
  edges: ReadonlyMap<string, GraphEdge>
} & StepSelection) {
  const { investigation, evidence, rule_id: rule } = finding
  const { nodes } = records
  const Icon = ruleIcons[rule] ?? ShieldAlert
  const fields = Object.fromEntries(
    (contextFields[rule] ?? []).filter((key) => Object.hasOwn(evidence, key)).map((key) => [key, evidence[key]]),
  )

  return (
    <>
      <div className="inspect-focus inspect-focus--finding">
        <div className="inspect-kind"><Icon size={15} aria-hidden="true" /> Security finding</div>
        <h3>{finding.category}</h3>
        <div className="inspect-cause"><CircleHelp size={15} aria-hidden="true" /> Root cause not established</div>
      </div>
      <section className="inspect-section" aria-labelledby="rule-interpretation-title">
        <h4 id="rule-interpretation-title">Rule interpretation</h4>
        <p className="inspect-muted">{finding.explanation}</p>
      </section>
      <section className="inspect-section" aria-labelledby="documented-trace-title">
        <h4 id="documented-trace-title"><Route size={15} aria-hidden="true" /> Documented trace</h4>
        {investigation ? (
          <>
            <div className="inspect-trace-summary">
              <span>{investigation.complete ? 'Evidence trace complete' : 'Partial evidence trace'}</span>
              <a href="#investigation-tools" className="inspect-graph-link">Investigation controls <ArrowUpRight size={14} aria-hidden="true" /></a>
            </div>
            <div className="inspect-trace-anchors">
              <TraceAnchor label="Earliest supported evidence" step={investigation.origin} records={records} />
              <TraceAnchor label="Trigger" step={investigation.trigger} records={records} />
            </div>
          </>
        ) : <p className="inspect-muted">A structured trace is unavailable from this source.</p>}
      </section>
      {investigation && (
        <section className="inspect-section" aria-labelledby="evidence-steps-title">
          <h4 id="evidence-steps-title">
            Evidence steps <span>{investigation.steps.length}</span>
          </h4>
          <EvidenceSteps steps={investigation.steps} records={records} activeStepIndex={activeStepIndex} onStepSelect={onStepSelect} />
        </section>
      )}
      {Object.keys(fields).length > 0 && (
        <section className="inspect-section" aria-labelledby="recorded-context-title">
          <h4 id="recorded-context-title">Recorded context</h4>
          <EvidenceFields evidence={fields} nodes={nodes} rule={rule} />
        </section>
      )}
      <section className="inspect-section inspect-records-section" aria-label="Evidence records">
        {investigation && <TraceRecords investigation={investigation} nodes={nodes} edges={edges} />}
        <details className="inspect-disclosure">
          <summary>Supporting records <ChevronDown size={15} aria-hidden="true" /></summary>
          {Object.keys(evidence).length ? (
            <EvidenceFields evidence={evidence} nodes={nodes} rule={rule} />
          ) : <p className="inspect-muted">No supporting records were supplied.</p>}
        </details>
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

export function Inspector({ data, node, finding, hidden, onNodeSelect, activeStepIndex, onStepSelect }: {
  data: Dashboard
  node?: GraphNode
  finding?: Finding
  hidden?: boolean
  onNodeSelect: (node: GraphNode) => void
} & StepSelection) {
  const nodes = useMemo(() => new Map(data.nodes.map((entry) => [entry.id, entry])), [data.nodes])
  const records = useMemo(() => ({
    nodes,
    interactions: new Map(data.interactions.map((record) => [record.id, record])),
    permissions: new Map(data.permissions.map((record) => [record.id, record])),
  }), [nodes, data.interactions, data.permissions])
  const edges = useMemo(() => new Map(data.edges.map((entry) => [entry.id, entry])), [data.edges])
  const shortcuts = useMemo(() => data.nodes.filter((entry) => entry.kind === 'agent').slice(0, 3), [data.nodes])

  return (
    <section className="panel investigation-inspector" id="inspector" aria-labelledby="inspector-title" hidden={hidden}>
      <header className="inspect-header">
        <div className="inspect-heading">
          <span className="inspect-header-icon"><Crosshair size={17} aria-hidden="true" /></span>
          <h2 id="inspector-title">Inspector</h2>
        </div>
        {node && <a href="#graph" className="inspect-graph-link">View graph <ArrowUpRight size={14} aria-hidden="true" /></a>}
      </header>
      <div className="inspect-body" key={finding?.id ?? node?.id} tabIndex={0} role="region" aria-label="Inspector details">
        {finding && (
          <FindingDetails
            finding={finding}
            records={records}
            edges={edges}
            activeStepIndex={activeStepIndex}
            onStepSelect={onStepSelect}
          />
        )}
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
      </div>
    </section>
  )
}
