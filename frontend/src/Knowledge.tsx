import { useEffect, useRef, useState, type FormEvent } from 'react'
import { FileCheck, FileText, KeyRound, RefreshCw, ShieldAlert } from 'lucide-react'
import { knowledgeRequest, KnowledgeRequestError } from './knowledgeApi'
import type {
  KnowledgeAdvisory, KnowledgeCandidate, KnowledgeIncident, KnowledgeRequest, KnowledgeSession,
} from './knowledgeApi'
import './knowledge.css'

type AdvisoryVersion = Pick<KnowledgeAdvisory, 'id' | 'version'>
type Library = {
  session: KnowledgeSession
  candidates: KnowledgeCandidate[]
  candidatesUnavailable: boolean
  incidents: KnowledgeIncident[]
  advisories: KnowledgeAdvisory[]
  selected?: KnowledgeAdvisory
}
type Connection = { request: KnowledgeRequest; controller: AbortController; pending: boolean }

const ruleLabels = {
  unauthorized_access: 'Unauthorized Access',
  excessive_permission: 'Excessive Permission',
  suspicious_chain: 'Suspicious Chain',
}

const statuses = {
  draft: 'Draft',
  in_review: 'In review',
  approved: 'Approved',
  rejected: 'Rejected',
}

const auditActions: Record<string, string> = {
  create: 'Draft created',
  submit: 'Submitted for review',
  approve: 'Approved',
  reject: 'Rejected',
  new_version: 'New version created',
}

function advisoryPath(id: string) {
  return `advisories/${encodeURIComponent(id)}/versions`
}

function versionPath({ id, version }: AdvisoryVersion) {
  return `${advisoryPath(id)}/${version}`
}

async function loadLibrary(request: KnowledgeRequest, selected?: AdvisoryVersion, previous?: KnowledgeSession): Promise<Library> {
  const session = await request<KnowledgeSession>('session')
  if (session.role !== 'analyst' && session.role !== 'reviewer') {
    throw new KnowledgeRequestError('Use this identity in Community. Knowledge requires an analyst or reviewer token.')
  }
  if (previous && (session.actor_id !== previous.actor_id || session.tenant_id !== previous.tenant_id || session.role !== previous.role)) {
    throw new KnowledgeRequestError('The Knowledge identity changed. Connect again to continue.')
  }
  const [candidates, incidents, advisories, preview] = await Promise.all([
    request<KnowledgeCandidate[]>('candidates').catch((error: unknown) => {
      if (error instanceof KnowledgeRequestError && error.status === 503) return undefined
      throw error
    }),
    request<KnowledgeIncident[]>('incidents'),
    request<KnowledgeAdvisory[]>('advisories'),
    selected ? request<KnowledgeAdvisory>(versionPath(selected)) : undefined,
  ])
  return { session, candidates: candidates ?? [], candidatesUnavailable: candidates === undefined, incidents, advisories, selected: preview }
}

function IncidentCard({ incident, canDraft, pending, onDraft }: {
  incident: KnowledgeIncident
  canDraft: boolean
  pending: boolean
  onDraft: () => void
}) {
  return (
    <article className="knowledge-card">
      <h3>{ruleLabels[incident.rule_id]}</h3>
      <code>{incident.id}</code>
      <p>{incident.evidence_complete ? 'Complete evidence' : 'Partial evidence'} · Root cause not established</p>
      <details>
        <summary>Incident evidence</summary>
        <dl>
          <div><dt>Snapshot</dt><dd><code>{incident.snapshot_id}</code></dd></div>
          <div><dt>Snapshot digest</dt><dd><code>{incident.snapshot_digest}</code></dd></div>
          <div><dt>Finding</dt><dd><code>{incident.finding_id}</code></dd></div>
          <div><dt>Rule version</dt><dd>{incident.rule_version}</dd></div>
          <div>
            <dt>Observed behavior</dt>
            <dd>{incident.observed_behavior.length ? (
              <ul>{incident.observed_behavior.map(({ action, outcome }, index) => <li key={index}>{action} · {outcome}</li>)}</ul>
            ) : 'No recorded action outcome'}</dd>
          </div>
          <div>
            <dt>Verified nodes</dt>
            <dd>{incident.evidence_node_ids.length ? (
              <ul>{incident.evidence_node_ids.map((id) => <li key={id}><code>{id}</code></li>)}</ul>
            ) : 'None recorded'}</dd>
          </div>
          <div>
            <dt>Verified links</dt>
            <dd>{incident.evidence_edge_ids.length ? (
              <ul>{incident.evidence_edge_ids.map((id) => <li key={id}><code>{id}</code></li>)}</ul>
            ) : 'None recorded'}</dd>
          </div>
        </dl>
      </details>
      {canDraft && <button type="button" disabled={pending} onClick={onDraft}>Create draft advisory</button>}
    </article>
  )
}

function AdvisoryPreview({ advisory, session, pending, onVersion, onChange }: {
  advisory: KnowledgeAdvisory
  session: KnowledgeSession
  pending: boolean
  onVersion: (version: number) => void
  onChange: (action: 'submit' | 'approve' | 'reject' | 'new') => void
}) {
  const latest = advisory.version === advisory.latest_version
  const author = session.actor_id === advisory.author_id
  const analyst = session.role === 'analyst'
  const canSubmit = latest && author && analyst && advisory.status === 'draft'
  const canReview = latest && !author && session.role === 'reviewer' && advisory.status === 'in_review'
  const canRevise = latest && analyst && (advisory.status === 'approved' || advisory.status === 'rejected')

  return (
    <section className="panel knowledge-panel knowledge-preview" aria-labelledby="knowledge-preview-title" id="knowledge-preview">
      <header className="knowledge-panel-header">
        <div>
          <h2 id="knowledge-preview-title"><FileCheck size={16} aria-hidden="true" /> Advisory preview</h2>
          <p><span>{statuses[advisory.status]}</span> · <code>{advisory.id}</code></p>
        </div>
        <label>
          Advisory version
          <select value={advisory.version} disabled={pending} onChange={(event) => onVersion(Number(event.target.value))}>
            {Array.from({ length: advisory.latest_version }, (_, index) => (
              <option key={index + 1} value={index + 1}>Version {index + 1}</option>
            ))}
          </select>
        </label>
      </header>
      <pre aria-label="Sanitized advisory">{JSON.stringify(advisory.advisory, null, 2)}</pre>
      {(canSubmit || canReview || canRevise) && (
        <div className="knowledge-actions">
          {canSubmit && <button type="button" disabled={pending} onClick={() => onChange('submit')}>Submit for review</button>}
          {canReview && (
            <>
              <button type="button" disabled={pending} onClick={() => onChange('approve')}>Approve</button>
              <button type="button" disabled={pending} onClick={() => onChange('reject')}>Reject</button>
            </>
          )}
          {canRevise && <button type="button" disabled={pending} onClick={() => onChange('new')}>New version</button>}
        </div>
      )}
      <section className="knowledge-audit" aria-labelledby="knowledge-audit-title">
        <h3 id="knowledge-audit-title">Audit history</h3>
        {advisory.audit.length ? (
          <ol>
            {advisory.audit.map((entry, index) => (
              <li key={index}>
                <strong>{auditActions[entry.action] ?? entry.action}</strong>
                <span><code>{entry.actor_id}</code> · <time dateTime={entry.occurred_at}>{entry.occurred_at}</time></span>
                <span>{entry.from_status && `${statuses[entry.from_status]} → `}{statuses[entry.to_status]}</span>
              </li>
            ))}
          </ol>
        ) : <p>No audit entries.</p>}
      </section>
    </section>
  )
}

export function Knowledge() {
  const [library, setLibrary] = useState<Library>()
  const [pending, setPending] = useState(false)
  const [message, setMessage] = useState('')
  const connection = useRef<Connection | null>(null)
  const tokenInput = useRef<HTMLInputElement>(null)

  useEffect(() => () => {
    connection.current?.controller.abort()
    connection.current = null
  }, [])

  function disconnect(problem = '') {
    connection.current?.controller.abort()
    connection.current = null
    setLibrary(undefined)
    setPending(false)
    setMessage(problem)
  }

  async function run(active: Connection, task: (request: KnowledgeRequest) => Promise<Library>) {
    if (active !== connection.current || active.pending) return
    active.pending = true
    setPending(true)
    try {
      const next = await task(active.request)
      if (connection.current === active) setLibrary(next)
    } catch (error) {
      if (connection.current === active) {
        disconnect(error instanceof KnowledgeRequestError ? error.message : 'Knowledge could not load. Connect again to retry.')
      }
    } finally {
      active.pending = false
      if (connection.current === active) setPending(false)
    }
  }

  function connect(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (connection.current) return
    const token = tokenInput.current?.value.trim()
    if (!token) return
    event.currentTarget.reset()
    setMessage('')
    const controller = new AbortController()
    const active = { request: knowledgeRequest(token, controller.signal), controller, pending: false }
    connection.current = active
    void run(active, loadLibrary)
  }

  function withLibrary(task: (request: KnowledgeRequest, current: Library) => Promise<Library>) {
    if (connection.current && library) void run(connection.current, (request) => task(request, library))
  }

  function createIncident(candidate: KnowledgeCandidate) {
    withLibrary(async (request, current) => {
      await request<KnowledgeIncident>('incidents', { snapshot_id: candidate.snapshot_id, finding_id: candidate.finding_id })
      return loadLibrary(request, current.selected, current.session)
    })
  }

  function createDraft(incidentId: string) {
    withLibrary(async (request, current) => {
      const draft = await request<KnowledgeAdvisory>('advisories', { incident_id: incidentId })
      return loadLibrary(request, draft, current.session)
    })
  }

  function changeAdvisory(advisory: KnowledgeAdvisory, action: 'submit' | 'approve' | 'reject' | 'new') {
    withLibrary(async (request, current) => {
      const { digest } = advisory.advisory
      const updated = action === 'new'
        ? await request<KnowledgeAdvisory>(advisoryPath(advisory.id), { version: advisory.version, digest })
        : await request<KnowledgeAdvisory>(`${versionPath(advisory)}/${action}`, { digest })
      return loadLibrary(request, updated, current.session)
    })
  }

  function showVersion(id: string, version: number) {
    withLibrary(async (request, current) => ({
      ...current,
      selected: await request<KnowledgeAdvisory>(versionPath({ id, version })),
    }))
  }

  const analyst = library?.session.role === 'analyst'
  const hasAdvisory = new Set(library?.advisories.map(({ incident_id }) => incident_id))
  const selected = library?.selected

  return (
    <section className="knowledge" id="knowledge" aria-labelledby="knowledge-title">
      <header className="knowledge-heading">
        <div>
          <h1 id="knowledge-title">Knowledge</h1>
          <p>Turn verified findings into incidents and sanitized advisories for review.</p>
        </div>
        {library && (
          <div className="knowledge-session">
            <p><strong>{library.session.actor_id}</strong> · {library.session.role} · <code>{library.session.tenant_id}</code></p>
            <div className="knowledge-actions">
              <button type="button" disabled={pending}
                onClick={() => withLibrary((request, current) => loadLibrary(request, current.selected, current.session))}>
                <RefreshCw size={14} aria-hidden="true" /> Refresh knowledge
              </button>
              <button type="button" onClick={() => disconnect()}>Disconnect</button>
            </div>
          </div>
        )}
      </header>
      {message && <p className="knowledge-error" role="alert"><ShieldAlert size={16} aria-hidden="true" /> {message}</p>}
      {pending && <p className="knowledge-progress" role="status">{library ? 'Updating Knowledge…' : 'Connecting to Knowledge…'}</p>}
      {!library ? (
        <form className="panel knowledge-panel knowledge-connect" onSubmit={connect} autoComplete="off">
          <label>
            <KeyRound size={15} aria-hidden="true" /> Knowledge access token
            <input ref={tokenInput} type="password" autoComplete="off" spellCheck={false} autoCapitalize="none" disabled={pending} required />
          </label>
          <button type="submit" disabled={pending}>Connect</button>
        </form>
      ) : (
        <>
          <div className="knowledge-grid">
            <section className="panel knowledge-panel" aria-labelledby="knowledge-candidates-title">
              <h2 id="knowledge-candidates-title">Candidates</h2>
              {library.candidates.length ? library.candidates.map((candidate) => {
                const exists = library.incidents.some((incident) =>
                  incident.snapshot_digest === candidate.snapshot_digest && incident.finding_id === candidate.finding_id)
                return (
                  <article className="knowledge-card" key={`${candidate.snapshot_digest}:${candidate.finding_id}`}>
                    <h3>{ruleLabels[candidate.rule_id]}</h3>
                    <code>{candidate.finding_id}</code>
                    <p>{candidate.evidence_complete ? 'Complete evidence' : 'Partial evidence'} · <code>{candidate.snapshot_id}</code></p>
                    <details>
                      <summary>Candidate provenance</summary>
                      <dl>
                        <div><dt>Snapshot digest</dt><dd><code>{candidate.snapshot_digest}</code></dd></div>
                        <div><dt>Rule version</dt><dd>{candidate.rule_version}</dd></div>
                      </dl>
                    </details>
                    {exists ? <p>Incident recorded</p> : analyst && (
                      <button type="button" disabled={pending} onClick={() => createIncident(candidate)}>Create incident</button>
                    )}
                  </article>
                )
              }) : library.candidatesUnavailable ? (
                <p role="status">Finding candidates are temporarily unavailable.</p>
              ) : <p>No finding candidates.</p>}
            </section>
            <section className="panel knowledge-panel" aria-labelledby="knowledge-incidents-title">
              <h2 id="knowledge-incidents-title">Incidents</h2>
              {library.incidents.length ? library.incidents.map((incident) => (
                <IncidentCard key={incident.id} incident={incident} pending={pending} onDraft={() => createDraft(incident.id)}
                  canDraft={analyst && incident.evidence_complete && incident.rule_id === 'suspicious_chain' && !hasAdvisory.has(incident.id)} />
              )) : <p>No incidents recorded.</p>}
            </section>
            <section className="panel knowledge-panel" aria-labelledby="knowledge-advisories-title">
              <h2 id="knowledge-advisories-title">Advisories</h2>
              {library.advisories.length ? library.advisories.map((advisory) => (
                <article className="knowledge-card" key={advisory.id}>
                  <h3><FileText size={15} aria-hidden="true" /> {statuses[advisory.status]} · Version {advisory.version}</h3>
                  <code>{advisory.id}</code>
                  <button type="button" disabled={pending} aria-controls="knowledge-preview"
                    aria-pressed={selected?.id === advisory.id}
                    onClick={() => showVersion(advisory.id, advisory.version)}>Preview advisory</button>
                </article>
              )) : <p>No advisories created.</p>}
            </section>
          </div>
          {selected && (
            <AdvisoryPreview advisory={selected} session={library.session} pending={pending}
              onVersion={(version) => showVersion(selected.id, version)}
              onChange={(action) => changeAdvisory(selected, action)} />
          )}
        </>
      )}
    </section>
  )
}
