import { useEffect, useRef, useState, type FormEvent } from 'react'
import { ClipboardCheck, Inbox, KeyRound, RefreshCw, Send, ShieldAlert } from 'lucide-react'
import { loadCommunity } from './communityApi'
import type {
  ApprovedVersion, CommunityDelivery, CommunityLibrary, FixtureScenario, SharedFeedback, SyntheticFixture,
} from './communityApi'
import { knowledgeRequest, KnowledgeRequestError } from './knowledgeApi'
import type { KnowledgeRequest } from './knowledgeApi'
import './knowledge.css'
import './community.css'

type Connection = { request: KnowledgeRequest; controller: AbortController; pending: boolean }
type DeliveryAction = 'verify' | 'validate' | 'feedback' | 'withdraw'

const statusLabels: Record<CommunityDelivery['status'], string> = {
  unverified: 'Awaiting verification',
  verified: 'Verified',
  expired: 'Expired',
  withdrawn: 'Withdrawn',
  unavailable: 'Verification unavailable',
}
const fixtureLabels: Record<FixtureScenario, string> = {
  positive: 'Positive control',
  negative: 'Negative control',
  inconclusive: 'Incomplete observations',
}
const resultLabels: Record<SharedFeedback['result'], string> = {
  pattern_observed: 'Pattern observed',
  pattern_not_observed: 'Pattern not observed',
  inconclusive: 'Inconclusive',
}
const protectionLabels: Record<SharedFeedback['protection_effectiveness'], string> = { unmeasured: 'Unmeasured' }

function versionKey(advisory: ApprovedVersion) {
  return `${advisory.knowledge_id}:${advisory.version}`
}

function formatTime(value: string) {
  return new Date(value).toLocaleString()
}

function resultDetails(result: SharedFeedback | CommunityDelivery['validations'][number]) {
  return (
    <>
      <p>Suite <code>{result.suite_id}</code> · Version {result.suite_version}</p>
      <p>Protection effectiveness · {protectionLabels[result.protection_effectiveness]}</p>
      <ul className="community-limitations">{result.limitations.map((limit) => <li key={limit}>{limit}</li>)}</ul>
    </>
  )
}

function FeedbackHistory({ feedback }: { feedback: SharedFeedback[] }) {
  return (
    <section className="community-history" aria-label="Feedback history">
      <h4>Feedback history</h4>
      {feedback.length ? feedback.map((entry) => (
        <div className="knowledge-card" key={entry.validation_id}>
          <p><strong>{resultLabels[entry.result]}</strong> · <time dateTime={entry.shared_at}>{formatTime(entry.shared_at)}</time></p>
          {resultDetails(entry)}
        </div>
      )) : <p>No feedback shared.</p>}
    </section>
  )
}

function DeliveryCard({ delivery, fixtures, pending, onAction }: {
  delivery: CommunityDelivery
  fixtures?: SyntheticFixture[]
  pending: boolean
  onAction: (action: DeliveryAction, reference?: string) => void
}) {
  const [fixtureId, setFixtureId] = useState('')
  const [pastExpiry, setPastExpiry] = useState(() => Date.parse(delivery.expires_at) <= Date.now())
  useEffect(() => {
    if (delivery.status === 'expired' || delivery.status === 'withdrawn') return
    const timeout = window.setTimeout(() => setPastExpiry(true), Math.max(0, Date.parse(delivery.expires_at) - Date.now()))
    return () => window.clearTimeout(timeout)
  }, [delivery.expires_at, delivery.status])

  const status = pastExpiry && delivery.status !== 'withdrawn' ? 'expired' : delivery.status
  const received = fixtures !== undefined
  const verified = status === 'verified'
  const active = verified || status === 'unverified'

  return (
    <article className="knowledge-card community-delivery">
      <header className="community-card-heading">
        <h3>Advisory version {delivery.version}</h3>
        <span className="community-status" data-status={status}>{statusLabels[status]}</span>
      </header>
      <dl className="community-metadata">
        <div><dt>{received ? 'From' : 'To'}</dt><dd><code>{received ? delivery.sender_tenant : delivery.recipient_tenant}</code></dd></div>
        <div><dt>Advisory</dt><dd><code>{delivery.knowledge_id}</code></dd></div>
        <div><dt>Digest</dt><dd><code>{delivery.digest}</code></dd></div>
        <div><dt>Delivered</dt><dd><time dateTime={delivery.delivered_at}>{formatTime(delivery.delivered_at)}</time></dd></div>
        <div><dt>Expires</dt><dd><time dateTime={delivery.expires_at}>{formatTime(delivery.expires_at)}</time></dd></div>
      </dl>
      {!received && active && <button type="button" disabled={pending} onClick={() => onAction('withdraw')}>Withdraw delivery</button>}
      {received && status === 'unverified' && (
        <div className="community-history">
          <p>Verify the registered sender, approved digest, permitted audience and expiry before opening this advisory.</p>
          <button type="button" disabled={pending} onClick={() => onAction('verify')}>Verify advisory</button>
        </div>
      )}
      {received && verified && delivery.advisory && (
        <div className="knowledge-preview community-history">
          <h4>Verified advisory</h4>
          <pre aria-label="Verified advisory envelope">{JSON.stringify(delivery.advisory, null, 2)}</pre>
          {fixtures.length ? (
            <form className="community-inline-form" onSubmit={(event) => {
              event.preventDefault()
              if (fixtureId) onAction('validate', fixtureId)
            }}>
              <label>
                Validation fixture
                <select required value={fixtureId} disabled={pending} onChange={(event) => setFixtureId(event.target.value)}>
                  <option value="">Select a fixture</option>
                  {fixtures.map((fixture) => (
                    <option key={fixture.id} value={fixture.id}>{fixtureLabels[fixture.scenario]}</option>
                  ))}
                </select>
              </label>
              <button type="submit" disabled={pending || !fixtureId}>Run validation</button>
            </form>
          ) : <p>Create a synthetic fixture to run validation.</p>}
        </div>
      )}
      {received && (verified || delivery.validations.length > 0) && (
        <section className="community-history" aria-label="Validation results">
          <h4>Validation results</h4>
          {delivery.validations.length ? delivery.validations.map((result) => {
            const shared = delivery.feedback.some((entry) => entry.validation_id === result.id)
            return (
              <div className="knowledge-card" key={result.id}>
                <p><strong>{resultLabels[result.result]}</strong> · <time dateTime={result.recorded_at}>{formatTime(result.recorded_at)}</time></p>
                <p>Fixture {fixtureLabels[result.fixture_scenario]} · <code>{result.fixture_id}</code></p>
                <p>Fixture digest <code>{result.fixture_digest}</code></p>
                {resultDetails(result)}
                {shared ? <p>Feedback shared</p> : verified && (
                  <button type="button" disabled={pending} onClick={() => onAction('feedback', result.id)}>Share feedback</button>
                )}
              </div>
            )
          }) : <p>No validations recorded.</p>}
        </section>
      )}
      <FeedbackHistory feedback={delivery.feedback} />
      {delivery.audit.length > 0 && (
        <details>
          <summary>Delivery audit</summary>
          <ol className="community-audit">
            {delivery.audit.map((entry, index) => (
              <li key={index}>{entry.action.replaceAll('_', ' ')} · <time dateTime={entry.occurred_at}>{formatTime(entry.occurred_at)}</time></li>
            ))}
          </ol>
        </details>
      )}
    </article>
  )
}

function PublishPanel({ library, pending, onSend }: {
  library: Extract<CommunityLibrary, { kind: 'publisher' }>
  pending: boolean
  onSend: (version: ApprovedVersion, recipient: string, hours: number) => void
}) {
  const [selection, setSelection] = useState('')
  const [recipient, setRecipient] = useState('')
  const [hours, setHours] = useState('24')
  const version = library.approved.find((advisory) => versionKey(advisory) === selection)
  const permitted = library.peers.includes(recipient)

  return (
    <section className="panel knowledge-panel" aria-labelledby="community-publish-title">
      <h2 id="community-publish-title"><Send size={16} aria-hidden="true" /> Publish advisory</h2>
      {!library.approved.length ? <p>No approved advisory versions are available.</p> : !library.peers.length ? (
        <p>No recipient tenants are permitted for this publisher.</p>
      ) : (
        <form className="community-form" onSubmit={(event) => {
          event.preventDefault()
          if (version && permitted) onSend(version, recipient, Number(hours))
        }}>
          <label>
            Approved advisory
            <select required value={version ? selection : ''} disabled={pending} onChange={(event) => setSelection(event.target.value)}>
              <option value="">Select an approved version</option>
              {library.approved.map((advisory) => (
                <option key={versionKey(advisory)} value={versionKey(advisory)}>{advisory.knowledge_id} · Version {advisory.version}</option>
              ))}
            </select>
          </label>
          {version && <p>Approved digest <code>{version.digest}</code></p>}
          <label>
            Recipient tenant
            <select required value={permitted ? recipient : ''} disabled={pending} onChange={(event) => setRecipient(event.target.value)}>
              <option value="">Select a tenant</option>
              {library.peers.map((tenant) => <option key={tenant} value={tenant}>{tenant}</option>)}
            </select>
          </label>
          <label>
            Valid for (hours)
            <input type="number" min={1} max={168} required value={hours} disabled={pending} onChange={(event) => setHours(event.target.value)} />
          </label>
          <button type="submit" disabled={pending || !version || !permitted}>Send advisory</button>
        </form>
      )}
    </section>
  )
}

function FixturesPanel({ fixtures, pending, onCreate }: {
  fixtures: SyntheticFixture[]
  pending: boolean
  onCreate: (scenario: FixtureScenario) => void
}) {
  const [scenario, setScenario] = useState<FixtureScenario>('positive')
  const existing = fixtures.some((fixture) => fixture.scenario === scenario)

  return (
    <section id="community-fixtures" className="panel knowledge-panel" aria-labelledby="community-fixtures-title">
      <h2 id="community-fixtures-title"><ClipboardCheck size={16} aria-hidden="true" /> Synthetic fixtures</h2>
      <p>Prepare a fixture owned by this tenant for an independent validation.</p>
      <form className="community-form" onSubmit={(event) => {
        event.preventDefault()
        if (!existing) onCreate(scenario)
      }}>
        <label>
          Fixture scenario
          <select value={scenario} disabled={pending} onChange={(event) => setScenario(event.target.value as FixtureScenario)}>
            {Object.entries(fixtureLabels).map(([key, label]) => <option key={key} value={key}>{label}</option>)}
          </select>
        </label>
        <button type="submit" disabled={pending || existing}>Create synthetic fixture</button>
      </form>
      {fixtures.map((fixture) => (
        <article className="knowledge-card" key={fixture.id}>
          <h3>{fixtureLabels[fixture.scenario]}</h3>
          <p>Fixture <code>{fixture.id}</code></p>
          <p>Digest <code>{fixture.digest}</code></p>
          <p>Created <time dateTime={fixture.created_at}>{formatTime(fixture.created_at)}</time></p>
        </article>
      ))}
    </section>
  )
}

export function Community() {
  const [library, setLibrary] = useState<CommunityLibrary>()
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

  async function run(active: Connection, task: (request: KnowledgeRequest) => Promise<CommunityLibrary>, problem: string) {
    if (active !== connection.current || active.pending) return
    active.pending = true
    setPending(true)
    setMessage('')
    try {
      const next = await task(active.request)
      if (active === connection.current) setLibrary(next)
    } catch (error) {
      if (active !== connection.current) return
      const status = error instanceof KnowledgeRequestError ? error.status : undefined
      if (status === 401 || status === 403 || !library) {
        const detail = error instanceof KnowledgeRequestError && !status ? error.message : problem
        disconnect(detail)
      } else {
        setMessage(problem)
        try {
          const next = await loadCommunity(active.request, library.session)
          if (active === connection.current) setLibrary(next)
        } catch {
          if (active === connection.current) disconnect(problem)
        }
      }
    } finally {
      active.pending = false
      if (active === connection.current) setPending(false)
    }
  }

  function connect(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (connection.current) return
    const token = tokenInput.current?.value.trim()
    if (!token) return
    event.currentTarget.reset()
    const controller = new AbortController()
    const active = { request: knowledgeRequest(token, controller.signal), controller, pending: false }
    connection.current = active
    void run(active, loadCommunity, 'Community could not connect. Check the access token and try again.')
  }

  function withLibrary(task: (request: KnowledgeRequest, current: CommunityLibrary) => Promise<CommunityLibrary>, problem: string) {
    if (connection.current && library) void run(connection.current, (request) => task(request, library), problem)
  }

  function send(version: ApprovedVersion, recipient: string, hours: number) {
    withLibrary(async (request, current) => {
      const delivery = await request<CommunityDelivery>('community/outbox', { ...version, recipient_tenant: recipient, ttl_hours: hours })
      return { ...current, deliveries: [delivery, ...current.deliveries.filter(({ id }) => id !== delivery.id)] }
    }, 'The advisory could not be sent. Check the approved version and permitted recipient.')
  }

  function createFixture(scenario: FixtureScenario) {
    withLibrary(async (request, current) => {
      if (current.kind !== 'validator') return current
      const fixture = await request<SyntheticFixture>('community/fixtures', { scenario })
      return { ...current, fixtures: [fixture, ...current.fixtures.filter(({ id }) => id !== fixture.id)] }
    }, 'The synthetic fixture could not be created.')
  }

  function changeDelivery(delivery: CommunityDelivery, action: DeliveryAction, reference?: string) {
    withLibrary(async (request, current) => {
      const box = current.kind === 'publisher' ? 'outbox' : 'inbox'
      const body: Record<string, string> = reference && action === 'validate' ? { fixture_id: reference } :
        reference && action === 'feedback' ? { validation_id: reference } : {}
      const updated = await request<CommunityDelivery>(`community/${box}/${encodeURIComponent(delivery.id)}/${action}`, body)
      return { ...current, deliveries: current.deliveries.map((row) => row.id === updated.id ? updated : row) }
    }, deliveryErrors[action])
  }

  const received = library?.kind === 'validator'

  return (
    <section className="knowledge community" id="community" aria-labelledby="community-title">
      <header className="knowledge-heading">
        <div>
          <h1 id="community-title">Community</h1>
          <p>Exchange approved advisories and validate observed patterns with local synthetic fixtures.</p>
        </div>
        {library && (
          <div className="knowledge-session">
            <p><strong>{library.session.actor_id}</strong> · {library.kind} · <code>{library.session.tenant_id}</code></p>
            <div className="knowledge-actions">
              <button type="button" disabled={pending}
                onClick={() => withLibrary((request, current) => loadCommunity(request, current.session), 'Community could not refresh.')}>
                <RefreshCw size={14} aria-hidden="true" /> Refresh Community
              </button>
              <button type="button" onClick={() => disconnect()}>Disconnect</button>
            </div>
          </div>
        )}
      </header>
      {message && <p className="knowledge-error" role="alert"><ShieldAlert size={16} aria-hidden="true" /> {message}</p>}
      {pending && <p className="knowledge-progress" role="status">{library ? 'Updating Community…' : 'Connecting to Community…'}</p>}
      {!library ? (
        <form className="panel knowledge-panel knowledge-connect" onSubmit={connect} autoComplete="off">
          <label>
            <KeyRound size={15} aria-hidden="true" /> Community access token
            <input ref={tokenInput} type="password" autoComplete="off" spellCheck={false} autoCapitalize="none" disabled={pending} required />
          </label>
          <button type="submit" disabled={pending}>Connect</button>
        </form>
      ) : (
        <div className="community-grid">
          {library.kind === 'publisher' && <PublishPanel library={library} pending={pending} onSend={send} />}
          <section className="panel knowledge-panel" aria-labelledby="community-deliveries-title">
            <h2 id="community-deliveries-title"><Inbox size={16} aria-hidden="true" /> {received ? 'Community Inbox' : 'Delivery status'}</h2>
            {library.deliveries.length ? library.deliveries.map((delivery) => (
              <DeliveryCard key={delivery.id} delivery={delivery} fixtures={library.kind === 'validator' ? library.fixtures : undefined}
                pending={pending} onAction={(action, reference) => changeDelivery(delivery, action, reference)} />
            )) : <p>{received ? 'No advisories received.' : 'No deliveries sent.'}</p>}
          </section>
          {library.kind === 'validator' && <FixturesPanel fixtures={library.fixtures} pending={pending} onCreate={createFixture} />}
        </div>
      )}
    </section>
  )
}

const deliveryErrors: Record<DeliveryAction, string> = {
  verify: 'The delivery could not be verified.',
  validate: 'Validation could not run. Check the fixture and current delivery status.',
  feedback: 'Feedback could not be shared. Check the current delivery status.',
  withdraw: 'The delivery could not be withdrawn.',
}
