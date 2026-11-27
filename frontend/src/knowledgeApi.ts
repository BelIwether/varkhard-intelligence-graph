import type { Interaction, RuleId } from './api'

export interface KnowledgeSession {
  actor_id: string
  tenant_id: string
  role: 'analyst' | 'reviewer' | 'publisher' | 'validator'
}

export interface KnowledgeCandidate {
  snapshot_id: string
  snapshot_digest: string
  finding_id: string
  rule_id: RuleId
  rule_version: number
  evidence_complete: boolean
}

export interface KnowledgeIncident extends KnowledgeCandidate {
  id: string
  evidence_node_ids: string[]
  evidence_edge_ids: string[]
  observed_behavior: Pick<Interaction, 'action' | 'outcome'>[]
  root_cause_status: 'not_established'
}

type AdvisoryStatus = 'draft' | 'in_review' | 'approved' | 'rejected'

export interface KnowledgeAdvisory {
  id: string
  version: number
  latest_version: number
  incident_id: string
  author_id: string
  status: AdvisoryStatus
  advisory: { digest: string } & Record<string, unknown>
  audit: {
    action: string
    actor_id: string
    occurred_at: string
    from_status: AdvisoryStatus | null
    to_status: AdvisoryStatus
  }[]
}

export type KnowledgeRequest = <Result>(path: string, body?: Record<string, string | number>) => Promise<Result>

export class KnowledgeRequestError extends Error {
  constructor(message: string, readonly status?: number) {
    super(message)
  }
}

function errorMessage(status: number) {
  if (status === 401 || status === 403) return 'Knowledge access was denied. Connect with an authorized token.'
  if (status === 409) return 'Knowledge has changed. Connect again to load the latest records.'
  if (status === 400 || status === 422) return 'Knowledge rejected the request.'
  return 'Knowledge is unavailable.'
}

export function knowledgeRequest(token: string, signal: AbortSignal): KnowledgeRequest {
  return async <Result,>(path: string, body?: Record<string, string | number>) => {
    const response = await fetch(`/api/knowledge/${path}`, {
      signal,
      cache: 'no-store',
      credentials: 'omit',
      redirect: 'error',
      method: body ? 'POST' : 'GET',
      headers: {
        Authorization: `Bearer ${token}`,
        ...(body ? { 'Content-Type': 'application/json' } : {}),
      },
      body: body && JSON.stringify(body),
    })
    if (!response.ok) throw new KnowledgeRequestError(errorMessage(response.status), response.status)
    return response.json() as Promise<Result>
  }
}
