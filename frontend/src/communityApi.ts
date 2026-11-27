import { KnowledgeRequestError } from './knowledgeApi'
import type { KnowledgeRequest, KnowledgeSession } from './knowledgeApi'

type CommunityRole = 'publisher' | 'validator'
type CommunitySession = KnowledgeSession & { role: CommunityRole }

export interface ApprovedVersion {
  knowledge_id: string
  version: number
  digest: string
}

export type FixtureScenario = 'positive' | 'negative' | 'inconclusive'

export interface SyntheticFixture {
  id: string
  scenario: FixtureScenario
  created_at: string
  digest: string
}

interface SyntheticResult {
  suite_id: string
  suite_version: number
  result: 'pattern_observed' | 'pattern_not_observed' | 'inconclusive'
  protection_effectiveness: 'unmeasured'
  limitations: string[]
}

export interface ValidationResult extends SyntheticResult {
  id: string
  fixture_id: string
  fixture_digest: string
  fixture_scenario: FixtureScenario
  recorded_at: string
}

export interface SharedFeedback extends SyntheticResult {
  validation_id: string
  shared_at: string
}

export interface CommunityDelivery extends ApprovedVersion {
  id: string
  sender_tenant: string
  recipient_tenant: string
  status: 'unverified' | 'verified' | 'expired' | 'withdrawn' | 'unavailable'
  delivered_at: string
  expires_at: string
  advisory?: Record<string, unknown>
  validations: ValidationResult[]
  feedback: SharedFeedback[]
  audit: { action: string; occurred_at: string }[]
}

export type CommunityLibrary =
  | { kind: 'publisher'; session: CommunitySession; approved: ApprovedVersion[]; peers: string[]; deliveries: CommunityDelivery[] }
  | { kind: 'validator'; session: CommunitySession; deliveries: CommunityDelivery[]; fixtures: SyntheticFixture[] }

export async function loadCommunity(request: KnowledgeRequest, previous?: CommunitySession): Promise<CommunityLibrary> {
  const session = await request<KnowledgeSession>('session')
  if (session.role !== 'publisher' && session.role !== 'validator') {
    throw new KnowledgeRequestError('Community requires a publisher or validator token.')
  }
  if (previous && (session.actor_id !== previous.actor_id || session.tenant_id !== previous.tenant_id || session.role !== previous.role)) {
    throw new KnowledgeRequestError('The Community identity changed. Connect again to continue.', 401)
  }

  const communitySession = { ...session, role: session.role }
  if (communitySession.role === 'publisher') {
    const [approved, peers, deliveries] = await Promise.all([
      request<ApprovedVersion[]>('community/approved'),
      request<string[]>('community/peers'),
      request<CommunityDelivery[]>('community/outbox'),
    ])
    return { kind: 'publisher', session: communitySession, approved, peers, deliveries }
  }

  const [deliveries, fixtures] = await Promise.all([
    request<CommunityDelivery[]>('community/inbox'),
    request<SyntheticFixture[]>('community/fixtures'),
  ])
  return { kind: 'validator', session: communitySession, deliveries, fixtures }
}
