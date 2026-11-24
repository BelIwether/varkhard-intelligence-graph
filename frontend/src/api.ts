export type GraphNodeKind = 'agent' | 'resource' | 'permission' | 'interaction'
export type EdgeKind = 'HAS_PERMISSION' | 'ON_RESOURCE' | 'PERFORMED' | 'TARGETS' | 'HANDED_TO' | 'TRIGGERS'
export type RuleId = 'unauthorized_access' | 'excessive_permission' | 'suspicious_chain'

export interface Agent {
  id: string
  name: string
}

export interface Resource {
  id: string
  name: string
  classification: string
  boundary: string
}

export interface Permission {
  id: string
  agent_id: string
  resource_id: string
  action: string
  kind: 'grant' | 'baseline'
}

export interface Interaction {
  id: string
  agent_id: string
  resource_id: string
  action: string
  outcome: 'success' | 'denied'
  occurred_at: number
  parent_id: string | null
  recipient_id: string | null
}

export interface GraphNode {
  id: string
  record_id: string
  kind: GraphNodeKind
  label: string
}

export interface GraphEdge {
  id: string
  source: string
  target: string
  kind: EdgeKind
}

export type EvidenceValue = string | number | boolean | null | EvidenceValue[] | { [key: string]: EvidenceValue }

export interface InvestigationStep {
  title: string
  description: string
  node_ids: string[]
  edge_ids: string[]
  record_node_id: string | null
  occurred_at: number | null
  action: string | null
  outcome: Interaction['outcome'] | null
}

export interface Investigation {
  origin: InvestigationStep | null
  trigger: InvestigationStep | null
  steps: InvestigationStep[]
  affected_node_ids: string[]
  node_ids: string[]
  edge_ids: string[]
  complete: boolean
}

export interface Finding {
  id: string
  rule_id: RuleId
  category: string
  explanation: string
  evidence: Record<string, EvidenceValue>
  node_ids: string[]
  edge_ids: string[]
  investigation?: Investigation
}

export interface Dashboard {
  agents: Agent[]
  resources: Resource[]
  permissions: Permission[]
  interactions: Interaction[]
  nodes: GraphNode[]
  edges: GraphEdge[]
  findings: Finding[]
  source: { filename: string; read_only: boolean; synthetic_demo?: boolean }
}

export async function getDashboard(signal: AbortSignal): Promise<Dashboard> {
  const response = await fetch('/api/graph', { signal, cache: 'no-store' })
  if (!response.ok) {
    const body = await response.json().catch(() => null)
    const message = typeof body?.detail === 'string'
      ? body.detail
      : `The graph API returned HTTP ${response.status}.`
    throw new Error(message)
  }
  return response.json()
}
