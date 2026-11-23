import {
  Background,
  Controls,
  Handle,
  MarkerType,
  Position,
  ReactFlow,
  useNodesState,
  useReactFlow,
  type Edge,
  type Node,
  type NodeProps,
  type NodeTypes,
} from '@xyflow/react'
import { Bot, Box, History, KeyRound } from 'lucide-react'
import { memo, useEffect, useMemo, useState } from 'react'
import '@xyflow/react/dist/style.css'
import type { GraphEdge, GraphNode } from './api'
import './graph.css'

type GraphFocus = {
  nodeIds: string[]
  edgeIds: string[]
  tone: 'finding' | 'entity'
}

type GraphProps = {
  nodes: GraphNode[]
  edges: GraphEdge[]
  focus?: GraphFocus
  onNodeSelect: (node: GraphNode) => void
}

type Emphasis = 'finding' | 'entity' | 'muted'
type FlowNode = Node<{ record: GraphNode; emphasis?: Emphasis }, 'record'>

const columns = {
  agent: { x: 0, height: 46 },
  permission: { x: 212, height: 30 },
  interaction: { x: 420, height: 30 },
  resource: { x: 631, height: 46 },
}

const compactColumns = { agent: 0, permission: 141, interaction: 253, resource: 365 }
const compactViewport = '(max-width: 640px)'

const icons = {
  agent: Bot,
  resource: Box,
  permission: KeyRound,
  interaction: History,
}

const nodeKinds = {
  agent: 'AI agent',
  resource: 'Resource',
  permission: 'Permission',
  interaction: 'Interaction',
}

const edgeLabels: Record<GraphEdge['kind'], string> = {
  HAS_PERMISSION: 'Has permission',
  ON_RESOURCE: 'Applies to resource',
  PERFORMED: 'Performed interaction',
  TARGETS: 'Targets resource',
  HANDED_TO: 'Handed to agent',
  TRIGGERS: 'Triggers interaction',
}

const fitViewOptions = { padding: 0.12, maxZoom: 1.15 }

const RecordCard = memo(function RecordCard({ data }: NodeProps<FlowNode>) {
  const { record, emphasis } = data
  const Icon = icons[record.kind]

  return (
    <div className={`graph-record graph-record--${record.kind}${emphasis ? ` graph-record--${emphasis}` : ''}`}>
      <Handle type="target" position={Position.Left} id="in" />
      <Handle type="source" position={Position.Right} id="out" />
      {record.kind === 'agent' && (
        <Handle type="target" position={Position.Right} id="recipient" style={{ top: '68%' }} />
      )}
      {record.kind === 'interaction' && (
        <>
          <Handle type="target" position={Position.Right} id="triggered" style={{ top: '20%' }} />
          <Handle type="source" position={Position.Right} id="triggers" style={{ top: '79%' }} />
          <Handle type="source" position={Position.Left} id="handoff" style={{ top: '72%' }} />
        </>
      )}
      <button
        type="button"
        title={`${record.label} · ${record.record_id}`}
        aria-label={`${nodeKinds[record.kind]}: ${record.label}`}
      >
        <span className="graph-record__icon"><Icon aria-hidden="true" /></span>
        <span className="graph-record__label">{record.label}</span>
      </button>
    </div>
  )
})

const nodeTypes = { record: RecordCard } satisfies NodeTypes

function connectedGroups(nodes: GraphNode[], edges: GraphEdge[]) {
  const records = new Map(nodes.map((node) => [node.id, node]))
  const adjacent = new Map(nodes.map((node) => [node.id, [] as string[]]))
  for (const edge of edges) {
    adjacent.get(edge.source)?.push(edge.target)
    adjacent.get(edge.target)?.push(edge.source)
  }

  const visited = new Set<string>()
  const groups: GraphNode[][] = []
  for (const node of nodes) {
    if (visited.has(node.id)) continue

    const group = [node]
    visited.add(node.id)
    for (const member of group) {
      for (const id of adjacent.get(member.id) ?? []) {
        const neighbor = records.get(id)
        if (neighbor && !visited.has(id)) {
          visited.add(id)
          group.push(neighbor)
        }
      }
    }
    groups.push(group)
  }
  return groups.sort((left, right) => right.length - left.length)
}

function interactionOrder(interactions: GraphNode[], triggers: Map<string, string[]>) {
  const byId = new Map(interactions.map((node) => [node.id, node]))
  const children = new Set(interactions.flatMap((node) => triggers.get(node.id) ?? []))
  const ordered: GraphNode[] = []
  const orderedRoots = interactions.filter((node) => !children.has(node.id))
  const queue = [...orderedRoots, ...interactions].map((node) => node.id).reverse()

  // Start with the event roots, then follow explicit trigger links.
  while (queue.length) {
    const id = queue.pop()
    if (id === undefined) break
    const node = byId.get(id)
    if (!node) continue
    byId.delete(id)
    ordered.push(node)
    queue.push(...(triggers.get(id) ?? []))
  }
  return ordered
}

function layoutGraph(nodes: GraphNode[], edges: GraphEdge[], compact: boolean): FlowNode[] {
  const triggers = new Map<string, string[]>()
  const agentByRecord = new Map<string, string>()
  const resourceByRecord = new Map<string, string>()
  for (const edge of edges) {
    if (edge.kind === 'TRIGGERS') {
      const next = triggers.get(edge.source) ?? []
      next.push(edge.target)
      triggers.set(edge.source, next)
    }
    if (edge.kind === 'HAS_PERMISSION' || edge.kind === 'PERFORMED') {
      agentByRecord.set(edge.target, edge.source)
    }
    if (edge.kind === 'TARGETS') {
      resourceByRecord.set(edge.source, edge.target)
    }
  }

  const positioned: FlowNode[] = []
  let startY = 0
  for (const group of connectedGroups(nodes, edges)) {
    const kinds = { agent: [], resource: [], permission: [], interaction: [] } as Record<GraphNode['kind'], GraphNode[]>
    for (const record of group) kinds[record.kind].push(record)

    for (const records of Object.values(kinds)) {
      records.sort((left, right) => left.id.localeCompare(right.id))
    }
    kinds.interaction = interactionOrder(kinds.interaction, triggers)
    const firstInteraction = new Map<string, number>()
    kinds.interaction.forEach((interaction, index) => {
      for (const id of [agentByRecord.get(interaction.id), resourceByRecord.get(interaction.id)]) {
        if (id && !firstInteraction.has(id)) firstInteraction.set(id, index)
      }
    })
    const compareEventOrder = (left: GraphNode, right: GraphNode) =>
      (firstInteraction.get(left.id) ?? group.length) - (firstInteraction.get(right.id) ?? group.length)
    kinds.agent.sort(compareEventOrder)
    kinds.resource.sort(compareEventOrder)
    const agentRank = new Map(kinds.agent.map((node, index) => [node.id, index]))
    kinds.permission.sort((left, right) =>
      (agentRank.get(agentByRecord.get(left.id) ?? '') ?? group.length)
      - (agentRank.get(agentByRecord.get(right.id) ?? '') ?? group.length),
    )

    const height = Math.max(
      kinds.agent.length * 58,
      kinds.resource.length * 58,
      kinds.permission.length * 36,
      kinds.interaction.length * 42,
      60,
    )
    for (const kind of Object.keys(kinds) as GraphNode['kind'][]) {
      const records = kinds[kind]
      if (!records.length) continue
      const { x, height: cardHeight } = columns[kind]
      const rowHeight = kind === 'interaction' ? 42 : height / records.length
      const inset = (height - rowHeight * records.length) / 2
      records.forEach((record, index) => {
        positioned.push({
          id: record.id,
          type: 'record',
          zIndex: 3,
          position: {
            x: compact ? compactColumns[kind] : x,
            y: startY + inset + (index + 0.5) * rowHeight - cardHeight / 2,
          },
          data: { record },
        })
      })
    }
    startY += height + 36
  }
  return positioned
}

function flowEdges(edges: GraphEdge[], focus?: GraphFocus): Edge[] {
  const highlighted = new Set(focus?.edgeIds)
  return edges.map((edge) => {
    const emphasis = highlighted.has(edge.id) ? focus?.tone : focus && 'muted'
    const isTrigger = edge.kind === 'TRIGGERS'
    const isHandoff = edge.kind === 'HANDED_TO'
    const color = {
      finding: '#f36c76',
      entity: '#b5c4d9',
      muted: '#30323a',
    }[emphasis ?? 'muted']
    return {
      id: edge.id,
      source: edge.source,
      target: edge.target,
      sourceHandle: isTrigger ? 'triggers' : isHandoff ? 'handoff' : 'out',
      targetHandle: isTrigger ? 'triggered' : isHandoff ? 'recipient' : 'in',
      ariaLabel: edgeLabels[edge.kind],
      className: 'graph-edge',
      focusable: false,
      zIndex: emphasis && emphasis !== 'muted' ? 2 : 0,
      style: {
        stroke: emphasis ? color : isTrigger || isHandoff ? '#747781' : '#525661',
        strokeWidth: emphasis === 'finding' || emphasis === 'entity' ? 2.4 : 1.25,
        strokeDasharray: isTrigger || isHandoff ? '5 4' : undefined,
      },
      markerEnd: {
        type: MarkerType.ArrowClosed,
        color: emphasis ? color : '#6b6d78',
        width: 13,
        height: 13,
      },
    }
  })
}

function FocusViewport({ nodeIds }: { nodeIds?: string[] }) {
  const { fitView } = useReactFlow()
  useEffect(() => {
    if (!nodeIds?.length) return
    void fitView({
      nodes: nodeIds.map((id) => ({ id })),
      padding: 0.25,
      maxZoom: 1.2,
      duration: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 0 : 280,
    })
  }, [fitView, nodeIds])
  return null
}

function GraphCanvas({ nodes, edges, focus, onNodeSelect, compact }: GraphProps & { compact: boolean }) {
  const layout = useMemo(() => layoutGraph(nodes, edges, compact), [nodes, edges, compact])
  const [positioned, setPositioned, onNodesChange] = useNodesState(layout)

  useEffect(() => setPositioned(layout), [layout, setPositioned])

  const visibleNodes = useMemo(() => {
    if (!focus) return positioned
    const highlighted = new Set(focus.nodeIds)
    return positioned.map((node) => ({
      ...node,
      data: {
        ...node.data,
        emphasis: highlighted.has(node.id) ? focus.tone : 'muted' as const,
      },
    }))
  }, [positioned, focus])
  const visibleEdges = useMemo(() => flowEdges(edges, focus), [edges, focus])

  return (
    <div
      className={compact ? 'intelligence-graph intelligence-graph--compact' : 'intelligence-graph'}
      role="region"
      aria-label="Interactive intelligence graph"
    >
      <ReactFlow<FlowNode>
        nodes={visibleNodes}
        edges={visibleEdges}
        nodeTypes={nodeTypes}
        onNodesChange={onNodesChange}
        onNodeClick={(_, node) => onNodeSelect(node.data.record)}
        nodesConnectable={false}
        nodesFocusable={false}
        edgesFocusable={false}
        elementsSelectable={false}
        deleteKeyCode={null}
        nodeDragThreshold={4}
        nodeClickDistance={3}
        fitView
        fitViewOptions={fitViewOptions}
        minZoom={0.1}
        maxZoom={2}
        zoomOnScroll={false}
        zoomOnDoubleClick={false}
        preventScrolling={false}
        colorMode="dark"
        proOptions={{ hideAttribution: true }}
      >
        <Background color="#32343d" gap={22} size={1.2} />
        <Controls
          position="bottom-right"
          orientation={compact ? 'horizontal' : 'vertical'}
          showInteractive={false}
        />
        <FocusViewport nodeIds={compact || focus?.tone === 'finding' ? focus?.nodeIds : undefined} />
      </ReactFlow>
    </div>
  )
}

export function IntelligenceGraph(props: GraphProps) {
  const [compact, setCompact] = useState(() => window.matchMedia(compactViewport).matches)
  useEffect(() => {
    const query = window.matchMedia(compactViewport)
    const update = (event: MediaQueryListEvent) => setCompact(event.matches)
    setCompact(query.matches)
    query.addEventListener('change', update)
    return () => query.removeEventListener('change', update)
  }, [])

  return <GraphCanvas key={compact ? 'compact' : 'wide'} compact={compact} {...props} />
}
