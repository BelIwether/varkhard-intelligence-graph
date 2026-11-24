import {
  Background,
  BaseEdge,
  Controls,
  Handle,
  MarkerType,
  Position,
  ReactFlow,
  getBezierPath,
  getSmoothStepPath,
  useNodesInitialized,
  useNodesState,
  useReactFlow,
  useStore,
  type Edge,
  type EdgeProps,
  type FitViewOptions,
  type Node,
  type NodeProps,
  type NodeTypes,
} from '@xyflow/react'
import { Bot, Box, GitBranch, KeyRound } from 'lucide-react'
import { memo, useEffect, useLayoutEffect, useMemo, useRef, useState, type FocusEvent } from 'react'
import '@xyflow/react/dist/style.css'
import type { GraphEdge, GraphNode, GraphNodeKind } from './api'
import './graph.css'

export type GraphFocus = {
  nodeIds: string[]
  edgeIds: string[]
  tone: 'finding' | 'entity' | 'origin' | 'affected' | 'step'
  originNodeId?: string
  selectedNodeId?: string
  stepNumber?: number
  orderedEdgeIds?: string[]
}

type GraphProps = {
  nodes: GraphNode[]
  edges: GraphEdge[]
  focus?: GraphFocus
  onNodeSelect: (node: GraphNode) => void
}

type Emphasis = GraphFocus['tone'] | 'muted'
type RecordNode = Node<{
  record: GraphNode
  emphasis?: Emphasis
  isOrigin?: boolean
  isSelected?: boolean
  stepNumber?: number
}, 'record'>
type LaneNode = Node<{ kind: GraphNodeKind }, 'lane'>
type FlowNode = RecordNode | LaneNode
type RelationshipEdge = Edge<{ title: string; label?: string; sameLane: boolean }, 'relationship'>

const lanes = {
  agent: { label: 'Agents', singular: 'AI agent', Icon: Bot, x: 0, compactX: 0, height: 46, gap: 13 },
  permission: { label: 'Permissions', singular: 'Permission', Icon: KeyRound, x: 227, compactX: 123, height: 30, gap: 7 },
  interaction: { label: 'Interactions', singular: 'Interaction', Icon: GitBranch, x: 414, compactX: 224, height: 33, gap: 10 },
  resource: { label: 'Resources', singular: 'Resource', Icon: Box, x: 648, compactX: 346, height: 46, gap: 13 },
}
const laneKinds = Object.keys(lanes) as GraphNodeKind[]

const edgeLabels: Record<GraphEdge['kind'], string> = {
  HAS_PERMISSION: 'Has permission',
  ON_RESOURCE: 'Applies to',
  PERFORMED: 'Performed',
  TARGETS: 'Targets',
  HANDED_TO: 'Handed to',
  TRIGGERS: 'Triggers',
}

const fitViewOptions: FitViewOptions = {
  padding: { top: '28px', right: '15px', bottom: '60px', left: '15px' },
  maxZoom: 1.2,
}

const RecordCard = memo(function RecordCard({ id, data }: NodeProps<RecordNode>) {
  const { record, emphasis, isOrigin, isSelected, stepNumber } = data
  const { fitView, getZoom } = useReactFlow()
  const { Icon, singular } = lanes[record.kind]
  const marker = stepNumber === undefined ? (isOrigin ? 'Origin' : undefined) : `Step ${stepNumber}`
  const classes = [
    'graph-record',
    `graph-record--${record.kind}`,
    emphasis && `graph-record--${emphasis}`,
    isOrigin && 'graph-record--origin',
    isSelected && 'graph-record--selected',
  ].filter(Boolean).join(' ')

  function revealKeyboardFocus(event: FocusEvent<HTMLButtonElement>) {
    const button = event.currentTarget
    if (!button.matches(':focus-visible')) return

    const frame = button.closest('.intelligence-graph')?.getBoundingClientRect()
    const card = button.getBoundingClientRect()
    if (frame && (card.left < frame.left || card.right > frame.right || card.top < frame.top || card.bottom > frame.bottom)) {
      void fitView({ ...fitViewOptions, nodes: [{ id }], maxZoom: getZoom() })
    }
  }

  return (
    <div className={classes}>
      <Handle type="target" position={Position.Left} id="in" />
      <Handle type="source" position={Position.Right} id="out" />
      {record.kind === 'agent' && (
        <>
          <Handle type="source" position={Position.Right} id="permission" style={{ top: '30%' }} />
          <Handle type="source" position={Position.Right} id="activity" style={{ top: '72%' }} />
          <Handle type="target" position={Position.Right} id="recipient" style={{ top: '50%' }} />
        </>
      )}
      {record.kind === 'resource' && (
        <>
          <Handle type="target" position={Position.Left} id="permission" style={{ top: '26%' }} />
          <Handle type="target" position={Position.Left} id="activity" style={{ top: '72%' }} />
        </>
      )}
      {record.kind === 'interaction' && (
        <>
          <Handle type="target" position={Position.Right} id="triggered" style={{ top: '15%' }} />
          <Handle type="source" position={Position.Right} id="triggers" style={{ top: '85%' }} />
          <Handle type="source" position={Position.Left} id="handoff" style={{ top: '77%' }} />
        </>
      )}
      <button
        type="button"
        title={`${singular}: ${record.label}\n${record.record_id}`}
        aria-label={`${singular}: ${record.label}`}
        aria-pressed={isSelected ?? false}
        aria-description={isOrigin ? 'Earliest supported evidence' : marker}
        onFocus={revealKeyboardFocus}
      >
        <span className="graph-record__icon"><Icon aria-hidden="true" /></span>
        <span className="graph-record__label">{record.label}</span>
      </button>
      {marker && <span className="graph-record__marker" aria-hidden="true">{marker}</span>}
    </div>
  )
})

function LaneHeading({ data }: NodeProps<LaneNode>) {
  return <span className={`graph-lane graph-lane--${data.kind}`} aria-hidden="true">{lanes[data.kind].label}</span>
}

const nodeTypes = { record: RecordCard, lane: LaneHeading } satisfies NodeTypes

const Relationship = memo(function Relationship({
  id, sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition, markerEnd, style, data,
}: EdgeProps<RelationshipEdge>) {
  const endpoints = { sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition }
  // Keep explicit event-to-event links in the gap beyond the interaction cards.
  const [path, labelX, labelY] = data?.sameLane
    ? getSmoothStepPath({ ...endpoints, borderRadius: 10, offset: 27 })
    : getBezierPath({ ...endpoints, curvature: 0.28 })

  return (
    <g>
      <title>{data?.title}</title>
      <BaseEdge id={id} path={path} markerEnd={markerEnd} style={style} interactionWidth={12} />
      {data?.label && (
        <text className="graph-edge-label" x={labelX} y={labelY - 5} aria-hidden="true">
          {data.label}
        </text>
      )}
    </g>
  )
})

const edgeTypes = { relationship: Relationship }

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
  return groups.sort((left, right) => right.length - left.length || left[0].id.localeCompare(right[0].id))
}

function orderInteractions(interactions: GraphNode[], triggers: Map<string, string[]>) {
  const remaining = new Map(interactions.map((node) => [node.id, node]))
  const children = new Set(interactions.flatMap((node) => triggers.get(node.id) ?? []))
  const roots = interactions.filter((node) => !children.has(node.id))
  const stack = [...roots, ...interactions].reverse().map((node) => node.id)
  const ordered: GraphNode[] = []

  // Follow the recorded trigger path before displaying any unrelated interactions.
  while (stack.length) {
    const id = stack.pop()!
    const node = remaining.get(id)
    if (!node) continue
    remaining.delete(id)
    ordered.push(node)
    for (const child of triggers.get(id) ?? []) stack.push(child)
  }
  return ordered
}

function layoutGraph(nodes: GraphNode[], edges: GraphEdge[], compact: boolean): FlowNode[] {
  const triggers = new Map<string, string[]>()
  const agentByRecord = new Map<string, string>()
  const resourceByRecord = new Map<string, string>()
  for (const edge of edges) {
    if (edge.kind === 'TRIGGERS') {
      const children = triggers.get(edge.source) ?? []
      children.push(edge.target)
      triggers.set(edge.source, children)
    }
    if (edge.kind === 'HAS_PERMISSION' || edge.kind === 'PERFORMED') {
      agentByRecord.set(edge.target, edge.source)
    }
    if (edge.kind === 'TARGETS' || edge.kind === 'ON_RESOURCE') {
      resourceByRecord.set(edge.source, edge.target)
    }
  }

  const xFor = (kind: GraphNodeKind) => compact ? lanes[kind].compactX : lanes[kind].x
  const availableKinds = new Set(nodes.map(({ kind }) => kind))
  const positioned: FlowNode[] = laneKinds.filter((kind) => availableKinds.has(kind)).map((kind) => ({
    id: `lane:${kind}`,
    type: 'lane',
    position: { x: xFor(kind), y: -34 },
    data: { kind },
    draggable: false,
    focusable: false,
    style: { pointerEvents: 'none' },
  }))

  let startY = 0
  for (const group of connectedGroups(nodes, edges)) {
    const kinds: Record<GraphNodeKind, GraphNode[]> = { agent: [], permission: [], interaction: [], resource: [] }
    for (const record of group) kinds[record.kind].push(record)
    for (const records of Object.values(kinds)) records.sort((left, right) => left.id.localeCompare(right.id))
    kinds.interaction = orderInteractions(kinds.interaction, triggers)

    const firstRelationship = new Map<string, number>()
    for (const [index, record] of [...kinds.interaction, ...kinds.permission].entries()) {
      for (const id of [agentByRecord.get(record.id), resourceByRecord.get(record.id)]) {
        if (id && !firstRelationship.has(id)) firstRelationship.set(id, index)
      }
    }
    const rank = (id: string) => firstRelationship.get(id) ?? group.length
    kinds.agent.sort((left, right) => rank(left.id) - rank(right.id))
    kinds.resource.sort((left, right) => rank(left.id) - rank(right.id))
    kinds.permission.sort((left, right) =>
      rank(agentByRecord.get(left.id) ?? '') - rank(agentByRecord.get(right.id) ?? '')
      || rank(resourceByRecord.get(left.id) ?? '') - rank(resourceByRecord.get(right.id) ?? ''),
    )

    const height = Math.max(...laneKinds.map((kind) => {
      const { height, gap } = lanes[kind]
      return (height + gap) * kinds[kind].length - gap
    }))

    for (const kind of laneKinds) {
      const { height: cardHeight, gap } = lanes[kind]
      const records = kinds[kind]
      if (!records.length) continue

      // Keep intermediate records together so related endpoints remain easy to trace.
      const isEndpoint = kind === 'agent' || kind === 'resource'
      const rowHeight = isEndpoint ? (height + gap) / records.length : cardHeight + gap
      const inset = (height + cardHeight - rowHeight * records.length) / 2
      records.forEach((record, index) => {
        positioned.push({
          id: record.id,
          type: 'record',
          zIndex: 3,
          position: { x: xFor(kind), y: startY + inset + (index + 0.5) * rowHeight - cardHeight },
          data: { record },
        })
      })
    }
    startY += height + 39
  }
  return positioned
}

const evidenceStroke: Record<Emphasis, string> = {
  muted: '#292a2d',
  entity: '#b3b6bd',
  affected: '#a3a5a9',
  finding: '#be747a',
  origin: '#d18a90',
  step: '#d18a90',
}

function flowEdges(nodes: GraphNode[], edges: GraphEdge[], focus?: GraphFocus): RelationshipEdge[] {
  const highlighted = new Set(focus?.edgeIds)
  const order = new Map(focus?.orderedEdgeIds?.map((id, index) => [id, index + 1]))
  const names = new Map(nodes.map(({ id, label }) => [id, label]))
  return edges.map((edge) => {
    const active = highlighted.has(edge.id)
    const emphasis = active ? focus?.tone : focus && 'muted'
    const access = edge.kind === 'HAS_PERMISSION' || edge.kind === 'ON_RESOURCE'
    const trigger = edge.kind === 'TRIGGERS'
    const handoff = edge.kind === 'HANDED_TO'
    const sourceHandle = trigger ? 'triggers' : handoff ? 'handoff'
      : edge.kind === 'HAS_PERMISSION' ? 'permission' : edge.kind === 'PERFORMED' ? 'activity' : 'out'
    const targetHandle = trigger ? 'triggered' : handoff ? 'recipient'
      : edge.kind === 'ON_RESOURCE' ? 'permission' : edge.kind === 'TARGETS' ? 'activity' : 'in'
    const stroke = emphasis ? evidenceStroke[emphasis] : access ? '#505156' : '#73757a'
    const relation = edgeLabels[edge.kind]
    const index = order.get(edge.id)
    // Keep progression readable next to the interaction cards. Supporting edges
    // still expose their direction and relationship through the SVG tooltip.
    const incomingStep = trigger && focus?.tone === 'step' && edge.target === focus.selectedNodeId
    const label = active && index !== undefined ? `${index} · ${relation}`
      : active && incomingStep ? relation : undefined
    const title = `${names.get(edge.source) ?? edge.source} → ${relation} → ${names.get(edge.target) ?? edge.target}`

    return {
      id: edge.id,
      type: 'relationship',
      source: edge.source,
      target: edge.target,
      sourceHandle,
      targetHandle,
      ariaLabel: title,
      data: { title, label, sameLane: trigger },
      className: `graph-edge${emphasis ? ` graph-edge--${emphasis}` : ''}`,
      focusable: false,
      zIndex: active ? 2 : 0,
      style: {
        stroke,
        strokeWidth: active ? 2.3 : 1.25,
        strokeDasharray: !active && (trigger || handoff) ? '4 4' : undefined,
      },
      markerEnd: { type: MarkerType.ArrowClosed, color: stroke, width: 14, height: 14 },
    }
  })
}

function GraphViewport({ focus }: { focus?: GraphFocus }) {
  const { fitView } = useReactFlow()
  const initialized = useNodesInitialized()
  const previous = useRef<GraphFocus | undefined>(undefined)
  const zoom = useStore(({ transform }) => Math.round(transform[2] * 100))

  useEffect(() => {
    if (!initialized || previous.current === focus) return

    previous.current = focus
    const nodes = focus?.nodeIds.map((id) => ({ id }))
    const duration = window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 0 : 240
    void fitView({ ...fitViewOptions, nodes: nodes?.length ? nodes : undefined, duration })
  }, [fitView, focus, initialized])

  return (
    <Controls position="bottom-right" orientation="horizontal" showInteractive={false} fitViewOptions={fitViewOptions}>
      <span className="graph-zoom" aria-label={`Zoom level ${zoom}%`}>{zoom}%</span>
    </Controls>
  )
}

function GraphCanvas({ nodes, edges, focus, onNodeSelect, compact }: GraphProps & { compact: boolean }) {
  const layout = useMemo(() => layoutGraph(nodes, edges, compact), [nodes, edges, compact])
  const [positioned, setPositioned, onNodesChange] = useNodesState(layout)

  useEffect(() => setPositioned(layout), [layout, setPositioned])

  const visibleNodes = useMemo(() => {
    if (!focus) return positioned

    const highlighted = new Set(focus.nodeIds)
    return positioned.map((node): FlowNode => {
      if (node.type !== 'record') return node
      if (!highlighted.has(node.id)) return { ...node, data: { ...node.data, emphasis: 'muted' } }

      const isSelected = focus.selectedNodeId === node.id
      const isOrigin = focus.originNodeId === node.id
      const emphasis = focus.tone === 'origin' ? 'entity' : focus.tone
      return {
        ...node,
        data: { ...node.data, emphasis, isOrigin, isSelected, stepNumber: isSelected ? focus.stepNumber : undefined },
      }
    })
  }, [positioned, focus])
  const visibleEdges = useMemo(() => flowEdges(nodes, edges, focus), [nodes, edges, focus])

  return (
    <ReactFlow<FlowNode, RelationshipEdge>
      nodes={visibleNodes}
      edges={visibleEdges}
      nodeTypes={nodeTypes}
      edgeTypes={edgeTypes}
      onNodesChange={onNodesChange}
      onNodeClick={(_, node) => {
        if (node.type === 'record') onNodeSelect(node.data.record)
      }}
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
      maxZoom={2.5}
      zoomActivationKeyCode={['Control', 'Meta']}
      zoomOnScroll={false}
      zoomOnDoubleClick={false}
      preventScrolling={false}
      colorMode="dark"
      ariaLabelConfig={{
        'controls.zoomIn.ariaLabel': 'Zoom in',
        'controls.zoomOut.ariaLabel': 'Zoom out',
        'controls.fitView.ariaLabel': 'Fit graph',
      }}
      proOptions={{ hideAttribution: true }}
    >
      <Background color="#303135" gap={24} size={1} />
      <GraphViewport focus={focus} />
    </ReactFlow>
  )
}

export function IntelligenceGraph(props: GraphProps) {
  const frame = useRef<HTMLDivElement>(null)
  const [compact, setCompact] = useState(false)

  useLayoutEffect(() => {
    const element = frame.current
    if (!element) return

    const update = () => setCompact(element.clientWidth < 575)
    const observer = new ResizeObserver(update)
    update()
    observer.observe(element)
    return () => observer.disconnect()
  }, [])

  return (
    <div
      ref={frame}
      className={compact ? 'intelligence-graph intelligence-graph--compact' : 'intelligence-graph'}
      role="region"
      aria-label="Interactive intelligence graph"
    >
      <GraphCanvas key={compact ? 'compact' : 'wide'} compact={compact} {...props} />
    </div>
  )
}
