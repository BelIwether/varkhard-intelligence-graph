import { ChevronRight, Search } from 'lucide-react'
import { useId, useMemo, useRef, useState, type KeyboardEvent } from 'react'
import type { Dashboard, Finding, GraphNode } from './api'
import './search.css'

const categories = {
  all: 'All records',
  agent: 'AI agents',
  resource: 'Resources',
  action: 'Actions',
  finding: 'Finding types',
  interaction: 'Interactions',
} as const

const kindLabels = {
  agent: 'AI agent',
  resource: 'Resource',
  permission: 'Permission',
  interaction: 'Interaction',
} as const

const resultLimit = 8

type Category = keyof typeof categories
type RecordMatch = { kind: 'node'; node: GraphNode } | { kind: 'finding'; finding: Finding }
type SearchEntry = RecordMatch & {
  id: string
  label: string
  detail: string
  searchable: string
  action: string
}

function normalize(value: string) {
  return value.toLowerCase().replace(/[\s_-]+/g, ' ').trim()
}

function indexDashboard(data: Dashboard): SearchEntry[] {
  const permissions = new Map(data.permissions.map((permission) => [permission.id, permission]))
  const interactions = new Map(data.interactions.map((interaction) => [interaction.id, interaction]))

  return [
    ...data.nodes.map((node): SearchEntry => {
      const action = node.kind === 'permission' ? permissions.get(node.record_id)?.action
        : node.kind === 'interaction' ? interactions.get(node.record_id)?.action : undefined

      return {
        kind: 'node',
        node,
        id: node.id,
        label: node.label,
        detail: `${kindLabels[node.kind]} · ${node.record_id}`,
        searchable: normalize(`${node.label} ${node.record_id} ${node.id} ${action ?? ''}`),
        action: normalize(action ?? ''),
      }
    }),
    ...data.findings.map((finding): SearchEntry => ({
      kind: 'finding',
      finding,
      id: `finding:${finding.id}`,
      label: finding.category,
      detail: `Finding · ${finding.rule_id}`,
      searchable: normalize(`${finding.category} ${finding.rule_id} ${finding.id}`),
      action: '',
    })),
  ]
}

function matchEntry(entry: SearchEntry, category: Category, query: string) {
  if (category === 'action') return Boolean(entry.action) && entry.action.includes(query)
  const kind = entry.kind === 'finding' ? 'finding' : entry.node.kind
  return (category === 'all' || category === kind) && entry.searchable.includes(query)
}

export function RecordSearch({ data, onNodeSelect, onFindingSelect }: {
  data: Dashboard
  onNodeSelect: (node: GraphNode) => void
  onFindingSelect: (finding: Finding) => void
}) {
  const [query, setQuery] = useState('')
  const [category, setCategory] = useState<Category>('all')
  const [open, setOpen] = useState(false)
  const input = useRef<HTMLInputElement>(null)
  const firstResult = useRef<HTMLButtonElement>(null)
  const resultId = useId()
  const index = useMemo(() => indexDashboard(data), [data])
  const search = normalize(query)
  const showResults = open && Boolean(search || category !== 'all')
  const { results, total } = useMemo(() => {
    const results: SearchEntry[] = []
    let total = 0
    if (showResults) {
      for (const entry of index) {
        if (!matchEntry(entry, category, search)) continue
        if (results.length < resultLimit) results.push(entry)
        total += 1
      }
    }
    return { results, total }
  }, [category, index, search, showResults])

  function selectResult(result: SearchEntry) {
    if (result.kind === 'node') onNodeSelect(result.node)
    else onFindingSelect(result.finding)
    setQuery('')
    input.current?.focus()
    setOpen(false)
  }

  function handleKeyDown(event: KeyboardEvent<HTMLDivElement>) {
    if (event.key === 'Escape' && showResults) {
      event.preventDefault()
      input.current?.focus()
      setOpen(false)
    }
    if (event.key === 'ArrowDown' && event.target === input.current && firstResult.current) {
      event.preventDefault()
      firstResult.current.focus()
    }
  }

  return (
    <div
      className="record-search"
      onFocus={() => setOpen(true)}
      onBlur={({ currentTarget, relatedTarget }) => {
        if (!currentTarget.contains(relatedTarget)) setOpen(false)
      }}
      onKeyDown={handleKeyDown}
    >
      <form className="record-search-form" role="search" onSubmit={(event) => {
        event.preventDefault()
        if (results[0]) selectResult(results[0])
        else setOpen(true)
      }}>
        <div className="record-search-field">
          <Search size={15} aria-hidden="true" />
          <input
            ref={input}
            type="search"
            autoComplete="off"
            placeholder="Search records"
            aria-label="Search graph records"
            aria-controls={showResults ? resultId : undefined}
            value={query}
            onClick={() => setOpen(true)}
            onChange={(event) => {
              setQuery(event.target.value)
              setOpen(true)
            }}
          />
        </div>
        <select aria-label="Search category" value={category} onChange={(event) => {
          setCategory(event.target.value as Category)
          setOpen(true)
        }}>
          {Object.entries(categories).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
        </select>
      </form>

      {showResults && (
        <section id={resultId} className="record-search-results" aria-label="Search results">
          <p className="record-search-status" role="status">
            {!total ? 'No graph records match your search.'
              : total > resultLimit ? `${results.length} of ${total} matches`
                : `${total} ${total === 1 ? 'match' : 'matches'}`}
          </p>
          {total > 0 && (
            <ul className="record-search-list">
              {results.map((result, index) => (
                <li key={result.id}>
                  <button type="button" ref={index === 0 ? firstResult : undefined} onClick={() => selectResult(result)}>
                    <strong>{result.label}</strong>
                    <small>{result.detail}</small>
                    <ChevronRight size={15} aria-hidden="true" />
                  </button>
                </li>
              ))}
            </ul>
          )}
        </section>
      )}
    </div>
  )
}
