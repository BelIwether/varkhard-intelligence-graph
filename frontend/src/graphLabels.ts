import type { Rect } from '@xyflow/react'

type TriggerLabel = { id: string; text: string; source: Rect; target: Rect }

const clearance = 4
const labelHeight = 24

function horizontalSpace(anchor: number, width: number, occupied: Rect[]) {
  let right = anchor
  for (const box of occupied) {
    if (box.x - clearance >= right + width) break
    if (box.x + box.width + clearance > right) right = box.x + box.width + clearance
  }

  let left = anchor
  for (let index = occupied.length - 1; index >= 0; index--) {
    const box = occupied[index]
    if (box.x + box.width + clearance <= left) continue
    if (box.x - clearance < left + width) left = box.x - clearance - width
  }

  return right - anchor <= anchor - left ? right : left
}

export function placeTriggerLabels(labels: TriggerLabel[], obstacles: Rect[]) {
  const placed = new Map<string, Rect>()
  const occupied = [...obstacles]

  for (const { id, text, source, target } of labels) {
    const width = 12 + text.length * 6
    const anchorX = Math.max(source.x + source.width, target.x + target.width) + 8
    const sourceY = source.y + source.height * .85
    const targetY = target.y + target.height * .15
    const anchorY = (sourceY + targetY - labelHeight) / 2
    let best: Rect | undefined
    let closest = Infinity

    // Try the route midpoint and nearby rows. Each row is searched in both
    // directions so even crowded or manually rearranged graphs have a free slot.
    for (const offset of [0, -12, 12, -24, 24, -36, 36]) {
      const y = anchorY + offset
      const row = occupied.filter((box) =>
        box.y - clearance < y + labelHeight && box.y + box.height + clearance > y,
      ).sort((left, right) => left.x - right.x)
      const x = horizontalSpace(anchorX, width, row)
      const distance = Math.hypot(x - anchorX, offset)
      if (distance < closest) {
        best = { x, y, width, height: labelHeight }
        closest = distance
      }
      if (distance === 0) break
    }

    if (best) {
      placed.set(id, best)
      occupied.push(best)
    }
  }

  return placed
}
