import { writable } from 'svelte/store'

export const connected = writable(false)
export const events = writable([])

let cap = 300
let paused = false
let filter = ''
let allEvents = []
let pendingEvents = []
let flushTimer = null
const flushIntervalMs = 100

export const capStore = writable(300)
export const pausedStore = writable(false)
export const filterStore = writable('')

capStore.subscribe(v => {
  cap = Math.min(5000, Math.max(10, Number(v) || 300))
  if (allEvents.length > cap) {
    allEvents = allEvents.slice(0, cap)
    events.set(allEvents)
  }
})
pausedStore.subscribe(v => { paused = v })
filterStore.subscribe(v => {
  filter = v
  pendingEvents = []
  events.set([])
  allEvents = []
})

function matches(e) {
  if (!filter) return true
  const q = filter.toLowerCase()
  return (
    String(e.seq).includes(q) ||
    (e.proto || '').toLowerCase().includes(q) ||
    (e.action || '').toLowerCase().includes(q) ||
    (e.direction || '').toLowerCase().includes(q) ||
    (e.src || '').toLowerCase().includes(q) ||
    (e.dst || '').toLowerCase().includes(q)
  )
}

export function clearEvents() {
  pendingEvents = []
  allEvents = []
  events.set([])
}

function scheduleFlush() {
  if (flushTimer) return
  flushTimer = window.setTimeout(flushEvents, flushIntervalMs)
}

function flushEvents() {
  flushTimer = null
  if (pendingEvents.length === 0) return

  allEvents = pendingEvents.reverse().concat(allEvents).slice(0, cap)
  pendingEvents = []
  events.set(allEvents)
}

const es = new EventSource(`${window.location.origin}/events`)

es.onopen = () => connected.set(true)
es.onerror = () => connected.set(false)

es.onmessage = (msg) => {
  if (paused) return
  let e
  try { e = JSON.parse(msg.data) } catch { return }
  if (!matches(e)) return

  pendingEvents.push(e)
  if (pendingEvents.length > cap) pendingEvents = pendingEvents.slice(-cap)
  scheduleFlush()
}
