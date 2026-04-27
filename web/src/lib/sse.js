import { writable } from 'svelte/store'

export const connected = writable(false)
export const events = writable([])

let cap = 300
let paused = false
let filter = ''
let allEvents = []

export const capStore = writable(300)
export const pausedStore = writable(false)
export const filterStore = writable('')

capStore.subscribe(v => { cap = v })
pausedStore.subscribe(v => { paused = v })
filterStore.subscribe(v => {
  filter = v
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
  allEvents = []
  events.set([])
}

const es = new EventSource(`${window.location.origin}/events`)

es.onopen = () => connected.set(true)
es.onerror = () => connected.set(false)

es.onmessage = (msg) => {
  if (paused) return
  let e
  try { e = JSON.parse(msg.data) } catch { return }
  if (!matches(e)) return

  allEvents.unshift(e)
  if (allEvents.length > cap) allEvents = allEvents.slice(0, cap)
  events.set(allEvents)
}