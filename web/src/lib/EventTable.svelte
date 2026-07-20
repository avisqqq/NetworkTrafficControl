<script>
  import { get } from 'svelte/store'
  import { events, pausedStore } from './sse.js'

  export let selectedPacket = null
  export let policies = []

  let resumeAfterHover = false
  let resumeAfterScroll = false

  function holdStream() {
    if (!get(pausedStore)) {
      pausedStore.set(true)
      resumeAfterHover = true
    }
  }

  function releaseStream() {
    if (resumeAfterHover) {
      pausedStore.set(false)
      resumeAfterHover = false
    }
  }

  function selectPacket(packet) {
    selectedPacket = packet
  }

  function handleScroll(event) {
    const isAtTop = event.currentTarget.scrollTop <= 2

    if (!isAtTop && !get(pausedStore)) {
      pausedStore.set(true)
      resumeAfterScroll = true
      return
    }

    if (isAtTop && resumeAfterScroll) {
      pausedStore.set(false)
      resumeAfterScroll = false
    }
  }

  function matchingPolicy(packet) {
    if ((packet.action || '').toUpperCase() !== 'PORT_DROP') return null
    const protocol = (packet.proto || '').toUpperCase()
    const direction = (packet.direction || '').toUpperCase()
    return policies.find(rule =>
      rule.protocol === protocol &&
      rule.direction === direction &&
      (
        (rule.ip === packet.src && Number(rule.port) === Number(packet.src_port)) ||
        (rule.ip === packet.dst && Number(rule.port) === Number(packet.dst_port))
      )
    )
  }

  function displayedAction(packet) {
    return (packet.action || '').toUpperCase() === 'PORT_DROP' ? 'DROP' : (packet.action || '—')
  }

  function dropReason(packet) {
    const rule = matchingPolicy(packet)
    if (rule) return `${rule.ip}:${rule.port}/${rule.protocol}→${rule.direction}`
    if ((packet.action || '').toUpperCase() === 'PORT_DROP') return 'Policy rule'
    if ((packet.action || '').toUpperCase() === 'ONLY_LOCAL_DROP') return 'Only-local restriction'
    if ((packet.action || '').toUpperCase() === 'DROP') return 'Blacklist'
    return '—'
  }
</script>

<div
  class="table-card"
  role="region"
  aria-label="Live traffic events"
  on:mouseenter={holdStream}
  on:mouseleave={releaseStream}
  on:focusin={holdStream}
  on:focusout={releaseStream}
  on:scroll={handleScroll}
>
  <table class="table">
    <thead>
      <tr>
        <th class="right">#</th>
        <th>Time</th>
        <th>Dir</th>
        <th>Proto</th>
        <th>Action</th>
        <th>Reason</th>
        <th>Source</th>
        <th>Destination</th>
      </tr>
    </thead>
    <tbody>
      {#each $events as e (e.seq)}
        <tr class:selected-packet={selectedPacket?.seq === e.seq}>
          <td class="right muted packet-info-cell">
            <span>{e.seq}</span>
            <span class="packet-info-wrap" role="group">
              <button class="packet-info-btn" type="button" aria-label="Open packet details" on:click={() => selectPacket(e)}>i</button>
            </span>
          </td>
          <td class="muted">{e.time}</td>
          <td><span class="badge {(e.direction || 'ingress').toLowerCase()}">{e.direction || '—'}</span></td>
          <td><span class="badge {(e.proto || 'other').toLowerCase()}">{e.proto || '—'}</span></td>
          <td><span class="badge {displayedAction(e).toLowerCase()}">{displayedAction(e)}</span></td>
          <td class="drop-reason" title={dropReason(e)}>{dropReason(e)}</td>
          <td class="addr">{e.src}</td>
          <td class="addr">{e.dst}</td>
        </tr>
      {/each}
    </tbody>
  </table>

  {#if $events.length === 0}
    <div style="display:flex;align-items:center;justify-content:center;height:120px;color:var(--text-3);font-size:13px">
      Waiting for events…
    </div>
  {/if}
</div>
