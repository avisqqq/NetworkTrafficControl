<script>
  import { onMount } from 'svelte'
  import { fetchList, addIP, removeIP, inspectPacket } from './api.js'

  export let selectedPacket = null

  let listType = 'black'
  let ipInput = ''
  let entries = []
  let loading = false
  let error = ''
  let inspectOpen = false
  let lastPacketSeq = null
  let inspectLoading = false
  let inspectError = ''
  let inspectResult = null
  let showEmptyPacket = false
  let showEmptySource = false
  let showEmptyDestination = false

  const titles = {
    black: 'Blacklist',
    white: 'Whitelist',
    local: 'Only local'
  }

  $: if ((selectedPacket?.seq ?? null) !== lastPacketSeq) {
    lastPacketSeq = selectedPacket?.seq ?? null
    inspectOpen = false
    inspectLoading = false
    inspectError = ''
    inspectResult = null
    showEmptyPacket = false
    showEmptySource = false
    showEmptyDestination = false
  }

  async function load() {
    loading = true
    error = ''
    try {
      const data = await fetchList(listType)
      entries = data ?? []
    } catch {
      error = 'Failed to load'
    } finally {
      loading = false
    }
  }

  async function handleAdd() {
    const ip = ipInput.trim()
    if (!ip) return
    await addIP(listType, ip)
    ipInput = ''
    await load()
  }

  async function handleRemove() {
    const ip = ipInput.trim()
    if (!ip) return
    await removeIP(listType, ip)
    ipInput = ''
    await load()
  }

  function selectEntry(ip) {
    ipInput = ip
  }

  function portValue(port) {
    const value = Number(port)
    return value > 0 ? String(value) : '—'
  }

  function endpoint(ip, port) {
    const value = portValue(port)
    if (value === '—') return ip || '—'
    return `${ip || '—'}:${value}`
  }

  function tcpFlags(flags) {
    const value = Number(flags) || 0
    if (!value) return '—'

    const names = [
      [1, 'FIN'],
      [2, 'SYN'],
      [4, 'RST'],
      [8, 'PSH'],
      [16, 'ACK'],
      [32, 'URG'],
      [64, 'ECE'],
      [128, 'CWR']
    ]
      .filter(([bit]) => value & bit)
      .map(([, name]) => name)

    return names.length ? `${names.join(', ')} (${value})` : String(value)
  }

  function ipScope(ip) {
    if (!ip) return '—'

    const value = ip.toLowerCase()
    if (value === 'localhost' || value === '::1' || value.startsWith('fc') || value.startsWith('fd') || value.startsWith('fe80:')) {
      return 'Private network'
    }

    const parts = value.split('.').map(Number)
    if (parts.length === 4 && parts.every(part => Number.isInteger(part) && part >= 0 && part <= 255)) {
      const [a, b] = parts
      if (a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254)) {
        return 'Private network'
      }
    }

    return 'GeoIP not configured'
  }

  function geoValue(value) {
    if (value === true) return 'yes'
    if (value === false) return 'no'
    return value || '—'
  }

  function hasValue(value) {
    return value !== undefined && value !== null && value !== '' && value !== false
  }

  function visibleRows(rows, showEmpty) {
    return showEmpty ? rows : rows.filter(row => hasValue(row[1]))
  }

  function endpointRows(endpoint) {
    if (!endpoint) return []
    return [
      ['IP', endpoint.ip],
      ['Endpoint', endpoint.endpoint],
      ['Scope', endpoint.scope],
      ['Port', portValue(endpoint.port)],
      ['Service', endpoint.service],
      ['Hint', endpoint.analysis_hint],
      ['Geo provider', endpoint.geo?.provider],
      ['Geo status', endpoint.geo?.status],
      ['Geo message', endpoint.geo?.message],
      ['Country', [endpoint.geo?.country, endpoint.geo?.country_code].filter(Boolean).join(' ')],
      ['Continent', [endpoint.geo?.continent, endpoint.geo?.continent_code].filter(Boolean).join(' ')],
      ['Region', [endpoint.geo?.region_name, endpoint.geo?.region].filter(Boolean).join(' ')],
      ['City', endpoint.geo?.city],
      ['District', endpoint.geo?.district],
      ['ZIP', endpoint.geo?.zip],
      ['Coordinates', endpoint.geo?.latitude || endpoint.geo?.longitude ? `${endpoint.geo.latitude}, ${endpoint.geo.longitude}` : ''],
      ['Timezone', endpoint.geo?.timezone],
      ['UTC offset', endpoint.geo?.utc_offset],
      ['Currency', endpoint.geo?.currency],
      ['ISP', endpoint.geo?.isp],
      ['Organization', endpoint.geo?.organization],
      ['AS', endpoint.geo?.as],
      ['AS name', endpoint.geo?.as_name],
      ['Mobile', endpoint.geo?.mobile],
      ['Proxy/VPN/Tor', endpoint.geo?.proxy],
      ['Hosting/DC', endpoint.geo?.hosting]
    ]
  }

  function packetRows(packet) {
    if (!packet) return []
    return [
      ['Time', packet.time],
      ['Direction', packet.direction],
      ['Protocol', packet.proto],
      ['Action', packet.action],
      ['Source', endpoint(packet.src, packet.src_port)],
      ['Source port', portValue(packet.src_port)],
      ['Source scope', ipScope(packet.src)],
      ['Destination', endpoint(packet.dst, packet.dst_port)],
      ['Destination port', portValue(packet.dst_port)],
      ['Destination scope', ipScope(packet.dst)],
      ['IP version', packet.ip_version],
      ['Packet size', packet.pkt_size ? `${packet.pkt_size} B` : ''],
      ['TCP flags', tcpFlags(packet.tcp_flags)]
    ]
  }

  function clearPacket() {
    selectedPacket = null
  }

  async function toggleInspect() {
    if (inspectOpen) {
      inspectOpen = false
      return
    }

    inspectOpen = true
    if (inspectResult || inspectLoading || !selectedPacket) return

    inspectLoading = true
    inspectError = ''
    try {
      inspectResult = await inspectPacket(selectedPacket)
    } catch (err) {
      inspectError = err.message || 'Inspection failed'
    } finally {
      inspectLoading = false
    }
  }

  onMount(load)
</script>

<aside class="panel">
  <div class="card">
    <div class="panel-header">
      <span class="panel-title">{titles[listType]}</span>
      <div class="tab-group">
        <button
          class="tab"
          class:active={listType === 'black'}
          on:click={() => { listType = 'black'; load() }}
        >Black</button>
        <button
          class="tab"
          class:active={listType === 'white'}
          on:click={() => { listType = 'white'; load() }}
        >White</button>
        <button
          class="tab"
          class:active={listType === 'local'}
          on:click={() => { listType = 'local'; load() }}
        >Local</button>
      </div>
    </div>

    <div class="panel-body">
      <input
        class="input"
        placeholder="e.g. 192.168.1.1"
        bind:value={ipInput}
        on:keydown={e => e.key === 'Enter' && handleAdd()}
      />

      <div class="btn-row">
        <button class="btn btn-success" on:click={handleAdd}>Add</button>
        <button class="btn btn-danger" on:click={handleRemove}>Remove</button>
        <button class="btn btn-ghost" on:click={load}>
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
            <path d="M21 12a9 9 0 1 1-3-6.7"/>
            <polyline points="21 3 21 9 15 9"/>
          </svg>
          Refresh
        </button>
      </div>

      <div class="entries-box">
        {#if loading}
          <div class="entries-empty">Loading…</div>
        {:else if error}
          <div class="entries-empty error">{error}</div>
        {:else if entries.length === 0}
          <div class="entries-empty">No entries</div>
        {:else}
          <ul class="entries-list">
            {#each entries as entry}
              <li>
                <button
                  class="entry"
                  class:selected={ipInput === entry.ip}
                  on:click={() => selectEntry(entry.ip)}
                >
                  <span
                    class="entry-dot"
                    class:black={listType === 'black'}
                    class:white={listType === 'white'}
                    class:local={listType === 'local'}
                  ></span>
                  {entry.ip}
                </button>
              </li>
            {/each}
          </ul>
        {/if}
      </div>
    </div>
  </div>

  <div class="card packet-details-card">
    <div class="panel-header">
      <span class="panel-title">Packet details</span>
      {#if selectedPacket}
        <div class="packet-detail-actions">
          <button class="btn btn-ghost inspect-btn" type="button" class:active={inspectOpen} on:click={toggleInspect}>Inspect</button>
          <button class="icon-btn" type="button" aria-label="Clear packet details" on:click={clearPacket}>
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
              <path d="M18 6 6 18"/>
              <path d="m6 6 12 12"/>
            </svg>
          </button>
        </div>
      {/if}
    </div>

    <div class="panel-body">
      {#if !selectedPacket}
        <div class="entries-empty">Click packet info</div>
      {:else}
        <div class="packet-detail-title">#{selectedPacket.seq}</div>
        <div class="packet-inspect-title-row">
          <div class="packet-inspect-title">Packet info</div>
          <button class="mini-toggle" type="button" class:active={showEmptyPacket} on:click={() => showEmptyPacket = !showEmptyPacket}>Show empty</button>
        </div>
        <div class="packet-detail-grid">
          {#each visibleRows(packetRows(selectedPacket), showEmptyPacket) as row}
            <span>{row[0]}</span><strong>{geoValue(row[1])}</strong>
          {/each}
        </div>

        {#if inspectOpen}
          <div class="packet-inspect">
            {#if inspectLoading}
              <div class="entries-empty">Inspecting…</div>
            {:else if inspectError}
              <div class="entries-empty error">{inspectError}</div>
            {:else if inspectResult}
              <div class="packet-inspect-section">
                <div class="packet-inspect-title-row">
                  <div class="packet-inspect-title">Source inspection</div>
                  <button class="mini-toggle" type="button" class:active={showEmptySource} on:click={() => showEmptySource = !showEmptySource}>Show empty</button>
                </div>
                <div class="packet-detail-grid inspect-grid">
                  {#each visibleRows(endpointRows(inspectResult.source), showEmptySource) as row}
                    <span>{row[0]}</span><strong>{geoValue(row[1])}</strong>
                  {/each}
                </div>
              </div>

              <div class="packet-inspect-section">
                <div class="packet-inspect-title-row">
                  <div class="packet-inspect-title">Destination inspection</div>
                  <button class="mini-toggle" type="button" class:active={showEmptyDestination} on:click={() => showEmptyDestination = !showEmptyDestination}>Show empty</button>
                </div>
                <div class="packet-detail-grid inspect-grid">
                  {#each visibleRows(endpointRows(inspectResult.destination), showEmptyDestination) as row}
                    <span>{row[0]}</span><strong>{geoValue(row[1])}</strong>
                  {/each}
                </div>
              </div>
            {/if}
          </div>
        {/if}
      {/if}
    </div>
  </div>
</aside>
