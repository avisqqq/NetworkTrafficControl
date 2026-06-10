<script>
  import { onMount } from 'svelte'
  import { fetchAnalysisSummary, fetchNetworkDevices, inspectPacket } from './api.js'

  const emptySummary = { peers: [], services: [], countries: [], blocked: [], totals: {} }

  let summary = emptySummary
  let devices = []
  let discoveredPeers = {}
  let discoveringPeers = {}
  let discoveringCountries = false
  let loading = false
  let error = ''

  $: peers = summary.peers || []
  $: services = summary.services || []
  $: countries = summary.countries || []
  $: blocked = summary.blocked || []
  $: totals = summary.totals || {}
  $: totalPackets = totals.packets ?? peers.reduce((sum, row) => sum + (Number(row.packets) || 0), 0)
  $: totalBytes = totals.bytes ?? peers.reduce((sum, row) => sum + (Number(row.bytes) || 0), 0)
  $: hostCount = totals.hosts ?? new Set(peers.map(row => row.host_ip).filter(Boolean)).size
  $: peerCount = totals.peers ?? new Set(peers.map(row => row.peer_ip).filter(Boolean)).size
  $: peerGroups = groupedPeers(peers)
  $: serviceGroups = groupedServices(services)
  $: countryGroups = groupedCountries(countries)
  $: blockedGroups = groupedPeers(blocked)
  $: deviceNames = Object.fromEntries((devices || [])
    .filter(device => device.ip && device.hostname)
    .map(device => [device.ip, device.hostname]))

  function formatNumber(value) {
    const number = Number(value) || 0
    return number.toLocaleString(undefined, { maximumFractionDigits: 2 })
  }

  function formatBytes(value) {
    const bytes = Number(value) || 0
    if (bytes < 1024) return `${bytes.toLocaleString()} B`
    const units = ['KB', 'MB', 'GB', 'TB']
    let current = bytes / 1024
    let unit = units[0]
    for (let i = 1; i < units.length && current >= 1024; i++) {
      current /= 1024
      unit = units[i]
    }
    return `${current.toLocaleString(undefined, { maximumFractionDigits: 1 })} ${unit}`
  }

  function formatDate(value) {
    if (!value) return '—'
    return new Intl.DateTimeFormat(undefined, {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    }).format(new Date(value))
  }

  function peerName(row) {
    return discoveredPeers[row?.peer_ip] || deviceNames[row?.peer_ip] || row?.peer_org || row?.peer_as_name || row?.peer_isp || row?.peer_ip || 'Unknown peer'
  }

  function peerSubtitle(row) {
    const flags = [
      row?.peer_country_code,
      row?.peer_hosting ? 'hosting' : '',
      row?.peer_proxy ? 'proxy' : '',
      row?.peer_mobile ? 'mobile' : '',
    ].filter(Boolean)
    return flags.length ? `${row.peer_ip} · ${flags.join(' · ')}` : row?.peer_ip || '—'
  }

  function serviceName(row) {
    return row?.service || (row?.port ? `Port ${row.port}` : 'Unknown service')
  }

  function joined(values, fallback = '—') {
    const unique = [...new Set(values.filter(Boolean))]
    return unique.length ? unique.join(', ') : fallback
  }

  function newest(a, b) {
    if (!a) return b || ''
    if (!b) return a
    return new Date(a) > new Date(b) ? a : b
  }

  function sortedGroups(groups) {
    return [...groups.values()].sort((a, b) => (Number(b.bytes) || 0) - (Number(a.bytes) || 0))
  }

  function groupedPeers(rows) {
    const groups = new Map()
    for (const row of rows || []) {
      const key = `${row.host_ip || ''}|${row.peer_ip || ''}`
      const current = groups.get(key) || {
        ...row,
        packets: 0,
        bytes: 0,
        services: [],
        directions: [],
        actions: [],
        rows: 0,
      }
      current.packets += Number(row.packets) || 0
      current.bytes += Number(row.bytes) || 0
      current.services.push(serviceName(row))
      current.directions.push(row.direction)
      current.actions.push(row.action)
      current.last_seen = newest(current.last_seen, row.last_seen)
      current.rows += 1
      groups.set(key, current)
    }
    return sortedGroups(groups)
  }

  function groupedServices(rows) {
    const groups = new Map()
    for (const row of rows || []) {
      const key = `${row.proto || ''}|${serviceName(row)}`
      const current = groups.get(key) || {
        ...row,
        service: serviceName(row),
        hostIPs: [],
        directions: [],
        actions: [],
        packets: 0,
        bytes: 0,
      }
      current.hostIPs.push(row.host_ip)
      current.directions.push(row.direction)
      current.actions.push(row.action)
      current.packets += Number(row.packets) || 0
      current.bytes += Number(row.bytes) || 0
      groups.set(key, current)
    }
    return sortedGroups(groups)
  }

  function groupedCountries(rows) {
    const groups = new Map()
    for (const row of rows || []) {
      const country = row.country_code || 'UNKNOWN'
      const current = groups.get(country) || {
        ...row,
        country_code: country,
        hostIPs: [],
        directions: [],
        actions: [],
        packets: 0,
        bytes: 0,
      }
      current.hostIPs.push(row.host_ip)
      current.directions.push(row.direction)
      current.actions.push(row.action)
      current.packets += Number(row.packets) || 0
      current.bytes += Number(row.bytes) || 0
      groups.set(country, current)
    }
    return sortedGroups(groups)
  }

  function canDiscover(row) {
    return row?.peer_ip && !row?.peer_org && !row?.peer_as_name && !row?.peer_isp && !deviceNames[row.peer_ip]
  }

  function missingCountryPeers() {
    return peerGroups.filter(peer => peer.peer_ip && (!peer.peer_country_code || peer.peer_country_code === 'UNKNOWN'))
  }

  function discoveredName(endpoint) {
    const geo = endpoint?.geo || {}
    return geo.organization || geo.as_name || geo.isp || geo.country || endpoint?.ip || ''
  }

  async function discoverPeer(row) {
    if (!row?.peer_ip || discoveringPeers[row.peer_ip]) return

    discoveringPeers = { ...discoveringPeers, [row.peer_ip]: true }
    try {
      const result = await inspectPacket({
        seq: 0,
        time: new Date().toISOString(),
        src: row.host_ip || '0.0.0.0',
        dst: row.peer_ip,
        src_port: 0,
        dst_port: Number(row.port) || 0,
        pkt_size: 0,
        proto: row.proto || 'TCP',
        action: row.action || 'PASS',
        ip_version: row.peer_ip.includes(':') ? 6 : 4,
        direction: row.direction || 'EGRESS',
        tcp_flags: 0,
      })
      const name = discoveredName(result.destination)
      if (name) {
        discoveredPeers = { ...discoveredPeers, [row.peer_ip]: name }
      }
      await load(false)
    } catch {
      error = `Could not discover ${row.peer_ip}`
    } finally {
      discoveringPeers = { ...discoveringPeers, [row.peer_ip]: false }
    }
  }

  async function discoverCountries() {
    const peers = missingCountryPeers()
    if (discoveringCountries || peers.length === 0) return

    discoveringCountries = true
    error = ''
    try {
      for (const peer of peers.slice(0, 12)) {
        await discoverPeer(peer)
      }
      await load(false)
    } catch {
      error = 'Could not discover countries'
    } finally {
      discoveringCountries = false
    }
  }

  async function load(showLoading = true) {
    loading = showLoading
    error = ''
    try {
      const [nextSummary, nextDevices] = await Promise.all([
        fetchAnalysisSummary(100),
        fetchNetworkDevices(),
      ])
      summary = nextSummary || emptySummary
      devices = nextDevices || []
    } catch {
      summary = emptySummary
    } finally {
      loading = false
    }
  }

  onMount(load)
</script>

<main class="container page stack">
  <section class="card page-panel analysis-panel">
    <div class="panel-header">
      <span class="panel-title">Analysis summary</span>
      <button class="btn btn-ghost" type="button" on:click={load} disabled={loading}>
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
          <path d="M21 12a9 9 0 1 1-3-6.7"/>
          <polyline points="21 3 21 9 15 9"/>
        </svg>
        {loading ? 'Loading' : 'Refresh'}
      </button>
    </div>

    <div class="panel-body">
      {#if error}
        <div class="entries-empty error">{error}</div>
      {/if}

      <div class="analysis-stat-grid">
        <div><span>Hosts</span><strong>{hostCount}</strong></div>
        <div><span>Peers</span><strong>{peerCount}</strong></div>
        <div><span>Services</span><strong>{formatNumber(totals.services ?? services.length)}</strong></div>
        <div><span>Countries</span><strong>{formatNumber(totals.countries ?? countries.length)}</strong></div>
        <div><span>Packets</span><strong>{formatNumber(totalPackets)}</strong></div>
        <div><span>Bytes</span><strong>{formatBytes(totalBytes)}</strong></div>
      </div>

      <div class="analysis-grid">
        <section class="analysis-block">
          <div class="analysis-block-title">Top peers</div>
          {#each peerGroups as peer}
            <div class="analysis-row">
              <div>
                <strong class="analysis-name">
                  {peerName(peer)}
                  {#if canDiscover(peer)}
                    <button class="analysis-discover" type="button" on:click={() => discoverPeer(peer)} disabled={discoveringPeers[peer.peer_ip]}>
                      {discoveringPeers[peer.peer_ip] ? '...' : 'Discover'}
                    </button>
                  {/if}
                </strong>
                <span>{peerSubtitle(peer)} · {joined(peer.directions)} · {joined(peer.actions)} · {joined(peer.services)} · {formatDate(peer.last_seen)}</span>
              </div>
              <b>{formatBytes(peer.bytes)}</b>
            </div>
          {:else}
            <div class="host-empty">No peer counters yet</div>
          {/each}
        </section>

        <section class="analysis-block">
          <div class="analysis-block-title">Top services</div>
          {#each serviceGroups as service}
            <div class="analysis-row">
              <div>
                <strong>{service.service}</strong>
                <span>{service.proto} · {joined(service.directions)} · {joined(service.actions)} · {joined(service.hostIPs, 'all hosts')}</span>
              </div>
              <b>{formatBytes(service.bytes)}</b>
            </div>
          {:else}
            <div class="host-empty">No service counters yet</div>
          {/each}
        </section>

        <section class="analysis-block">
          <div class="analysis-block-title analysis-block-title-row">
            <span>Countries</span>
            {#if missingCountryPeers().length > 0}
              <button class="analysis-discover" type="button" on:click={discoverCountries} disabled={discoveringCountries}>
                {discoveringCountries ? '...' : 'Discover'}
              </button>
            {/if}
          </div>
          {#each countryGroups as country}
            <div class="analysis-row">
              <div>
                <strong>{country.country_code}</strong>
                <span>{joined(country.directions)} · {joined(country.actions)} · {joined(country.hostIPs, 'all hosts')}</span>
              </div>
              <b>{formatBytes(country.bytes)}</b>
            </div>
          {:else}
            <div class="host-empty">No country counters yet</div>
          {/each}
        </section>

        <section class="analysis-block">
          <div class="analysis-block-title">Blocked peers</div>
          {#each blockedGroups as item}
            <div class="analysis-row blocked">
              <div>
                <strong class="analysis-name">
                  {peerName(item)}
                  {#if canDiscover(item)}
                    <button class="analysis-discover" type="button" on:click={() => discoverPeer(item)} disabled={discoveringPeers[item.peer_ip]}>
                      {discoveringPeers[item.peer_ip] ? '...' : 'Discover'}
                    </button>
                  {/if}
                </strong>
                <span>{peerSubtitle(item)} · {joined(item.services)} · {formatDate(item.last_seen)}</span>
              </div>
              <b>{formatBytes(item.bytes)}</b>
            </div>
          {:else}
            <div class="host-empty">No blocked counters yet</div>
          {/each}
        </section>
      </div>
    </div>
  </section>
</main>
