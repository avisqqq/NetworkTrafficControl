<script>
  import { onMount } from 'svelte'
  import { addIP, fetchAnalysisSummary, fetchHostAnalysis, fetchKnownHosts, fetchList, fetchMetricsText, fetchNetworkDevices, removeIP } from './api.js'

  let devices = []
  let metricsText = ''
  let analysis = emptyAnalysis()
  let selectedAnalysis = emptyAnalysis()
  let reportAnalysis = emptyAnalysis()
  let selectedIP = ''
  let reportIP = ''
  let loading = false
  let summaryLoading = false
  let showKnownHosts = false
  let knownHosts = []
  let knownHostsLoaded = false
  let knownHostsLoading = false
  let blacklistMap = {}
  let onlyLocalMap = {}
  let error = ''
  let endpointTooltip = { text: '', x: 0, y: 0 }

  $: knownDevices = showKnownHosts ? knownDevicesFromHosts(knownHosts, devices) : []
  $: allDevices = [...devices, ...knownDevices]
  $: selectedDevice = visibleDevices.find(device => device.ip === selectedIP) || null
  $: reportDevice = allDevices.find(device => device.ip === reportIP) || null
  $: activeCount = visibleDevices.filter(device => isConnected(device)).length
  $: blockedCount = visibleDevices.filter(device => !device.active).length
  $: onlyLocalCount = visibleDevices.filter(device => device.onlyLocal).length
  $: selectedPeers = topRows(selectedAnalysis.peers)
  $: selectedServices = topRows(selectedAnalysis.services)
  $: selectedCountries = topRows(selectedAnalysis.countries)
  $: selectedBlocked = topRows(selectedAnalysis.blocked)
  $: reportSource = reportDevice?.ip ? reportAnalysis : analysis
  $: reportPeersAll = reportSource.peers || []
  $: reportServicesAll = reportSource.services || []
  $: reportCountriesAll = reportSource.countries || []
  $: reportBlockedAll = reportSource.blocked || []
  $: reportTotals = reportSource.totals || {}
  $: reportPeers = topRows(reportPeersAll)
  $: reportServices = topRows(reportServicesAll)
  $: reportCountries = topRows(reportCountriesAll)
  $: reportBlocked = topRows(reportBlockedAll)
  $: visibleDevices = allDevices.filter(device => !isAnonymousLinkLocal(device) || allDevices.length === 1)
  $: knownHostCount = knownDevicesFromHosts(knownHosts, devices).length
  $: localNames = {
    ...Object.fromEntries((knownHosts || []).filter(host => host.ip && host.hostname).map(host => [host.ip, host.hostname])),
    ...Object.fromEntries((allDevices || []).flatMap(device => deviceIPs(device).map(ip => [ip, device.hostname]).filter(([, name]) => name))),
  }

  function emptyAnalysis() {
    return { peers: [], services: [], countries: [], blocked: [], totals: {} }
  }

  function sources(device) {
    return device?.sources || device?.source || []
  }

  function deviceName(device) {
    return device?.hostname || device?.ip || 'Unknown host'
  }

  function deviceIPs(device) {
    return [device?.ip, ...(device?.aliases || [])].filter(Boolean)
  }

  function isAnonymousLinkLocal(device) {
    const ip = (device?.ip || '').toLowerCase()
    return ip.startsWith('fe80:') && !device?.hostname && !device?.mac
  }

  function isConnected(device) {
    if (!device?.active) return false
    const state = (device.state || '').toUpperCase()
    if (sources(device).includes('self')) return true
    if (!sources(device).includes('neigh')) return false
    if (!state) return true
    return ['REACHABLE', 'DELAY', 'PROBE'].includes(state)
  }

  function knownDevicesFromHosts(hosts, currentDevices) {
    const existing = new Set((currentDevices || []).flatMap(deviceIPs))
    return (hosts || [])
      .filter(host => host?.ip && !existing.has(host.ip))
      .map(host => ({
        ip: host.ip,
        version: host.ip.includes(':') ? 6 : 4,
        mac: host.mac || '',
        hostname: host.hostname || '',
        state: 'HISTORICAL',
        sources: ['analytics'],
        active: !blacklistMap[host.ip],
        onlyLocal: !!onlyLocalMap[host.ip],
        first_seen: host.first_seen,
        last_seen: host.last_seen,
      }))
  }

  function statusText(device) {
    if (isConnected(device)) return 'Connected'
    if (sources(device).includes('analytics')) {
      const lastSeen = lastSeenForHost(device?.ip)
      return lastSeen ? `Known ${formatRelative(lastSeen)}` : 'Known host'
    }
    return 'Offline'
  }

  function metricValue(name) {
    const match = metricsText.match(new RegExp(`^${name}\\s+([^\\n]+)$`, 'm'))
    if (!match) return '0'
    return formatNumber(match[1])
  }

  function metricByIP(name, ip) {
    if (!ip) return '0'
    const escapedIP = ip.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
    const match = metricsText.match(new RegExp(`^${name}\\{[^\\n]*ip="${escapedIP}"[^\\n]*\\}\\s+([^\\n]+)$`, 'm'))
    if (!match) return '0'
    return formatNumber(match[1])
  }

  function formatNumber(value) {
    return formatCompact(value)
  }

  function formatCompact(value) {
    const number = Number(value)
    if (!Number.isFinite(number)) return value
    const units = ['', 'K', 'M', 'B', 'T']
    let current = Math.abs(number)
    let unitIndex = 0
    while (current >= 1000 && unitIndex < units.length - 1) {
      current /= 1000
      unitIndex += 1
    }
    const signed = number < 0 ? -current : current
    return `${signed.toLocaleString(undefined, { maximumFractionDigits: current >= 10 || unitIndex === 0 ? 0 : 1 })}${units[unitIndex]}`
  }

  function fullNumber(value) {
    const number = Number(value)
    return Number.isFinite(number) ? number.toLocaleString() : value
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

  function formatRelative(value) {
    if (!value) return ''
    const diffMs = Date.now() - new Date(value).getTime()
    const diffMin = Math.max(0, Math.round(diffMs / 60000))
    if (diffMin < 1) return 'now'
    if (diffMin < 60) return `${diffMin}m ago`
    const hours = Math.round(diffMin / 60)
    if (hours < 48) return `${hours}h ago`
    return formatDate(value)
  }

  function topRows(rows, limit = 8) {
    return (rows || []).slice(0, limit)
  }

  function peerName(row) {
    return endpointLabel(row?.peer_ip) || localNames[row?.peer_ip] || row?.peer_org || row?.peer_as_name || row?.peer_isp || row?.peer_ip || 'Unknown peer'
  }

  async function copyIP(ip) {
    if (!ip) return
    try {
      if (navigator?.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(ip)
        return
      }
      const input = document.createElement('textarea')
      input.value = ip
      input.setAttribute('readonly', '')
      input.style.position = 'fixed'
      input.style.opacity = '0'
      document.body.appendChild(input)
      input.select()
      document.execCommand('copy')
      document.body.removeChild(input)
    } catch {
      // Ignore clipboard errors; the title still exposes the IP.
    }
  }

  function showEndpointTooltip(ip, event) {
    if (!ip) return
    endpointTooltip = {
      text: `${ip} · click to copy`,
      x: Math.min(window.innerWidth - 320, Math.max(12, event.clientX + 16)),
      y: Math.max(12, event.clientY - 18),
    }
  }

  function handleEndpointTooltip(event) {
    const target = event.target?.closest?.('.endpoint-copy[data-endpoint-ip]')
    if (!target) {
      hideEndpointTooltip()
      return
    }
    showEndpointTooltip(target.dataset.endpointIp, event)
  }

  function hideEndpointTooltip() {
    if (endpointTooltip.text) endpointTooltip = { text: '', x: 0, y: 0 }
  }

  function endpointLabel(ip) {
    if (!ip) return ''
    if (ip === '255.255.255.255') return 'IPv4 broadcast'
    if (ip.endsWith('.255')) return 'Subnet broadcast'
    if (ip === '224.0.0.251') return 'mDNS multicast'
    if (ip === '239.255.255.250') return 'SSDP multicast'
    if (ip === '224.0.0.1') return 'All hosts multicast'
    if (ip.startsWith('224.') || ip.startsWith('239.')) return 'IPv4 multicast'
    if (ip.toLowerCase().startsWith('ff02::fb')) return 'mDNS multicast'
    if (ip.toLowerCase().startsWith('ff')) return 'IPv6 multicast'
    return ''
  }

  function peerSubtitle(row) {
    const flags = [
      row?.peer_country_code,
      row?.peer_hosting ? 'hosting' : '',
      row?.peer_proxy ? 'proxy' : '',
      row?.peer_mobile ? 'mobile' : '',
    ].filter(Boolean)
    return flags.join(' · ')
  }

  function peerTitle(row) {
    return row?.peer_ip || peerName(row)
  }

  function peerDetails(row, parts = []) {
    return [peerSubtitle(row), ...parts].filter(Boolean).join(' · ') || '—'
  }

  function serviceContext(row) {
    const service = row?.service || row?.port || 'Unknown service'
    const peer = peerName(row)
    if (!peer || peer === row?.peer_ip) return service
    return `${service} · ${peer}`
  }

  function lastSeenForHost(ip) {
    if (!ip) return ''
    const knownHost = knownHosts.find(host => host.ip === ip)
    const seen = [
      knownHost?.last_seen,
      ...(analysis.peers || []).filter(row => row.host_ip === ip).map(row => row.last_seen),
      ...(analysis.blocked || []).filter(row => row.host_ip === ip).map(row => row.last_seen),
    ].filter(Boolean).sort()
    return seen.at(-1) || ''
  }

  function firstSeenForHost(ip) {
    if (!ip) return ''
    const knownHost = knownHosts.find(host => host.ip === ip)
    return knownHost?.first_seen || ''
  }

  function deviceFirstSeen(device) {
    return device?.first_seen || firstSeenForHost(device?.ip)
  }

  function deviceLastSeen(device) {
    return device?.last_seen || lastSeenForHost(device?.ip)
  }

  function totalBytes(rows) {
    return (rows || []).reduce((sum, row) => sum + (Number(row.bytes) || 0), 0)
  }

  function totalPackets(rows) {
    return (rows || []).reduce((sum, row) => sum + (Number(row.packets) || 0), 0)
  }

  function selectDevice(device) {
    selectedIP = device.ip
    loadSelectedAnalysis(device.ip)
  }

  async function loadSelectedAnalysis(ip) {
    if (!ip) return
    try {
      selectedAnalysis = await fetchHostAnalysis(ip, 100)
    } catch {
      selectedAnalysis = emptyAnalysis()
    }
  }

  async function toggleKnownHosts() {
    if (showKnownHosts) {
      showKnownHosts = false
      return
    }

    knownHostsLoading = true
    error = ''
    try {
      knownHosts = await fetchKnownHosts()
      knownHostsLoaded = true
      showKnownHosts = true
    } catch {
      error = 'Failed to load known hosts'
    } finally {
      knownHostsLoading = false
    }
  }

  async function load() {
    loading = devices.length === 0
    error = ''

    try {
      const [networkDevices, blacklist, onlyLocal, metrics, nextKnownHosts] = await Promise.all([
        fetchNetworkDevices(),
        fetchList('black'),
        fetchList('local'),
        fetchMetricsText(),
        fetchKnownHosts().catch(() => knownHosts),
      ])

      metricsText = metrics
      knownHosts = nextKnownHosts || []
      knownHostsLoaded = true
      blacklistMap = Object.fromEntries((blacklist || []).map(entry => [entry.ip, true]))
      onlyLocalMap = Object.fromEntries((onlyLocal || []).map(entry => [entry.ip, true]))
      devices = (networkDevices || []).map(device => ({
        ...device,
        active: !blacklistMap[device.ip],
        onlyLocal: !!onlyLocalMap[device.ip],
      }))

      try {
        analysis = await fetchAnalysisSummary(100)
      } catch {
        analysis = emptyAnalysis()
      }

      if (selectedIP && !visibleDevices.some(device => device.ip === selectedIP)) {
        selectedIP = visibleDevices[0]?.ip || ''
      }

      if (!selectedIP && visibleDevices.length > 0) {
        selectedIP = visibleDevices[0].ip
        await loadSelectedAnalysis(selectedIP)
      } else if (selectedIP) {
        await loadSelectedAnalysis(selectedIP)
      }
    } catch {
      error = 'Failed to load host data'
    } finally {
      loading = false
    }
  }

  async function refreshSummary() {
    summaryLoading = true
    error = ''
    try {
      if (reportIP) {
        reportAnalysis = await fetchHostAnalysis(reportIP, 100)
      } else {
        analysis = await fetchAnalysisSummary(100)
      }
    } catch {
      error = 'Failed to load analysis summary'
    } finally {
      summaryLoading = false
    }
  }

  async function generateSummary() {
    reportIP = selectedIP
    if (!reportIP) return
    summaryLoading = true
    error = ''
    try {
      reportAnalysis = await fetchHostAnalysis(reportIP, 100)
    } catch {
      error = 'Failed to generate host summary'
    } finally {
      summaryLoading = false
    }
  }

  async function toggleDevice(device, index) {
    if (!device.ip) return

    const previousActive = device.active
    const nextActive = !previousActive
    devices = devices.map((item, i) => i === index ? { ...item, active: nextActive } : item)
    blacklistMap = { ...blacklistMap, [device.ip]: !nextActive }

    try {
      if (nextActive) await removeIP('black', device.ip)
      else await addIP('black', device.ip)
    } catch {
      devices = devices.map((item, i) => i === index ? { ...item, active: previousActive } : item)
      blacklistMap = { ...blacklistMap, [device.ip]: !previousActive }
      error = 'Failed to update blacklist'
    }
  }

  async function toggleOnlyLocal(device, index) {
    if (!device.ip) return

    const previousOnlyLocal = device.onlyLocal
    const nextOnlyLocal = !previousOnlyLocal
    devices = devices.map((item, i) => i === index ? { ...item, onlyLocal: nextOnlyLocal } : item)
    onlyLocalMap = { ...onlyLocalMap, [device.ip]: nextOnlyLocal }

    try {
      if (nextOnlyLocal) await addIP('local', device.ip)
      else await removeIP('local', device.ip)
    } catch {
      devices = devices.map((item, i) => i === index ? { ...item, onlyLocal: previousOnlyLocal } : item)
      onlyLocalMap = { ...onlyLocalMap, [device.ip]: previousOnlyLocal }
      error = 'Failed to update only-local list'
    }
  }

  onMount(load)
</script>

<section class="hosts-shell" aria-label="Hostnames" on:mousemove={handleEndpointTooltip} on:mouseleave={hideEndpointTooltip} on:focusout={hideEndpointTooltip}>
  <aside class="hosts-pane host-list-pane">
    <div class="hosts-pane-header">
      <div>
        <div class="hosts-title">Hosts</div>
        <div class="hosts-subtitle">{visibleDevices.length} devices · {activeCount} connected</div>
      </div>
      <button class="icon-btn" type="button" aria-label="Refresh hosts" on:click={load}>
        <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
          <path d="M21 12a9 9 0 1 1-3-6.7"/>
          <polyline points="21 3 21 9 15 9"/>
        </svg>
      </button>
    </div>

    <div class="host-search">
      <span></span>
      <input placeholder="Search host" />
    </div>

    <div class="host-list-actions">
      <button class="btn btn-ghost" type="button" on:click={toggleKnownHosts} disabled={knownHostsLoading}>
        {#if knownHostsLoading}
          Loading known hosts
        {:else if showKnownHosts}
          Hide known hosts
        {:else if knownHostsLoaded}
          {knownHostCount > 0 ? `Show known hosts (${knownHostCount})` : 'Refresh known hosts'}
        {:else}
          Fetch known hosts
        {/if}
      </button>
    </div>

    <div class="host-list">
      {#each visibleDevices as device, index (`${device.ip}-${device.mac}`)}
        <button class="host-row" class:selected={selectedIP === device.ip} type="button" on:click={() => selectDevice(device)}>
          <span class="host-status-dot" class:connected={isConnected(device)}></span>
          <span class="host-row-main">
            <strong>{deviceName(device)}</strong>
            <span>{device.ip || '—'}</span>
          </span>
          <span class="host-row-meta">
            {#if isConnected(device)}
              Connected
            {:else if sources(device).includes('analytics')}
              {formatRelative(lastSeenForHost(device.ip)) || 'Known'}
            {:else}
              Offline
            {/if}
          </span>
        </button>
      {/each}
    </div>

    <div class="hosts-mini-stats">
      <div><span>Blocked</span><strong>{blockedCount}</strong></div>
      <div><span>Only local</span><strong>{onlyLocalCount}</strong></div>
      <div><span>Active IPs</span><strong>{metricValue('ntc_active_ips')}</strong></div>
    </div>

    {#if loading}
      <div class="entries-empty">Loading…</div>
    {:else if error}
      <div class="entries-empty error">{error}</div>
    {:else if visibleDevices.length === 0}
      <div class="entries-empty">No hosts</div>
    {/if}
  </aside>

  <aside class="hosts-pane host-detail-pane">
    {#if selectedDevice}
      <div class="host-detail-header">
        <div>
          <div class="host-detail-title">{deviceName(selectedDevice)}</div>
          <div class="host-status-line">
            <span class="host-status-dot" class:connected={isConnected(selectedDevice)}></span>
            {statusText(selectedDevice)}
          </div>
        </div>
        <button class="btn btn-ghost inspect-btn" type="button" on:click={generateSummary} disabled={summaryLoading}>
          {summaryLoading ? 'Loading' : 'Summary'}
        </button>
      </div>

      <div class="host-info-card">
        <div class="host-info-row"><span>IP</span><strong>{selectedDevice.ip || '—'}</strong></div>
        <div class="host-info-row"><span>Aliases</span><strong>{(selectedDevice.aliases || []).join(', ') || '—'}</strong></div>
        <div class="host-info-row"><span>IPv</span><strong>{selectedDevice.version || '—'}</strong></div>
        <div class="host-info-row"><span>MAC</span><strong>{selectedDevice.mac || '—'}</strong></div>
        <div class="host-info-row"><span>State</span><strong>{selectedDevice.state || '—'}</strong></div>
        <div class="host-info-row"><span>Sources</span><strong>{sources(selectedDevice).join(', ') || '—'}</strong></div>
        <div class="host-info-row"><span>First known</span><strong>{formatDate(deviceFirstSeen(selectedDevice))}</strong></div>
        <div class="host-info-row"><span>Last updated</span><strong>{formatDate(deviceLastSeen(selectedDevice))}</strong></div>
        <div class="host-info-row"><span>Access</span><strong>{selectedDevice.active ? 'Allowed' : 'Blacklisted'}</strong></div>
        <div class="host-info-row"><span>Policy</span><strong>{selectedDevice.onlyLocal ? 'Only local' : 'External allowed'}</strong></div>
      </div>

      <div class="host-controls">
        <button class="host-action" type="button" on:click={() => toggleDevice(selectedDevice, devices.findIndex(item => item.ip === selectedDevice.ip))}>
          {selectedDevice.active ? 'Block host' : 'Allow host'}
        </button>
        <button class="host-action" type="button" on:click={() => toggleOnlyLocal(selectedDevice, devices.findIndex(item => item.ip === selectedDevice.ip))}>
          {selectedDevice.onlyLocal ? 'Disable local only' : 'Only local'}
        </button>
      </div>

      <div class="host-info-card">
        <div class="host-info-row"><span>Packets/s</span><strong>{metricByIP('ntc_ip_packets_per_second', selectedDevice.ip)}</strong></div>
        <div class="host-info-row"><span>Bytes/s</span><strong>{metricByIP('ntc_ip_bytes_per_second', selectedDevice.ip)}</strong></div>
        <div class="host-info-row"><span>Dst ports</span><strong>{metricByIP('ntc_ip_unique_dst_ports', selectedDevice.ip)}</strong></div>
        <div class="host-info-row"><span>SYN</span><strong>{metricByIP('ntc_ip_syn_count', selectedDevice.ip)}</strong></div>
        <div class="host-info-row"><span>ACK</span><strong>{metricByIP('ntc_ip_ack_count', selectedDevice.ip)}</strong></div>
      </div>

      <div class="host-section">
        <div class="host-section-title">Top talkers</div>
        {#if selectedPeers.length === 0}
          <div class="host-empty">No analysis data yet</div>
        {:else}
          {#each selectedPeers.slice(0, 4) as peer}
            <div class="host-mini-row">
              <button class="endpoint-copy endpoint-copy-muted" type="button" data-endpoint-ip={peer.peer_ip} aria-label={`Copy ${peer.peer_ip}`} on:focus={(event) => showEndpointTooltip(peer.peer_ip, event)} on:click={() => copyIP(peer.peer_ip)}>{peerName(peer)}</button>
              <strong>{formatBytes(peer.bytes)}</strong>
            </div>
          {/each}
        {/if}
      </div>
    {:else}
      <div class="host-empty">Select a host</div>
    {/if}
  </aside>

  <section class="hosts-pane host-summary-pane">
    <div class="hosts-pane-header">
      <div>
        <div class="hosts-title">{reportDevice ? `${deviceName(reportDevice)} summary` : 'Network summary'}</div>
        <div class="hosts-subtitle">Metrics and analytics counters</div>
      </div>
      <button class="btn btn-ghost" type="button" on:click={refreshSummary} disabled={summaryLoading}>
        {summaryLoading ? 'Loading' : 'Refresh'}
      </button>
    </div>

    <div class="summary-hero-grid">
      <div><span>Peers</span><strong title={fullNumber(reportTotals.peers ?? reportPeersAll.length)}>{formatCompact(reportTotals.peers ?? reportPeersAll.length)}</strong></div>
      <div><span>Services</span><strong title={fullNumber(reportTotals.services ?? reportServicesAll.length)}>{formatCompact(reportTotals.services ?? reportServicesAll.length)}</strong></div>
      <div><span>Countries</span><strong title={fullNumber(reportTotals.countries ?? reportCountriesAll.length)}>{formatCompact(reportTotals.countries ?? reportCountriesAll.length)}</strong></div>
      <div><span>Blocked</span><strong title={fullNumber(reportTotals.blocked ?? reportBlockedAll.length)}>{formatCompact(reportTotals.blocked ?? reportBlockedAll.length)}</strong></div>
      <div><span>Packets</span><strong title={fullNumber(reportTotals.packets ?? totalPackets(reportPeersAll))}>{formatCompact(reportTotals.packets ?? totalPackets(reportPeersAll))}</strong></div>
      <div><span>Bytes</span><strong>{formatBytes(reportTotals.bytes ?? totalBytes(reportPeersAll))}</strong></div>
    </div>

    <div class="summary-columns">
      <div class="summary-block">
        <div class="host-section-title">Top peers</div>
        {#each reportPeers as peer}
          <div class="summary-row">
            <div>
              <strong><button class="endpoint-copy" type="button" data-endpoint-ip={peer.peer_ip} aria-label={`Copy ${peer.peer_ip}`} on:focus={(event) => showEndpointTooltip(peer.peer_ip, event)} on:click={() => copyIP(peer.peer_ip)}>{peerName(peer)}</button></strong>
              <span>{peerDetails(peer, [peer.direction, peer.action, peer.service || peer.port])}</span>
            </div>
            <b>{formatBytes(peer.bytes)}</b>
          </div>
        {:else}
          <div class="host-empty">No peer counters yet</div>
        {/each}
      </div>

      <div class="summary-block">
        <div class="host-section-title">Top services</div>
        {#each reportServices as service}
          <div class="summary-row">
            <div>
              <strong>{service.service || service.port}</strong>
              <span>{service.proto} · {service.direction} · {service.action}</span>
            </div>
            <b>{formatBytes(service.bytes)}</b>
          </div>
        {:else}
          <div class="host-empty">No service counters yet</div>
        {/each}
      </div>

      <div class="summary-block">
        <div class="host-section-title">Countries</div>
        {#each reportCountries as country}
          <div class="summary-row">
            <div>
              <strong>{country.country_code}</strong>
              <span>{country.direction} · {country.action}</span>
            </div>
            <b>{formatBytes(country.bytes)}</b>
          </div>
        {:else}
          <div class="host-empty">No country counters yet</div>
        {/each}
      </div>

      <div class="summary-block">
        <div class="host-section-title">Blocked</div>
        {#each reportBlocked as blocked}
          <div class="summary-row blocked">
            <div>
              <strong><button class="endpoint-copy" type="button" data-endpoint-ip={blocked.peer_ip} aria-label={`Copy ${blocked.peer_ip}`} on:focus={(event) => showEndpointTooltip(blocked.peer_ip, event)} on:click={() => copyIP(blocked.peer_ip)}>{peerName(blocked)}</button></strong>
              <span>{peerDetails(blocked, [serviceContext(blocked), formatDate(blocked.last_seen)])}</span>
            </div>
            <b>{formatBytes(blocked.bytes)}</b>
          </div>
        {:else}
          <div class="host-empty">No blocked counters yet</div>
        {/each}
      </div>
    </div>
  </section>
</section>
{#if endpointTooltip.text}
  <div class="endpoint-tooltip" style={`left: ${endpointTooltip.x}px; top: ${endpointTooltip.y}px;`}>
    {endpointTooltip.text}
  </div>
{/if}
