<script>
  import { onMount } from 'svelte'
  import { fetchAnalysisSummary, fetchKnownHosts, fetchNetworkDevices, generateAnalysisReport, inspectPacket } from './api.js'

  const emptySummary = { peers: [], services: [], countries: [], blocked: [], totals: {} }

  let summary = emptySummary
  let devices = []
  let knownHosts = []
  let discoveredPeers = {}
  let discoveringPeers = {}
  let discoveringCountries = false
  let loading = false
  let error = ''
  let reportLimit = 5
  let reportHost = ''
  let reportLoading = false
  let reportError = ''
  let aiReport = null
  let endpointTooltip = { text: '', x: 0, y: 0 }

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
    .flatMap(device => deviceIPs(device).map(ip => [ip, device.hostname]).filter(([, name]) => name)))
  $: knownHostNames = Object.fromEntries((knownHosts || [])
    .filter(host => host.ip && host.hostname)
    .map(host => [host.ip, host.hostname]))

  function formatNumber(value) {
    const number = Number(value) || 0
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

  function prettyJSON(value) {
    return JSON.stringify(value, null, 2)
  }

  function reportSummary(report) {
    if (!report) return ''
    if (typeof report.summary === 'string') return report.summary
    if (report.summary) return prettyJSON(report.summary)
    return ''
  }

  function reportItems(value) {
    return Array.isArray(value) ? value : []
  }

  function deviceIPs(device) {
    return [device?.ip, ...(device?.aliases || [])].filter(Boolean)
  }

  function peerName(row) {
    return endpointName(row?.peer_ip, row) || 'Unknown peer'
  }

  function endpointName(ip, row = null) {
    return endpointLabel(ip) || discoveredPeers[ip] || deviceNames[ip] || knownHostNames[ip] || row?.peer_org || row?.peer_as_name || row?.peer_isp || ip || ''
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
    const endpoint = event.target?.closest?.('.endpoint-copy[data-endpoint-ip]')
    if (endpoint) {
      showEndpointTooltip(endpoint.dataset.endpointIp, event)
      return
    }
    const service = event.target?.closest?.('.service-label[data-service-tooltip]')
    if (service) {
      endpointTooltip = {
        text: service.dataset.serviceTooltip,
        x: Math.min(window.innerWidth - 320, Math.max(12, event.clientX + 16)),
        y: Math.max(12, event.clientY - 18),
      }
      return
    }
    hideEndpointTooltip()
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

  function serviceName(row) {
    return row?.service || (row?.port ? `Port ${row.port}` : 'Unknown service')
  }

  function serviceTooltip(row) {
    const proto = row?.proto || 'service'
    const port = Number(row?.port) || 0
    return port ? `${proto} port ${port}` : proto
  }

  function joined(values, fallback = '—') {
    const unique = [...new Set(values.filter(Boolean))]
    return unique.length ? unique.join(', ') : fallback
  }

  function uniqueValues(values) {
    return [...new Set((values || []).filter(Boolean))]
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
        contributors: [],
        rows: 0,
      }
      current.packets += Number(row.packets) || 0
      current.bytes += Number(row.bytes) || 0
      current.services.push(serviceName(row))
      current.directions.push(row.direction)
      current.actions.push(row.action)
      current.last_seen = newest(current.last_seen, row.last_seen)
      current.contributors.push(row)
      current.rows += 1
      groups.set(key, current)
    }
    return sortedGroups(groups)
  }

  function topContributors(group, limit = 3) {
    return [...(group?.contributors || [])]
      .sort((a, b) => (Number(b.bytes) || 0) - (Number(a.bytes) || 0))
      .slice(0, limit)
  }

  function contributorText(row) {
    return [
      row.proto,
      serviceName(row),
      row.direction,
      row.action,
      `${formatNumber(row.packets)} pkts`,
      `${formatDate(row.first_seen)} - ${formatDate(row.last_seen)}`,
    ].filter(Boolean).join(' · ')
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
    return row?.peer_ip && !row?.peer_org && !row?.peer_as_name && !row?.peer_isp && !deviceNames[row.peer_ip] && !knownHostNames[row.peer_ip]
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
      const hosts = knownHosts.length ? knownHosts : await fetchKnownHosts()
      knownHosts = hosts || []
      const knownHost = knownHosts.find(host => host.ip === row.peer_ip)
      const localName = deviceNames[row.peer_ip] || knownHost?.hostname || knownHostNames[row.peer_ip]
      if (localName) {
        discoveredPeers = { ...discoveredPeers, [row.peer_ip]: localName }
        return
      }

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
      const [nextSummary, nextDevices, nextKnownHosts] = await Promise.all([
        fetchAnalysisSummary(100),
        fetchNetworkDevices(),
        fetchKnownHosts().catch(() => []),
      ])
      summary = nextSummary || emptySummary
      devices = nextDevices || []
      knownHosts = nextKnownHosts || []
    } catch {
      summary = emptySummary
    } finally {
      loading = false
    }
  }

  async function generateReport() {
    if (reportLoading) return

    reportLoading = true
    reportError = ''
    try {
      aiReport = await generateAnalysisReport({
        ip: reportHost.trim(),
        limit: Number(reportLimit) || 5,
      })
    } catch (err) {
      reportError = (err?.message || 'Could not generate AI report').trim()
    } finally {
      reportLoading = false
    }
  }

  onMount(load)
</script>

<main class="container page stack" on:mousemove={handleEndpointTooltip} on:mouseleave={hideEndpointTooltip} on:focusout={hideEndpointTooltip}>
  <section class="card page-panel analysis-panel">
    <div class="panel-header">
      <span class="panel-title">Analysis summary</span>
      <button class="btn btn-ghost" type="button" on:click={() => load()} disabled={loading}>
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
        <div><span>Hosts</span><strong title={fullNumber(hostCount)}>{formatNumber(hostCount)}</strong></div>
        <div><span>Peers</span><strong title={fullNumber(peerCount)}>{formatNumber(peerCount)}</strong></div>
        <div><span>Services</span><strong title={fullNumber(totals.services ?? services.length)}>{formatNumber(totals.services ?? services.length)}</strong></div>
        <div><span>Countries</span><strong title={fullNumber(totals.countries ?? countries.length)}>{formatNumber(totals.countries ?? countries.length)}</strong></div>
        <div><span>Packets</span><strong title={fullNumber(totalPackets)}>{formatNumber(totalPackets)}</strong></div>
        <div><span>Bytes</span><strong>{formatBytes(totalBytes)}</strong></div>
      </div>

      <section class="analysis-ai">
        <div class="analysis-ai-header">
          <div>
            <div class="analysis-block-title">AI report</div>
            <span>Local model report from the current analytics summary</span>
          </div>
          <button class="btn btn-success" type="button" on:click={generateReport} disabled={reportLoading}>
            {reportLoading ? 'Generating' : 'Generate'}
          </button>
        </div>

        <div class="analysis-ai-controls">
          <label>
            <span>Rows</span>
            <input class="input input-small no-spinner" type="number" min="1" max="50" bind:value={reportLimit} disabled={reportLoading}>
          </label>
          <label>
            <span>Host IP</span>
            <input class="input" type="text" placeholder="optional, e.g. 192.168.50.19" bind:value={reportHost} disabled={reportLoading}>
          </label>
        </div>

        {#if reportError}
          <div class="entries-empty error">{reportError}</div>
        {/if}

        {#if aiReport}
          <div class="analysis-ai-result">
            <div class="analysis-ai-meta">
              <span>Model</span><strong>{aiReport.model || 'local'}</strong>
              <span>Duration</span><strong>{formatNumber(aiReport.duration_ms || 0)} ms</strong>
              <span>Scope</span><strong>{aiReport.input?.scope || 'global'}</strong>
              <span>Limit</span><strong>{aiReport.input?.limit || reportLimit}</strong>
            </div>

            {#if aiReport.report?.risk_level || reportSummary(aiReport.report)}
              <div class="analysis-ai-card">
                <div class="analysis-ai-risk">
                  <span>Risk</span>
                  <strong>{aiReport.report?.risk_level || 'unknown'}</strong>
                </div>
                {#if reportSummary(aiReport.report)}
                  <p>{reportSummary(aiReport.report)}</p>
                {/if}
              </div>
            {/if}

            {#if reportItems(aiReport.report?.findings).length}
              <div class="analysis-ai-card">
                <div class="analysis-block-title">Findings</div>
                {#each reportItems(aiReport.report.findings) as finding}
                  <div class="analysis-ai-item">
                    <strong>{finding.title || finding.peer_ip || finding.evidence || 'Finding'}</strong>
                    <span>{finding.recommendation || finding.severity || prettyJSON(finding)}</span>
                  </div>
                {/each}
              </div>
            {/if}

            {#if reportItems(aiReport.report?.recommended_actions).length}
              <div class="analysis-ai-card">
                <div class="analysis-block-title">Recommended actions</div>
                {#each reportItems(aiReport.report.recommended_actions) as action}
                  <div class="analysis-ai-item">
                    <span>{typeof action === 'string' ? action : prettyJSON(action)}</span>
                  </div>
                {/each}
              </div>
            {/if}

            <details class="analysis-ai-raw">
              <summary>Raw output</summary>
              <pre>{prettyJSON(aiReport.report)}</pre>
            </details>
          </div>
        {:else if !reportLoading}
          <div class="host-empty">No AI report yet</div>
        {:else}
          <div class="host-empty">Waiting for local model...</div>
        {/if}
      </section>

      <div class="analysis-grid">
        <section class="analysis-block">
          <div class="analysis-block-title">Top peers</div>
          {#each peerGroups as peer}
            <div class="analysis-row analysis-row-expanded">
              <div>
                <div class="analysis-row-top">
                  <strong class="analysis-name">
                    <button class="endpoint-copy" type="button" data-endpoint-ip={peer.peer_ip} aria-label={`Copy ${peer.peer_ip}`} on:focus={(event) => showEndpointTooltip(peer.peer_ip, event)} on:click={() => copyIP(peer.peer_ip)}>{peerName(peer)}</button>
                    {#if canDiscover(peer)}
                      <button class="analysis-discover" type="button" on:click={() => discoverPeer(peer)} disabled={discoveringPeers[peer.peer_ip]}>
                        {discoveringPeers[peer.peer_ip] ? '...' : 'Discover'}
                      </button>
                    {/if}
                  </strong>
                  <b>{formatBytes(peer.bytes)}</b>
                </div>
                <span>{peerDetails(peer, [`${formatNumber(peer.packets)} pkts`, joined(peer.directions), joined(peer.actions), joined(peer.services), formatDate(peer.last_seen)])}</span>
                <div class="analysis-breakdown">
                  {#each topContributors(peer) as row}
                    <div title={row.peer_ip}>
                      <button class="endpoint-copy endpoint-copy-muted" type="button" data-endpoint-ip={row.host_ip} aria-label={`Copy ${row.host_ip}`} on:focus={(event) => showEndpointTooltip(row.host_ip, event)} on:click={() => copyIP(row.host_ip)}>
                        host {endpointName(row.host_ip)}
                      </button>
                      <span>{contributorText(row)}</span>
                      <b>{formatBytes(row.bytes)}</b>
                    </div>
                  {/each}
                </div>
              </div>
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
                <span>{service.proto} · {joined(service.directions)} · {joined(service.actions)}</span>
                <div class="endpoint-chip-row">
                  {#each uniqueValues(service.hostIPs) as ip}
                    <button class="endpoint-copy endpoint-copy-muted" type="button" data-endpoint-ip={ip} aria-label={`Copy ${ip}`} on:focus={(event) => showEndpointTooltip(ip, event)} on:click={() => copyIP(ip)}>{endpointName(ip)}</button>
                  {:else}
                    <span>all hosts</span>
                  {/each}
                </div>
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
                <span>{joined(country.directions)} · {joined(country.actions)}</span>
                <div class="endpoint-chip-row">
                  {#each uniqueValues(country.hostIPs) as ip}
                    <button class="endpoint-copy endpoint-copy-muted" type="button" data-endpoint-ip={ip} aria-label={`Copy ${ip}`} on:focus={(event) => showEndpointTooltip(ip, event)} on:click={() => copyIP(ip)}>{endpointName(ip)}</button>
                  {:else}
                    <span>all hosts</span>
                  {/each}
                </div>
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
                  <button class="endpoint-copy" type="button" data-endpoint-ip={item.peer_ip} aria-label={`Copy ${item.peer_ip}`} on:focus={(event) => showEndpointTooltip(item.peer_ip, event)} on:click={() => copyIP(item.peer_ip)}>{peerName(item)}</button>
                  {#if canDiscover(item)}
                    <button class="analysis-discover" type="button" on:click={() => discoverPeer(item)} disabled={discoveringPeers[item.peer_ip]}>
                      {discoveringPeers[item.peer_ip] ? '...' : 'Discover'}
                    </button>
                  {/if}
                </strong>
                <span>{peerDetails(item, [joined(item.services), formatDate(item.last_seen)])}</span>
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
  {#if endpointTooltip.text}
    <div class="endpoint-tooltip" style={`left: ${endpointTooltip.x}px; top: ${endpointTooltip.y}px;`}>
      {endpointTooltip.text}
    </div>
  {/if}
</main>
