<script>
  import { onMount } from 'svelte'
  import { addIP, fetchList, fetchMetricsText, fetchNetworkDevices, removeIP } from './api.js'
  import { fitPopover } from './popover.js'

  let devices = []
  let metricsText = ''
  let loading = false
  let error = ''

  $: activeCount = devices.filter(device => device.active).length
  $: blockedCount = devices.filter(device => !device.active).length
  $: onlyLocalCount = devices.filter(device => device.onlyLocal).length
  $: sourceCount = new Set(devices.flatMap(device => device.sources || device.source || [])).size

  function metricValue(name) {
    const match = metricsText.match(new RegExp(`^${name}\\s+([^\\n]+)$`, 'm'))
    if (!match) return '0'
    const value = Number(match[1])
    return Number.isFinite(value) ? value.toLocaleString(undefined, { maximumFractionDigits: 2 }) : match[1]
  }

  function metricByIP(name, ip) {
    if (!ip) return '0'
    const escapedIP = ip.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
    const match = metricsText.match(new RegExp(`^${name}\\{[^\\n]*ip="${escapedIP}"[^\\n]*\\}\\s+([^\\n]+)$`, 'm'))
    if (!match) return '0'
    const value = Number(match[1])
    return Number.isFinite(value) ? value.toLocaleString(undefined, { maximumFractionDigits: 2 }) : match[1]
  }

  function sources(device) {
    return device.sources || device.source || []
  }

  async function load() {
    loading = devices.length === 0
    error = ''

    try {
      const [networkDevices, blacklist, onlyLocal, metrics] = await Promise.all([
        fetchNetworkDevices(),
        fetchList('black'),
        fetchList('local'),
        fetchMetricsText(),
      ])

      metricsText = metrics
      const blacklistMap = Object.fromEntries((blacklist || []).map(entry => [entry.ip, true]))
      const onlyLocalMap = Object.fromEntries((onlyLocal || []).map(entry => [entry.ip, true]))
      devices = networkDevices.map(device => ({
        ...device,
        active: !blacklistMap[device.ip],
        onlyLocal: !!onlyLocalMap[device.ip],
      }))
    } catch {
      error = 'Failed to load devices'
    } finally {
      loading = false
    }
  }

  async function toggleDevice(device, index) {
    if (!device.ip) return

    const previousActive = device.active
    const nextActive = !previousActive
    devices = devices.map((item, i) => i === index ? { ...item, active: nextActive } : item)

    try {
      if (nextActive) {
        await removeIP('black', device.ip)
      } else {
        await addIP('black', device.ip)
      }
    } catch {
      devices = devices.map((item, i) => i === index ? { ...item, active: previousActive } : item)
      error = 'Failed to update blacklist'
    }
  }

  async function toggleOnlyLocal(device, index) {
    if (!device.ip) return

    const previousOnlyLocal = device.onlyLocal
    const nextOnlyLocal = !previousOnlyLocal
    devices = devices.map((item, i) => i === index ? { ...item, onlyLocal: nextOnlyLocal } : item)

    try {
      if (nextOnlyLocal) {
        await addIP('local', device.ip)
      } else {
        await removeIP('local', device.ip)
      }
    } catch {
      devices = devices.map((item, i) => i === index ? { ...item, onlyLocal: previousOnlyLocal } : item)
      error = 'Failed to update only-local list'
    }
  }

  onMount(load)
</script>

<section class="table-card hostnames-table">
  <div class="table-actions">
    <div>
      <div class="panel-title">Hostnames</div>
      <div class="meta">Devices discovered from DHCP leases and neighbor table</div>
    </div>
    <button class="btn btn-ghost" on:click={load}>
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
        <path d="M21 12a9 9 0 1 1-3-6.7"/>
        <polyline points="21 3 21 9 15 9"/>
      </svg>
      Refresh
    </button>
  </div>

  <div class="table-stats">
    <div class="stat-tile">
      <span>Devices</span>
      <strong>{devices.length}</strong>
    </div>
    <div class="stat-tile">
      <span>Active</span>
      <strong>{activeCount}</strong>
    </div>
    <div class="stat-tile">
      <span>Blocked</span>
      <strong>{blockedCount}</strong>
    </div>
    <div class="stat-tile">
      <span>Only local</span>
      <strong>{onlyLocalCount}</strong>
    </div>
    <div class="stat-tile">
      <span>Sources</span>
      <strong>{sourceCount}</strong>
    </div>
    <div class="stat-tile">
      <span>Active IPs</span>
      <strong>{metricValue('ntc_active_ips')}</strong>
    </div>
  </div>

  <table class="table">
    <thead>
      <tr>
        <th>Hostname</th>
        <th>IP</th>
        <th>MAC</th>
        <th>State</th>
        <th>Sources</th>
        <th class="right">Access</th>
        <th class="right">Only local</th>
      </tr>
    </thead>
    <tbody>
      {#each devices as device, index (`${device.ip}-${device.mac}`)}
        <tr>
          <td class="hostname-cell" use:fitPopover>
            <span>{device.hostname || '—'}</span>
            <div class="device-popover">
              <div class="popover-title">{device.hostname || device.ip || 'Unknown device'}</div>
              <div class="popover-grid">
                <span>IP</span><strong>{device.ip || '—'}</strong>
                <span>Version</span><strong>IPv{device.version || '—'}</strong>
                <span>MAC</span><strong>{device.mac || '—'}</strong>
                <span>State</span><strong>{device.state || '—'}</strong>
                <span>Sources</span><strong>{sources(device).join(', ') || '—'}</strong>
                <span>Access</span><strong>{device.active ? 'Active' : 'Blacklisted'}</strong>
                <span>Only local</span><strong>{device.onlyLocal ? 'Enabled' : 'Disabled'}</strong>
                <span>Packets/s</span><strong>{metricByIP('ntc_ip_packets_per_second', device.ip)}</strong>
                <span>Bytes/s</span><strong>{metricByIP('ntc_ip_bytes_per_second', device.ip)}</strong>
                <span>Dst ports</span><strong>{metricByIP('ntc_ip_unique_dst_ports', device.ip)}</strong>
                <span>SYN</span><strong>{metricByIP('ntc_ip_syn_count', device.ip)}</strong>
                <span>ACK</span><strong>{metricByIP('ntc_ip_ack_count', device.ip)}</strong>
              </div>
            </div>
          </td>
          <td class="addr">{device.ip}</td>
          <td class="addr">{device.mac || '—'}</td>
          <td>
            {#if device.state}
              <span class="badge">{device.state}</span>
            {:else}
              <span class="muted">—</span>
            {/if}
          </td>
          <td>{sources(device).join(', ')}</td>
          <td class="right">
            <button
              class="switch"
              class:active={device.active}
              type="button"
              role="switch"
              aria-checked={device.active}
              on:click={() => toggleDevice(device, index)}
              title={device.active ? 'Active' : 'Blacklisted'}
            >
              <span></span>
            </button>
          </td>
          <td class="right">
            <button
              class="switch switch-local"
              class:active={device.onlyLocal}
              type="button"
              role="switch"
              aria-checked={device.onlyLocal}
              on:click={() => toggleOnlyLocal(device, index)}
              title={device.onlyLocal ? 'Only local' : 'Can reach external networks'}
            >
              <span></span>
            </button>
          </td>
        </tr>
      {/each}
    </tbody>
  </table>

  {#if loading}
    <div class="entries-empty">Loading…</div>
  {:else if error}
    <div class="entries-empty error">{error}</div>
  {:else if devices.length === 0}
    <div class="entries-empty">No devices</div>
  {/if}
</section>
