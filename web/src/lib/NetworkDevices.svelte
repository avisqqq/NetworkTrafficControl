<script>
  import { onMount } from 'svelte'
  import { addIP, fetchList, fetchNetworkDevices, removeIP } from './api.js'

  let devices = []
  let loading = false
  let error = ''

  async function load() {
    loading = devices.length === 0
    error = ''

    try {
      const [networkDevices, blacklist, onlyLocal] = await Promise.all([
        fetchNetworkDevices(),
        fetchList('black'),
        fetchList('local')
      ])

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

<section class="table-card">
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
          <td>{device.hostname || '—'}</td>
          <td class="addr">{device.ip}</td>
          <td class="addr">{device.mac || '—'}</td>
          <td>
            {#if device.state}
              <span class="badge">{device.state}</span>
            {:else}
              <span class="muted">—</span>
            {/if}
          </td>
          <td>{(device.sources || device.source || []).join(', ')}</td>
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
