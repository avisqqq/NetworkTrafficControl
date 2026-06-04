<script>
  import { onDestroy, onMount } from 'svelte'

  let connected = false
  let snapshot = null
  let error = ''
  let stream
  let sortKey = 'cpuPercent'
  let sortDir = 'desc'

  $: sortedProcesses = sortProcesses(snapshot?.processes || [], sortKey, sortDir)

  function formatBytes(value) {
    const units = ['B', 'KB', 'MB', 'GB', 'TB']
    let size = Number(value || 0)
    let unit = 0

    while (size >= 1024 && unit < units.length - 1) {
      size /= 1024
      unit += 1
    }

    return `${size.toFixed(size >= 10 || unit === 0 ? 0 : 1)} ${units[unit]}`
  }

  function formatRate(value) {
    return `${formatBytes(value)}/s`
  }

  function percent(value) {
    return `${Number(value || 0).toFixed(1)}%`
  }

  function barWidth(value) {
    return `${Math.max(0, Math.min(100, Number(value || 0)))}%`
  }

  function toggleSort(key) {
    if (sortKey === key) {
      sortDir = sortDir === 'desc' ? 'asc' : 'desc'
      return
    }

    sortKey = key
    sortDir = key === 'name' ? 'asc' : 'desc'
  }

  function sortProcesses(processes, key, dir) {
    const direction = dir === 'asc' ? 1 : -1

    return [...processes].sort((a, b) => {
      const left = a[key]
      const right = b[key]

      if (typeof left === 'string' || typeof right === 'string') {
        const result = String(left || '').localeCompare(String(right || ''), undefined, {
          sensitivity: 'base',
        })
        if (result !== 0) return result * direction
      } else {
        const result = Number(left || 0) - Number(right || 0)
        if (result !== 0) return result * direction
      }

      return String(a.name || '').localeCompare(String(b.name || ''), undefined, {
        sensitivity: 'base',
      })
    })
  }

  function sortArrow(key) {
    if (sortKey !== key) return ''
    return sortDir === 'desc' ? '↓' : '↑'
  }

  onMount(() => {
    stream = new EventSource(`${window.location.origin}/system/events`)

    stream.onopen = () => {
      connected = true
      error = ''
    }

    stream.onerror = () => {
      connected = false
      error = 'System stream disconnected'
    }

    stream.onmessage = (msg) => {
      try {
        snapshot = JSON.parse(msg.data)
        error = ''
      } catch {
        error = 'Invalid system payload'
      }
    }
  })

  onDestroy(() => {
    if (stream) stream.close()
  })
</script>

<main class="container page stack">
  <section class="card page-panel system-panel">
    <div class="panel-header">
      <span class="panel-title">System</span>
      <div class="connection-status system-status" class:ok={connected} class:bad={!connected}>
        <span></span>
        {connected ? 'Live' : 'Offline'}
      </div>
    </div>

    <div class="panel-body">
      {#if error}
        <div class="entries-empty error">{error}</div>
      {/if}

      {#if snapshot}
        <div class="stat-grid">
          <div class="stat-tile">
            <span>CPU</span>
            <strong>{percent(snapshot.cpu.totalPercent)}</strong>
          </div>
          <div class="stat-tile">
            <span>RAM</span>
            <strong>{percent(snapshot.ram.usedPercent)}</strong>
          </div>
          <div class="stat-tile">
            <span>Used RAM</span>
            <strong>{formatBytes(snapshot.ram.usedBytes)}</strong>
          </div>
          <div class="stat-tile">
            <span>Total RAM</span>
            <strong>{formatBytes(snapshot.ram.totalBytes)}</strong>
          </div>
          <div class="stat-tile">
            <span>RX</span>
            <strong>{formatRate(snapshot.network.rxBytesPerSec)}</strong>
          </div>
          <div class="stat-tile">
            <span>TX</span>
            <strong>{formatRate(snapshot.network.txBytesPerSec)}</strong>
          </div>
        </div>

        <div class="system-section">
          <div class="current-net-title">CPU cores</div>
          <div class="core-grid">
            {#each snapshot.cpu.coresPercent as core, index}
              <div class="core-row">
                <span>CPU {index}</span>
                <div class="usage-bar" aria-label={`CPU ${index} ${percent(core)}`}>
                  <div style={`width: ${barWidth(core)}`}></div>
                </div>
                <strong>{percent(core)}</strong>
              </div>
            {/each}
          </div>
        </div>

        <div class="table-card system-table">
          <div class="table-actions">
            <div>
              <div class="panel-title">Processes</div>
              <div class="system-note">Sorted {sortDir} by {sortKey}, showing {sortedProcesses.length}</div>
            </div>
          </div>

          <table class="table">
            <thead>
              <tr>
                <th>
                  <button class="sort-header" type="button" on:click={() => toggleSort('pid')}>
                    PID <span>{sortArrow('pid')}</span>
                  </button>
                </th>
                <th>
                  <button class="sort-header" type="button" on:click={() => toggleSort('name')}>
                    App <span>{sortArrow('name')}</span>
                  </button>
                </th>
                <th class="right">
                  <button class="sort-header right" type="button" on:click={() => toggleSort('cpuPercent')}>
                    CPU <span>{sortArrow('cpuPercent')}</span>
                  </button>
                </th>
                <th class="right">
                  <button class="sort-header right" type="button" on:click={() => toggleSort('ramBytes')}>
                    RAM <span>{sortArrow('ramBytes')}</span>
                  </button>
                </th>
                <th class="right">
                  <button class="sort-header right" type="button" on:click={() => toggleSort('ramPercent')}>
                    RAM % <span>{sortArrow('ramPercent')}</span>
                  </button>
                </th>
              </tr>
            </thead>
            <tbody>
              {#each sortedProcesses as proc}
                <tr>
                  <td class="muted">{proc.pid}</td>
                  <td class="process-name">{proc.name}</td>
                  <td class="right">{percent(proc.cpuPercent)}</td>
                  <td class="right">{formatBytes(proc.ramBytes)}</td>
                  <td class="right">{percent(proc.ramPercent)}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {:else}
        <div class="entries-empty">Loading system data...</div>
      {/if}
    </div>
  </section>
</main>
