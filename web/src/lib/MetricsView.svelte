<script>
  import { onDestroy, onMount } from 'svelte'
  import { fetchList, fetchMetricsText } from './api.js'
  import { fitPopover } from './popover.js'

  export let metricsText = ''
  let listCounts = { black: 0, white: 0, local: 0 }
  let loading = false
  let error = ''
  let refreshTimer
  $: parsedMetrics = parseMetrics(metricsText)

  const currentHost = window.location.hostname 
  const grafanaRoot = `http://${currentHost}:3000`
  const grafanaBase = `${grafanaRoot}/d`
  const victoriaBase = `http://${currentHost}:8428/vmui/`

  const dashboards = [
    { title: 'Overview', href: `${grafanaBase}/ntc-overview/ntc-overview` },
    { title: 'Top Talkers', href: `${grafanaBase}/ntc-top-talkers/ntc-top-talkers` },
    { title: 'Security', href: `${grafanaBase}/ntc-security/ntc-security` },
  ]

  const metricRows = [
    ['ntc_packets_per_second', 'Current packet rate'],
    ['ntc_bytes_per_second', 'Current byte rate'],
    ['ntc_active_ips', 'Active source IPs'],
    ['ntc_active_flows', 'Tracked flows'],
    ['ntc_action_packets_total', 'Actions by pass/drop/skip/ssh'],
    ['ntc_direction_packets_total', 'Ingress and egress packets'],
    ['ntc_packets_total', 'Protocol packet counters'],
    ['ntc_ip_packets_per_second', 'Top talkers by packets'],
    ['ntc_ip_bytes_per_second', 'Top talkers by bytes'],
    ['ntc_ip_unique_dst_ports', 'Port scan signal'],
    ['ntc_ip_syn_count', 'SYN flood signal'],
  ]

  const statCards = [
    {
      label: 'Packets/s',
      metric: 'ntc_packets_per_second',
      value: () => metricValue('ntc_packets_per_second'),
      description: 'Total packets per second across the 60 second sliding window.',
      source: 'ntc_packets_per_second',
    },
    {
      label: 'Bytes/s',
      metric: 'ntc_bytes_per_second',
      value: () => metricValue('ntc_bytes_per_second'),
      description: 'Total bytes per second across the 60 second sliding window.',
      source: 'ntc_bytes_per_second',
    },
    {
      label: 'Active IPs',
      metric: 'ntc_active_ips',
      value: () => metricValue('ntc_active_ips'),
      description: 'Distinct source IP addresses seen recently.',
      source: 'ntc_active_ips',
    },
    {
      label: 'Active flows',
      metric: 'ntc_active_flows',
      value: () => metricValue('ntc_active_flows'),
      description: 'Currently tracked flows in the in-memory flow table.',
      source: 'ntc_active_flows',
    },
    {
      label: 'Total packets',
      metric: 'ntc_packets_total',
      value: () => metricSum('ntc_packets_total'),
      description: 'Packet counters summed across protocol labels.',
      source: 'sum(ntc_packets_total)',
    },
    {
      label: 'Total bytes',
      metric: 'ntc_bytes_total',
      value: () => metricSum('ntc_bytes_total'),
      description: 'Byte counters summed across protocol labels.',
      source: 'sum(ntc_bytes_total)',
    },
    {
      label: 'Dropped',
      metric: 'ntc_action_packets_total',
      value: () => metricSum('ntc_action_packets_total', 'action="drop"'),
      description: 'Packets dropped by firewall action.',
      source: 'ntc_action_packets_total{action="drop"}',
    },
    {
      label: 'SSH bypass',
      metric: 'ntc_action_packets_total',
      value: () => metricSum('ntc_action_packets_total', 'action="ssh"'),
      description: 'Packets bypassed by the SSH safety rule.',
      source: 'ntc_action_packets_total{action="ssh"}',
    },
  ]

  function formatMetric(value) {
    return Number.isFinite(value) ? value.toLocaleString(undefined, { maximumFractionDigits: 2 }) : '0'
  }

  function parseMetrics(text) {
    const parsed = {}
    text
      .split('\n')
      .map(line => line.trim())
      .filter(line => line && !line.startsWith('#'))
      .forEach(line => {
        const parts = line.split(/\s+/)
        const value = Number(parts[parts.length - 1])
        if (!Number.isFinite(value)) return

        const series = parts[0]
        const name = series.split('{')[0]
        const sample = { series, value }
        if (!parsed[name]) parsed[name] = { exact: null, samples: [] }
        if (series === name) parsed[name].exact = value
        parsed[name].samples.push(sample)
      })
    return parsed
  }

  function metricValue(name) {
    const metric = parsedMetrics[name]
    if (!metric) return '0'
    if (metric.exact !== null) return formatMetric(metric.exact)
    return formatMetric(metric.samples.reduce((total, sample) => total + sample.value, 0))
  }

  function metricSum(name, label = '') {
    const metric = parsedMetrics[name]
    if (!metric) return '0'
    const sum = metric.samples.reduce((total, sample) => {
      if (label && !sample.series.includes(label)) return total
      return total + sample.value
    }, 0)
    return formatMetric(sum)
  }

  function metricSeries(name, limit = 5) {
    const metric = parsedMetrics[name]
    if (!metric) return []
    return metric.samples.slice(0, limit)
  }

  function vmuiQuery(query) {
    return `${victoriaBase}?g0.expr=${encodeURIComponent(query)}&g0.range_input=30m`
  }

  async function load() {
    loading = !metricsText
    error = ''
    try {
      const metrics = await fetchMetricsText()
      if (!metrics) throw new Error('empty metrics response')
      metricsText = metrics
    } catch (err) {
      error = 'Failed to load metrics'
    } finally {
      loading = false
    }

    try {
      const [blacklist, whitelist, onlyLocal] = await Promise.all([
        fetchList('black'),
        fetchList('white'),
        fetchList('local'),
      ])
      listCounts = {
        black: (blacklist || []).length,
        white: (whitelist || []).length,
        local: (onlyLocal || []).length,
      }
    } catch {
      listCounts = { black: 0, white: 0, local: 0 }
    }
  }

  onMount(() => {
    load()
    refreshTimer = window.setInterval(load, 2000)
  })

  onDestroy(() => {
    if (refreshTimer) window.clearInterval(refreshTimer)
  })
</script>

<main class="container page stack">
  <section class="card page-panel metrics-panel">
    <div class="panel-header">
      <span class="panel-title">Metrics</span>
      <button class="btn btn-ghost" on:click={load}>
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
          <path d="M21 12a9 9 0 1 1-3-6.7"/>
          <polyline points="21 3 21 9 15 9"/>
        </svg>
        Refresh
      </button>
    </div>

    <div class="panel-body">
      <div class="stat-grid">
        {#each statCards as stat}
          <div class="stat-tile stat-hover" use:fitPopover>
            <span>{stat.label}</span>
            <strong>{stat.value()}</strong>
            <div class="device-popover stat-popover">
              <div class="popover-title">{stat.label}</div>
              <div class="popover-grid">
                <span>Metric</span><strong>{stat.metric}</strong>
                <span>Value</span><strong>{stat.value()}</strong>
                <span>Source</span><strong>{stat.source}</strong>
                <span>Description</span><strong>{stat.description}</strong>
              </div>
              {#if metricSeries(stat.metric).length > 0}
                <div class="popover-series">
                  {#each metricSeries(stat.metric) as sample}
                    <div><span>{sample.series}</span><strong>{formatMetric(sample.value)}</strong></div>
                  {/each}
                </div>
              {/if}
            </div>
          </div>
        {/each}
      </div>

      <div class="current-net">
        <div class="current-net-title">Access lists</div>
        <div class="list-summary">
          <div class="list-chip" use:fitPopover>
            <strong>{listCounts.black}</strong> blacklisted
            <div class="device-popover list-popover">
              <div class="popover-title">Blacklist</div>
              <div class="popover-grid">
                <span>Count</span><strong>{listCounts.black}</strong>
                <span>Effect</span><strong>Matched IPs are blocked.</strong>
                <span>Storage</span><strong>Persisted between runs.</strong>
              </div>
            </div>
          </div>
          <div class="list-chip" use:fitPopover>
            <strong>{listCounts.white}</strong> whitelisted
            <div class="device-popover list-popover">
              <div class="popover-title">Whitelist</div>
              <div class="popover-grid">
                <span>Count</span><strong>{listCounts.white}</strong>
                <span>Effect</span><strong>Matched IPs bypass normal blocking.</strong>
                <span>Storage</span><strong>Persisted between runs.</strong>
              </div>
            </div>
          </div>
          <div class="list-chip" use:fitPopover>
            <strong>{listCounts.local}</strong> only local
            <div class="device-popover list-popover">
              <div class="popover-title">Only local</div>
              <div class="popover-grid">
                <span>Count</span><strong>{listCounts.local}</strong>
                <span>Effect</span><strong>Matched IPs can only reach local networks.</strong>
                <span>Storage</span><strong>Runtime state only.</strong>
              </div>
            </div>
          </div>
        </div>
      </div>

      {#if loading}
        <div class="entries-empty">Loading…</div>
      {:else if error}
        <div class="entries-empty error">{error}</div>
      {/if}
    </div>
  </section>

  <section class="card page-panel">
    <div class="panel-header">
      <span class="panel-title">Grafana</span>
      <a class="btn btn-ghost" href={grafanaRoot} target="_blank" rel="noreferrer">Open Grafana</a>
    </div>
    <div class="panel-body">
      <div class="link-grid">
        {#each dashboards as dashboard}
          <a class="link-tile" href={dashboard.href} target="_blank" rel="noreferrer">
            <span>{dashboard.title}</span>
            <strong>Dashboard</strong>
          </a>
        {/each}
      </div>
    </div>
  </section>

  <section class="table-card">
    <div class="table-actions">
      <div>
        <div class="panel-title">VictoriaMetrics series</div>
        <div class="meta">Open each metric in VMUI to show stored time series</div>
      </div>
      <a class="btn btn-ghost" href={victoriaBase} target="_blank" rel="noreferrer">Open VMUI</a>
    </div>

    <table class="table">
      <thead>
        <tr>
          <th>Metric</th>
          <th>Meaning</th>
          <th class="right">Query</th>
        </tr>
      </thead>
      <tbody>
        {#each metricRows as row}
          <tr>
            <td class="addr">{row[0]}</td>
            <td>{row[1]}</td>
            <td class="right">
              <a class="inline-link" href={vmuiQuery(row[0])} target="_blank" rel="noreferrer">VMUI</a>
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  </section>
</main>
