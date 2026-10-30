<script>
  import { onMount } from 'svelte'
  import Header from './lib/Header.svelte'
  import EventTable from './lib/EventTable.svelte'
  import ListPanel from './lib/ListPanel.svelte'
  import PolicyPanel from './lib/PolicyPanel.svelte'
  import NetworkDevices from './lib/NetworkDevices.svelte'
  import MetricsView from './lib/MetricsView.svelte'
  import SystemMonitor from './lib/SystemMonitor.svelte'
  import AuditLogs from './lib/AuditLogs.svelte'
  import AnalysisSummary from './lib/AnalysisSummary.svelte'
  import { fetchList, fetchLocalNets, fetchMetricsText } from './lib/api.js'
  import { fitPopover } from './lib/popover.js'

  let activeView = 'main'
  let localNets = { v4: [], v6: [] }
  let localNetsLoading = false
  let localNetsError = ''
  let overviewMetrics = ''
  let listCounts = { black: 0, white: 0, local: 0 }
  let selectedPacket = null
  let policies = []
  let lastActiveView = activeView
  const currentHost = window.location.hostname || 'localhost'
  const grafanaBase = `http://${currentHost}:3000/d`
  const victoriaBase = `http://${currentHost}:8428/vmui/`

  const grafanaDashboards = [
    { title: 'Overview', href: `${grafanaBase}/ntc-overview/ntc-overview` },
    { title: 'Top Talkers', href: `${grafanaBase}/ntc-top-talkers/ntc-top-talkers` },
    { title: 'Security', href: `${grafanaBase}/ntc-security/ntc-security` },
  ]

  const overviewStatCards = [
    {
      label: 'Packets/s',
      metric: 'ntc_packets_per_second',
      value: () => metricValue('ntc_packets_per_second'),
      description: 'Total packets per second across the 60 second sliding window.',
      source: 'ntc_packets_per_second',
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
  ]

  function metricValue(name) {
    const match = overviewMetrics.match(new RegExp(`^${name}\\s+([^\\n]+)$`, 'm'))
    if (!match) return '0'
    const value = Number(match[1])
    return Number.isFinite(value) ? value.toLocaleString(undefined, { maximumFractionDigits: 2 }) : match[1]
  }

  async function loadLocalNets() {
    localNetsLoading = true
    localNetsError = ''

    try {
      const [nets, metrics, blacklist, whitelist, onlyLocal] = await Promise.all([
        fetchLocalNets(),
        fetchMetricsText(),
        fetchList('black'),
        fetchList('white'),
        fetchList('local'),
      ])
      localNets = nets
      overviewMetrics = metrics
      listCounts = {
        black: (blacklist || []).length,
        white: (whitelist || []).length,
        local: (onlyLocal || []).length,
      }
    } catch {
      localNetsError = 'Failed to load overview'
    } finally {
      localNetsLoading = false
    }
  }

  $: if (activeView !== lastActiveView) {
    lastActiveView = activeView
    selectedPacket = null
    window.scrollTo({ top: 0, left: 0 })
  }

  onMount(loadLocalNets)
</script>

<Header bind:activeView />

{#if activeView === 'main'}
  <main class="container page stack">
    <section class="card page-panel overview-panel">
      <div class="panel-header">
        <span class="panel-title">Main</span>
        <button class="btn btn-ghost" on:click={loadLocalNets}>
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
            <path d="M21 12a9 9 0 1 1-3-6.7"/>
            <polyline points="21 3 21 9 15 9"/>
          </svg>
          Refresh
        </button>
      </div>
      <div class="panel-body">
        <div class="stat-grid">
          {#each overviewStatCards as stat}
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

        <div class="current-net">
          <div class="current-net-title">Current net is</div>

          {#if localNetsLoading}
            <div class="entries-empty">Loading…</div>
          {:else if localNetsError}
            <div class="entries-empty error">{localNetsError}</div>
          {:else if localNets.v4.length === 0 && localNets.v6.length === 0}
            <div class="entries-empty">No local nets</div>
          {:else}
            <div class="net-groups">
              {#if localNets.v4.length > 0}
                <div class="net-group">
                  <span class="net-family">IPv4</span>
                  <div class="net-chips">
                    {#each localNets.v4 as net}
                      <span class="net-chip">{net.cidr}</span>
                    {/each}
                  </div>
                </div>
              {/if}

              {#if localNets.v6.length > 0}
                <div class="net-group">
                  <span class="net-family">IPv6</span>
                  <div class="net-chips">
                    {#each localNets.v6 as net}
                      <span class="net-chip">{net.cidr}</span>
                    {/each}
                  </div>
                </div>
              {/if}
            </div>
          {/if}
        </div>
      </div>
    </section>

    <section class="card page-panel">
      <div class="panel-header">
        <span class="panel-title">Demo surfaces</span>
      </div>
      <div class="panel-body">
        <div class="link-grid">
          <a class="link-tile" href="/metrics" target="_blank" rel="noreferrer">
            <span>Prometheus</span>
            <strong>/metrics</strong>
          </a>
          <a class="link-tile" href={victoriaBase} target="_blank" rel="noreferrer">
            <span>VictoriaMetrics</span>
            <strong>VMUI</strong>
          </a>
          {#each grafanaDashboards as dashboard}
            <a class="link-tile" href={dashboard.href} target="_blank" rel="noreferrer">
              <span>Grafana</span>
              <strong>{dashboard.title}</strong>
            </a>
          {/each}
        </div>
      </div>
    </section>
  </main>
{:else if activeView === 'live'}
  <main class="split live-layout">
    <ListPanel bind:selectedPacket />
    <EventTable bind:selectedPacket {policies} />
    <PolicyPanel bind:policies {selectedPacket} />
  </main>
{:else if activeView === 'hostnames'}
  <main class="container page">
    <NetworkDevices />
  </main>
{:else if activeView === 'metrics'}
  <MetricsView bind:metricsText={overviewMetrics} />
{:else if activeView === 'analysis'}
  <AnalysisSummary />
{:else if activeView === 'system'}
  <SystemMonitor />
{:else if activeView === 'logs'}
  <AuditLogs />
{/if}
