<script>
  import { onMount } from 'svelte'
  import Header from './lib/Header.svelte'
  import EventTable from './lib/EventTable.svelte'
  import ListPanel from './lib/ListPanel.svelte'
  import NetworkDevices from './lib/NetworkDevices.svelte'
  import { fetchLocalNets } from './lib/api.js'

  let activeView = 'main'
  let localNets = { v4: [], v6: [] }
  let localNetsLoading = false
  let localNetsError = ''

  async function loadLocalNets() {
    localNetsLoading = true
    localNetsError = ''

    try {
      localNets = await fetchLocalNets()
    } catch {
      localNetsError = 'Failed to load current net'
    } finally {
      localNetsLoading = false
    }
  }

  onMount(loadLocalNets)
</script>

<Header bind:activeView />

{#if activeView === 'main'}
  <main class="container page">
    <section class="card page-panel">
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
  </main>
{:else if activeView === 'live'}
  <main class="split container">
    <ListPanel />
    <EventTable />
  </main>
{:else if activeView === 'hostnames'}
  <main class="container page">
    <NetworkDevices />
  </main>
{/if}
