<script>
  import Header from './lib/Header.svelte'
  import EventTable from './lib/EventTable.svelte'
  import ListPanel from './lib/ListPanel.svelte'
  import NetworkDevices from './lib/NetworkDevices.svelte'

  let activeView = 'main'
</script>

<Header bind:activeView />

{#if activeView === 'main'}
  <main class="container page">
    <section class="card page-panel">
      <div class="panel-header">
        <span class="panel-title">Main</span>
      </div>
      <div class="panel-body">
        <div class="entries-empty">Overview widgets can go here</div>
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
