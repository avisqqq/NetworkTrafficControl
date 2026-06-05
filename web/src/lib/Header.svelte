<script>
  import { onMount } from 'svelte'
  import { fetchRuntimeState } from './api.js'
  import { connected, filterStore, pausedStore, capStore, clearEvents, events } from './sse.js'

  export let activeView = 'main'

  let rowCount = 0
  let mockMode = false
  events.subscribe(e => rowCount = e.length)

  function subtitle() {
    if (activeView === 'live') return 'Live traffic'
    if (activeView === 'hostnames') return 'Network devices'
    if (activeView === 'metrics') return 'Metrics'
    if (activeView === 'analysis') return 'Analysis summary'
    if (activeView === 'system') return 'System monitor'
    if (activeView === 'logs') return 'Audit logs'
    return 'Overview'
  }

  function togglePause() {
    pausedStore.update(v => !v)
  }

  function updateCap(delta) {
    capStore.update(value => {
      const next = Number(value) + delta
      return Math.min(5000, Math.max(10, next))
    })
  }

  onMount(async () => {
    const state = await fetchRuntimeState()
    mockMode = !!state.mockMode
  })
</script>

<header class="top">
  <div class="header-bar">
    <div class="brand">
      <div class="title">NTC</div>
      <div class="subtitle">{subtitle()}</div>
    </div>

    <nav class="nav-tabs" aria-label="Primary">
      <button
        class="nav-tab"
        class:active={activeView === 'main'}
        on:click={() => activeView = 'main'}
      >
        Main
      </button>
      <button
        class="nav-tab"
        class:active={activeView === 'live'}
        on:click={() => activeView = 'live'}
      >
        Live traffic
      </button>
      <button
        class="nav-tab"
        class:active={activeView === 'hostnames'}
        on:click={() => activeView = 'hostnames'}
      >
        Hostnames
      </button>
      <button
        class="nav-tab"
        class:active={activeView === 'metrics'}
        on:click={() => activeView = 'metrics'}
      >
        Metrics
      </button>
      <button
        class="nav-tab"
        class:active={activeView === 'analysis'}
        on:click={() => activeView = 'analysis'}
      >
        Analysis
      </button>
      <button
        class="nav-tab"
        class:active={activeView === 'system'}
        on:click={() => activeView = 'system'}
      >
        System
      </button>
      <button
        class="nav-tab"
        class:active={activeView === 'logs'}
        on:click={() => activeView = 'logs'}
      >
        Logs
      </button>
    </nav>

    <div class="spacer"></div>

    <div class="connection-status" class:ok={$connected} class:bad={!$connected}>
      <span></span>
      {$connected ? 'SSE online' : 'SSE offline'}
    </div>

    {#if mockMode}
      <div class="mock-status">Mock</div>
    {/if}
  </div>

  {#if activeView === 'live'}
    <div class="toolbar-bar">
      <input
        class="input filter-input"
        placeholder="Filter by IP, proto, action…"
        bind:value={$filterStore}
      />

      <button
        class="btn"
        class:btn-paused={$pausedStore}
        on:click={togglePause}
      >
        {#if $pausedStore}
          <svg width="11" height="11" viewBox="0 0 24 24" fill="currentColor"><polygon points="5,3 19,12 5,21"/></svg>
          Resume
        {:else}
          <svg width="11" height="11" viewBox="0 0 24 24" fill="currentColor"><rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/></svg>
          Pause
        {/if}
      </button>

      <button class="btn btn-ghost" on:click={clearEvents}>
        <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="3,6 5,6 21,6"/><path d="M19,6l-1,14H6L5,6"/><path d="M10,11v6"/><path d="M14,11v6"/></svg>
        Clear
      </button>

      <div class="spacer"></div>

      <label class="stepper-label">
        <span>Max</span>
        <button class="stepper-btn" type="button" on:click={() => updateCap(-10)} aria-label="Decrease max rows">
          −
        </button>
        <input
          class="input input-small no-spinner"
          type="number"
          bind:value={$capStore}
          min="10"
          max="5000"
        />
        <button class="stepper-btn" type="button" on:click={() => updateCap(10)} aria-label="Increase max rows">
          +
        </button>
      </label>

      <div class="meta">
        <span style="color:var(--text-2);font-weight:600">{rowCount}</span> rows
      </div>
    </div>
  {/if}
</header>
