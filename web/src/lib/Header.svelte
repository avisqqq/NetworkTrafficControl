<script>
  import { connected, filterStore, pausedStore, capStore, clearEvents, events } from './sse.js'

  let rowCount = 0
  events.subscribe(e => rowCount = e.length)

  function togglePause() {
    pausedStore.update(v => !v)
  }
</script>

<header class="top">
  <div class="header-bar">
    <div class="brand">
      <div class="title">NTC</div>
      <div class="subtitle">/events · live stream</div>
    </div>

    <div class="spacer"></div>

    <div class="pill" class:ok={$connected} class:bad={!$connected}>
      {$connected ? 'Connected' : 'Disconnected'}
    </div>
  </div>

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

    <label class="meta row" style="gap:6px">
      Max
      <input
        class="input input-small"
        type="number"
        bind:value={$capStore}
        min="10"
        max="5000"
      />
    </label>

    <div class="meta">
      <span style="color:var(--text-2);font-weight:600">{rowCount}</span> rows
    </div>
  </div>
</header>