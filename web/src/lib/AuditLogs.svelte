<script>
  import { onMount } from 'svelte'
  import { fetchAppLogs } from './api.js'

  const levelOptions = ['All levels', 'INFO', 'WARN', 'ERROR']
  const categoryOptions = ['All categories', 'system', 'list', 'storage', 'network']
  const sourceOptions = ['All sources', 'startup', 'http', 'list_manager', 'storage']

  let rows = []
  let loading = false
  let loadError = ''

  let timeframeOpen = false
  let levelOpen = false
  let categoryOpen = false
  let sourceOpen = false

  let startDraft = '2026-06-03'
  let endDraft = '2026-06-04'
  let startDate = startDraft
  let endDate = endDraft
  let levelFilter = 'All levels'
  let categoryFilter = 'All categories'
  let sourceFilter = 'All sources'

  $: filteredRows = rows.filter(row => {
    const day = row.time.slice(0, 10)
    return day >= startDate
      && day <= endDate
      && (levelFilter === 'All levels' || row.level === levelFilter)
      && (categoryFilter === 'All categories' || row.category === categoryFilter)
      && (sourceFilter === 'All sources' || row.source === sourceFilter)
  })

  function labelDate(value) {
    return value.replaceAll('-', '/')
  }

  function formatDateTime(value) {
    return new Intl.DateTimeFormat(undefined, {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    }).format(new Date(value))
  }

  async function loadLogs() {
    loading = true
    loadError = ''
    try {
      const logs = await fetchAppLogs(200)
      rows = (logs || []).map(log => ({
        id: log.id,
        time: log.created_at,
        level: log.level || '',
        category: log.category || '',
        event: log.event || '',
        message: log.message || '',
        entityType: log.entity_type || '',
        target: log.entity_id || '',
        actor: log.actor || '',
        source: log.source || '',
        metadata: log.metadata_json || '',
      }))
    } catch (err) {
      loadError = err.message || 'Failed to load logs'
    } finally {
      loading = false
    }
  }

  function applyTimeframe() {
    startDate = startDraft
    endDate = endDraft
    timeframeOpen = false
  }

  function closeMenus(except) {
    if (except !== 'timeframe') timeframeOpen = false
    if (except !== 'level') levelOpen = false
    if (except !== 'category') categoryOpen = false
    if (except !== 'source') sourceOpen = false
  }

  onMount(loadLogs)
</script>

<main class="container page audit-page">
  <section class="audit-toolbar" aria-label="Audit log filters">
    <div class="audit-filter-wrap">
      <button class="audit-filter audit-filter-wide" type="button" on:click={() => { closeMenus('timeframe'); timeframeOpen = !timeframeOpen }}>
        Timeframe: {labelDate(startDate)} – {labelDate(endDate)}
        <span class="chevron"></span>
      </button>

      {#if timeframeOpen}
        <div class="timeframe-popover">
          <label>
            <span>Start</span>
            <input type="date" bind:value={startDraft} />
          </label>
          <label>
            <span>End</span>
            <input type="date" bind:value={endDraft} />
          </label>
          <button class="apply-btn" type="button" on:click={applyTimeframe} disabled={!startDraft || !endDraft || startDraft > endDraft}>
            Apply
          </button>
        </div>
      {/if}
    </div>

    <div class="audit-filter-wrap">
      <button class="audit-filter" type="button" on:click={() => { closeMenus('level'); levelOpen = !levelOpen }}>
        {levelFilter === 'All levels' ? 'Level' : levelFilter}
        <span class="chevron"></span>
      </button>
      {#if levelOpen}
        <div class="filter-menu">
          {#each levelOptions as option}
            <button type="button" on:click={() => { levelFilter = option; levelOpen = false }}>{option}</button>
          {/each}
        </div>
      {/if}
    </div>

    <div class="audit-filter-wrap">
      <button class="audit-filter" type="button" on:click={() => { closeMenus('category'); categoryOpen = !categoryOpen }}>
        {categoryFilter === 'All categories' ? 'Category' : categoryFilter}
        <span class="chevron"></span>
      </button>
      {#if categoryOpen}
        <div class="filter-menu">
          {#each categoryOptions as option}
            <button type="button" on:click={() => { categoryFilter = option; categoryOpen = false }}>{option}</button>
          {/each}
        </div>
      {/if}
    </div>

    <div class="audit-filter-wrap">
      <button class="audit-filter" type="button" on:click={() => { closeMenus('source'); sourceOpen = !sourceOpen }}>
        {sourceFilter === 'All sources' ? 'Source' : sourceFilter}
        <span class="chevron"></span>
      </button>
      {#if sourceOpen}
        <div class="filter-menu">
          {#each sourceOptions as option}
            <button type="button" on:click={() => { sourceFilter = option; sourceOpen = false }}>{option}</button>
          {/each}
        </div>
      {/if}
    </div>

    <button class="audit-refresh" type="button" on:click={loadLogs} disabled={loading}>
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
        <path d="M21 12a9 9 0 1 1-3-6.7"/>
        <polyline points="21 3 21 9 15 9"/>
      </svg>
      {loading ? 'Loading' : 'Refresh'}
    </button>
  </section>

  {#if loadError}
    <div class="audit-load-error">{loadError}</div>
  {/if}

  <section class="audit-table-wrap">
    <table class="audit-table">
      <thead>
        <tr>
          <th class="expand-col"></th>
          <th>ID</th>
          <th>Date</th>
          <th>Level</th>
          <th>Category</th>
          <th>Event</th>
          <th>Message</th>
          <th>Entity</th>
          <th>Target</th>
          <th>Actor</th>
          <th>Source</th>
          <th>Metadata</th>
        </tr>
      </thead>
      <tbody>
        {#each filteredRows as row}
          <tr>
            <td class="expand-col">
              <span class:level-dot={true} class:info={row.level === 'INFO'} class:warn={row.level === 'WARN'} class:error={row.level === 'ERROR'}></span>
            </td>
            <td>{row.id}</td>
            <td>{formatDateTime(row.time)}</td>
            <td>{row.level}</td>
            <td>{row.category}</td>
            <td>{row.event}</td>
            <td>{row.message}</td>
            <td>{row.entityType}</td>
            <td>{row.target}</td>
            <td>{row.actor}</td>
            <td>{row.source}</td>
            <td>{row.metadata}</td>
          </tr>
        {:else}
          <tr>
            <td colspan="11" class="audit-empty">{loading ? 'Loading logs...' : 'No events in this range'}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  </section>
</main>
