<script>
  import { onMount } from 'svelte'
  import { fetchList, addIP, removeIP } from './api.js'

  let listType = 'black'
  let ipInput = ''
  let entries = []
  let loading = false
  let error = ''

  async function load() {
    loading = true
    error = ''
    try {
      const data = await fetchList(listType)
      entries = data ?? []
    } catch {
      error = 'Failed to load'
    } finally {
      loading = false
    }
  }

  async function handleAdd() {
    const ip = ipInput.trim()
    if (!ip) return
    await addIP(listType, ip)
    ipInput = ''
    await load()
  }

  async function handleRemove() {
    const ip = ipInput.trim()
    if (!ip) return
    await removeIP(listType, ip)
    ipInput = ''
    await load()
  }

  function selectEntry(ip) {
    ipInput = ip
  }

  onMount(load)
</script>

<aside class="panel">
  <div class="card">
    <div class="panel-header">
      <span class="panel-title">{listType === 'black' ? 'Blacklist' : 'Whitelist'}</span>
      <div class="tab-group">
        <button
          class="tab"
          class:active={listType === 'black'}
          on:click={() => { listType = 'black'; load() }}
        >Black</button>
        <button
          class="tab"
          class:active={listType === 'white'}
          on:click={() => { listType = 'white'; load() }}
        >White</button>
      </div>
    </div>

    <div class="panel-body">
      <input
        class="input"
        placeholder="e.g. 192.168.1.1"
        bind:value={ipInput}
        on:keydown={e => e.key === 'Enter' && handleAdd()}
      />

      <div class="btn-row">
        <button class="btn btn-success" on:click={handleAdd}>Add</button>
        <button class="btn btn-danger" on:click={handleRemove}>Remove</button>
        <button class="btn btn-ghost" on:click={load}>
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
            <path d="M21 12a9 9 0 1 1-3-6.7"/>
            <polyline points="21 3 21 9 15 9"/>
          </svg>
          Refresh
        </button>
      </div>

      <div class="entries-box">
        {#if loading}
          <div class="entries-empty">Loading…</div>
        {:else if error}
          <div class="entries-empty error">{error}</div>
        {:else if entries.length === 0}
          <div class="entries-empty">No entries</div>
        {:else}
          <ul class="entries-list">
            {#each entries as entry}
              <li>
                <button
                  class="entry"
                  class:selected={ipInput === entry.ip}
                  on:click={() => selectEntry(entry.ip)}
                >
                  <span class="entry-dot" class:black={listType === 'black'} class:white={listType === 'white'}></span>
                  {entry.ip}
                </button>
              </li>
            {/each}
          </ul>
        {/if}
      </div>
    </div>
  </div>
</aside>