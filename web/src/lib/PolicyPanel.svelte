<script>
  import { onMount } from 'svelte'
  import { addPolicy, fetchPolicies, removePolicy } from './api.js'

  export let policies = []
  export let selectedPacket = null

  let ip = ''
  let port = ''
  let protocol = 'TCP'
  let direction = 'INGRESS'
  let loading = false
  let saving = false
  let error = ''
  $: draftIsValid = Boolean(
    ip.trim() &&
    Number.isInteger(Number(port)) &&
    Number(port) > 0 &&
    Number(port) <= 65535
  )

  const commonPorts = [
    { value: 22, label: 'SSH' },
    { value: 53, label: 'DNS' },
    { value: 80, label: 'HTTP' },
    { value: 443, label: 'HTTPS' },
    { value: 8080, label: 'HTTP alt' },
  ]

  async function load() {
    loading = true
    error = ''
    try {
      policies = (await fetchPolicies()) || []
    } catch (err) {
      error = err.message || 'Failed to load rules'
    } finally {
      loading = false
    }
  }

  function draft() {
    return {
      ip: ip.trim(),
      port: Number(port),
      protocol,
      direction,
    }
  }

  async function add() {
    if (!draftIsValid || saving) return
    saving = true
    error = ''
    try {
      await addPolicy(draft())
      await load()
    } catch (err) {
      error = err.message || 'Failed to add rule'
    } finally {
      saving = false
    }
  }

  async function remove(rule) {
    if (saving) return
    saving = true
    error = ''
    try {
      await removePolicy(rule)
      await load()
    } catch (err) {
      error = err.message || 'Failed to remove rule'
    } finally {
      saving = false
    }
  }

  function useEndpoint(endpoint) {
    if (!selectedPacket) return
    const source = endpoint === 'source'
    ip = source ? selectedPacket.src : selectedPacket.dst
    port = String(source ? selectedPacket.src_port : selectedPacket.dst_port)
    protocol = ['TCP', 'UDP'].includes((selectedPacket.proto || '').toUpperCase())
      ? selectedPacket.proto.toUpperCase()
      : 'TCP'
    direction = (selectedPacket.direction || 'INGRESS').toUpperCase()
  }

  function edit(rule) {
    ip = rule.ip
    port = String(rule.port)
    protocol = rule.protocol
    direction = rule.direction
  }

  onMount(load)
</script>

<aside class="policy-panel">
  <div class="card">
    <div class="panel-header">
      <span class="panel-title">Rules</span>
      <button class="icon-btn" type="button" aria-label="Refresh rules" on:click={load}>↻</button>
    </div>

    <div class="panel-body policy-form">
      {#if selectedPacket}
        <div class="packet-rule-fill">
          <span>Complete from packet #{selectedPacket.seq}</span>
          <div>
            <button class="mini-toggle" type="button" on:click={() => useEndpoint('source')}>Source</button>
            <button class="mini-toggle" type="button" on:click={() => useEndpoint('destination')}>Destination</button>
          </div>
        </div>
      {/if}

      <label>
        <span>IP address</span>
        <input class="input" bind:value={ip} placeholder="192.168.1.10" />
      </label>

      <label>
        <span>Port</span>
        <input class="input" type="number" min="1" max="65535" list="policy-ports" bind:value={port} placeholder="443" />
        <datalist id="policy-ports">
          {#each commonPorts as item}
            <option value={item.value}>{item.label}</option>
          {/each}
        </datalist>
      </label>

      <div class="policy-field-row">
        <label>
          <span>Protocol</span>
          <select class="input" bind:value={protocol}>
            <option value="TCP">TCP</option>
            <option value="UDP">UDP</option>
          </select>
        </label>
        <label>
          <span>Direction</span>
          <select class="input" bind:value={direction}>
            <option value="INGRESS">Ingress</option>
            <option value="EGRESS">Egress</option>
          </select>
        </label>
      </div>

      <button class="btn btn-danger policy-add" type="button" disabled={!draftIsValid || saving} on:click={add}>
        {saving ? 'Applying…' : 'Add drop rule'}
      </button>

      {#if error}<div class="policy-error">{error}</div>{/if}
    </div>
  </div>

  <div class="card policy-list-card">
    <div class="panel-header">
      <span class="panel-title">Active rules</span>
      <span class="policy-count">{policies.length}</span>
    </div>
    <div class="policy-list">
      {#if loading}
        <div class="entries-empty">Loading…</div>
      {:else if policies.length === 0}
        <div class="entries-empty">No rules</div>
      {:else}
        {#each policies as rule (`${rule.ip}:${rule.port}:${rule.protocol}:${rule.direction}`)}
          <div class="policy-rule">
            <button class="policy-rule-main" type="button" on:click={() => edit(rule)}>
              <strong>{rule.ip}:{rule.port}</strong>
              <span>{rule.protocol} · {rule.direction}</span>
            </button>
            <button class="policy-remove" type="button" aria-label={`Remove rule ${rule.ip}:${rule.port}`} disabled={saving} on:click={() => remove(rule)}>×</button>
          </div>
        {/each}
      {/if}
    </div>
  </div>
</aside>
