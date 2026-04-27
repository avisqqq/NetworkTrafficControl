<script>
  import { events } from './sse.js'
</script>

<div class="table-card">
  <table class="table">
    <thead>
      <tr>
        <th class="right">#</th>
        <th>Time</th>
        <th>Dir</th>
        <th>Proto</th>
        <th>Action</th>
        <th>Source</th>
        <th>Destination</th>
      </tr>
    </thead>
    <tbody>
      {#each $events as e (e.seq)}
        <tr>
          <td class="right muted">{e.seq}</td>
          <td class="muted">{e.time}</td>
          <td><span class="badge {(e.direction || 'ingress').toLowerCase()}">{e.direction || '—'}</span></td>
          <td><span class="badge {(e.proto || 'other').toLowerCase()}">{e.proto || '—'}</span></td>
          <td><span class="badge {(e.action || '').toLowerCase()}">{e.action || '—'}</span></td>
          <td class="addr">{e.src}</td>
          <td class="addr">{e.dst}</td>
        </tr>
      {/each}
    </tbody>
  </table>

  {#if $events.length === 0}
    <div style="display:flex;align-items:center;justify-content:center;height:120px;color:var(--text-3);font-size:13px">
      Waiting for events…
    </div>
  {/if}
</div>
