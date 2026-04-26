<script>
  import Header from './lib/Header.svelte'
  import EventTable from './lib/EventTable.svelte'
  import ListPanel from './lib/ListPanel.svelte'
</script>

<Header />

<main class="split container">
  <ListPanel />
  <EventTable />
</main>