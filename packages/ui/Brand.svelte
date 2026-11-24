<script lang="ts">
  import { Network } from 'lucide-svelte'
  let { caption }: { caption: string } = $props()
</script>

<div class="brand">
  <span class="mark"><Network size={21} strokeWidth={1.8} /></span>
  <div><strong>HomeProxy</strong><small>{caption}</small></div>
</div>

<style>
  .brand { display: flex; align-items: center; gap: 11px; min-width: 0; }
  strong { display: block; font-size: 1rem; letter-spacing: -.02em; }
  small { display: block; font-size: .72rem; color: var(--muted); }
</style>
