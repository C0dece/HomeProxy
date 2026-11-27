<script lang="ts">
  let {
    caption = '',
    title = 'HomeProxy',
    size = 28
  }: { caption?: string; title?: string; size?: number } = $props()
</script>

<div class="brand">
  <svg
    width={size}
    height={size}
    viewBox="0 0 32 32"
    fill="none"
    xmlns="http://www.w3.org/2000/svg"
    class="emblem"
    aria-hidden="true"
  >
    <rect x="0.75" y="0.75" width="30.5" height="30.5" rx="8.25" fill="#16161A" stroke="rgba(255,255,255,0.16)" stroke-width="1.5" />
    <path d="M8 16H13.5L17.5 10.5H24" stroke="#F4F4F5" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />
    <path d="M13.5 16L17.5 21.5H24" stroke="#10B981" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />
    <circle cx="8" cy="16" r="2" fill="#F4F4F5" />
    <circle cx="24" cy="10.5" r="1.8" fill="#F4F4F5" />
    <circle cx="24" cy="21.5" r="1.8" fill="#10B981" />
  </svg>
  {#if title || caption}
    <div class="brand-text">
      {#if title}<strong>{title}</strong>{/if}
      {#if caption}<small>{caption}</small>{/if}
    </div>
  {/if}
</div>

<style>
  .brand { display: flex; align-items: center; gap: 10px; min-width: 0; }
  .emblem { flex: none; display: block; }
  .brand-text { min-width: 0; }
  strong { display: block; font-size: .92rem; font-weight: 600; letter-spacing: -.015em; color: #FFFFFF; }
  small { display: block; font-size: .7rem; color: var(--muted); }
</style>
