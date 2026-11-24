<script lang="ts">
  import { Cable, CirclePower, Download, Globe2, Link2, Monitor, RefreshCw, Route, Settings, Shield, Signal, Trash2 } from 'lucide-svelte'
  import { invoke } from '@tauri-apps/api/core'
  import { onMount } from 'svelte'
  import Brand from '../../../packages/ui/Brand.svelte'
  import { actionNames, profileNames, scopeOf } from '../../../packages/shared/models'
  import type { Action, Profile, Rule } from '../../../packages/shared/models'

  type Candidate = { tag: string; name: string; available: boolean }
  type Application = { name: string; path: string; icon?: string }
  type Status = {
    platform?: 'android';
    tun?: boolean;
    alwaysOn?: boolean | null; lockdown?: boolean | null;
    excludedApps?: string[]; exclusionsAllowed?: boolean;
    linked: boolean; online: boolean; enabled: boolean; profile: Profile; custom: Action; revision: number | null;
    ack: number; proxyPort: number; error: string | null; rules: Rule[]; remoteRules: Rule[] | null; pending: Rule[];
    route: { selected: string | null; fallback: boolean; serverDirectAvailable: boolean; candidates: Candidate[] }
  }
  type Update = {
    configured: boolean; installed: string; allowed: boolean; active: boolean; confirm: boolean;
    notice: string | null; offer: { channel: string; version: string; size: number | null; notes: string | null } | null;
  }
  let data = $state<Status>()
  let android = $derived(data?.platform === 'android')
  let appKind = $derived(android ? 'package' : 'process')
  let tab = $state<'connection' | 'rules' | 'apps' | 'diagnostics' | 'updates'>('connection')
  let error = $state('')
  let busy = $state(false)
  let link = $state('')
  let profile = $state<Profile>('AUTO')
  let custom = $state<Action>('PROXY')
  let scope = $state<'LOCAL' | 'PERSONAL'>('LOCAL')
  let pattern = $state('')
  let kind = $state<'domain' | 'suffix'>('domain')
  let action = $state<Action>('PROXY')
  let apps = $state<Application[]>([])
  let appSearch = $state('')
  let appPattern = $state('')
  let appAction = $state<Action>('PROXY')
  let appScope = $state<'LOCAL' | 'PERSONAL'>('LOCAL')
  let explanation = $state<{ action: Action; scope: string; rule: Rule | null }>()
  let testHost = $state('')
  let update = $state<Update>()
  let channel = $state('stable')
  let filteredApps = $derived(apps.filter(app =>
    (app.name + ' ' + app.path).toLowerCase().includes(appSearch.trim().toLowerCase())))
  let syncedApps = $derived((data?.remoteRules ?? []).filter(rule => rule.kind === appKind))
  let localApps = $derived((data?.rules ?? []).filter(rule => rule.kind === appKind))
  let excludedApps = $derived(data?.excludedApps ?? [])
  const siteRule = (rule: Rule) => rule.kind === 'domain' || rule.kind === 'suffix'
  let selected = $derived(data?.route.candidates.find(c => c.tag === data?.route.selected))
  let actual = $derived(!data?.enabled ? (data?.alwaysOn ? 'Ожидание VPN' : 'Отключено')
    : data.profile === 'CUSTOM' && data.custom === 'BLOCK' ? 'Блокировка'
    : data.profile === 'DIRECT_INTERNET' || data.profile === 'CUSTOM' && data.custom === 'LOCAL_DIRECT' ? 'Интернет устройства'
    : data.profile === 'CUSTOM' && data.custom === 'SERVER_DIRECT' ? 'Интернет сервера'
    : selected?.name ?? 'Прокси недоступны')

  async function talk<T>(command: string, payload: unknown = null) {
    return invoke<T>('agent_command', { command, data: payload })
  }

  async function run(command: string, payload: unknown = null) {
    if (busy) return
    busy = true; error = ''
    try {
      if (command === 'explain') explanation = await talk('explain', payload)
      else if (command === 'list-apps') apps = await talk('list-apps')
      else if (command === 'vpn-settings') await talk('vpn-settings')
      else if (command === 'update-permission' || command === 'update-confirm') await talk(command)
      else if (command.startsWith('update-')) {
        if (command === 'update-check' && update) update.offer = null
        update = await talk<Update>(command, payload)
      }
      else {
        if (command === 'start') await invoke('start_agent')
        const result = await talk<Status>(command === 'start' ? 'status' : command, payload)
        data = result; profile = result.profile; custom = result.custom
        if (command === 'connect') link = ''
        if ((command === 'local-rule' || command === 'personal-rule') && siteRule(payload as Rule)) pattern = ''
      }
    } catch (failure) { error = String(failure) }
    finally { busy = false }
  }
  onMount(() => {
    void run('status')
    function refresh() {
      if (!busy && (!data || data.linked || android)) {
        void talk<Status>('status').then(value => {
          if (busy) return
          if (!data) { profile = value.profile; custom = value.custom; error = '' }
          data = value
        }).catch(() => {
          if (!busy && (data?.linked || android)) error = 'Локальный агент недоступен'
        })
      }
      if (!busy && tab === 'updates') {
        void talk<Update>('update-status').then(value => update = value).catch(() => { error = 'Статус обновления недоступен' })
      }
    }
    function resumed() {
      if ((android || tab === 'updates') && !document.hidden) refresh()
    }
    const timer = setInterval(refresh, 5000)
    document.addEventListener('visibilitychange', resumed)
    return () => {
      clearInterval(timer)
      document.removeEventListener('visibilitychange', resumed)
    }
  })
  function updateRule(event: SubmitEvent) {
    event.preventDefault()
    const revision = data?.remoteRules?.find(r => r.userId && r.pattern === pattern.trim().toLowerCase() && r.kind === kind)?.revision ?? 0
    void run(scope === 'LOCAL' ? 'local-rule' : 'personal-rule', { pattern, kind, action, revision })
  }
  function updateAppRule(event: SubmitEvent) {
    event.preventDefault()
    const normalized = android ? appPattern.trim() : appPattern.trim().replaceAll('/', '\\').toLowerCase()
    const revision = syncedApps.find(r => r.userId && r.pattern === normalized)?.revision ?? 0
    void run(appScope === 'LOCAL' ? 'local-rule' : 'personal-rule', { pattern: normalized, kind: appKind, action: appAction, revision })
  }
  function applicationRule(id: string) {
    const matches = (rule: Rule) => rule.pattern === id && rule.action !== 'INHERIT'
    return localApps.find(matches) ?? syncedApps.find(rule => rule.userId && matches(rule)) ?? syncedApps.find(matches)
  }
  function selectPackage(id: string) {
    appPattern = id
    const rule = applicationRule(id)
    appAction = rule?.action ?? 'PROXY'
    appScope = rule?.userId ? 'PERSONAL' : 'LOCAL'
  }
  function excludePackage() {
    const name = appPattern.trim()
    if (name && window.confirm('Исключить ' + name + ' из VPN? Приложение сможет выходить в сеть напрямую. При lockdown Android заблокирует этот трафик.')) {
      void run('vpn-exclusion', { package: name, excluded: true })
    }
  }
  function showUpdates() {
    tab = 'updates'
    void run('update-status')
  }
</script>

<header class="between">
  <Brand caption={android ? 'Android VPN' : data?.tun ? 'Windows TUN' : 'Локальный агент'} />
  {#if data?.linked}<span class="badge" class:ok={data.online} class:wait={!data.online}>{data.online ? 'Сервер доступен' : 'Автономная работа'}</span>{/if}
</header>
<main class="stack">
  {#if error}<p class="notice error" role="alert">{error}</p>{/if}
  {#if data?.error}<p class="notice warning" role="status">{data.error}</p>{/if}
  {#if !data}
    <section class="card stack onboarding">
      <span class="mark"><Monitor size={22} /></span>
      <h1>Локальный агент</h1>
      <p class="muted">Агент продолжает обслуживать прокси после закрытия окна.</p>
      <button class="primary" disabled={busy} onclick={() => run('start')}><CirclePower size={18} /> {busy ? 'Запуск…' : 'Запустить агент'}</button>
    </section>
  {:else if tab === 'updates'}
    <div class="between"><h1>Обновления</h1><button onclick={() => tab = 'connection'}>Назад</button></div>
    {#if update}
      <section class="card stack">
        <p class="label">Установлена версия <code>{update.installed}</code></p>
        {#if update.configured}
          <label>Канал<select bind:value={channel} disabled={busy || update.active}>
            <option value="stable">STABLE</option><option value="beta">BETA</option><option value="dev">DEV</option>
          </select></label>
          <button disabled={busy || update.active} onclick={() => run('update-check', { channel })}><RefreshCw size={16} /> Проверить обновления</button>
          {#if update.notice}<p class="muted" role="status">{update.notice}</p>{/if}
          {#if update.confirm}
            <button class="primary" disabled={busy} onclick={() => run('update-confirm')}>Подтвердить установку</button>
          {/if}
          {#if update.active}
            <button disabled={busy} onclick={() => run('update-cancel')}>Отменить установку</button>
          {:else if update.offer?.channel === channel}
            <h2>HomeProxy {update.offer.version}</h2>
            {#if update.offer.size !== null}
              <p class="muted">{new Intl.NumberFormat('ru', { maximumFractionDigits: 1 }).format(update.offer.size / 1048576)} МБ</p>
            {/if}
            {#if update.offer.notes}<p>{update.offer.notes}</p>{/if}
            {#if update.allowed}
              <button class="primary" disabled={busy} onclick={() => run('update-install', { channel, version: update?.offer?.version })}>
                <Download size={16} /> {busy ? 'Подготовка…' : android ? 'Загрузить APK' : 'Загрузить установщик'}
              </button>
            {:else}
              <button disabled={busy} onclick={() => run('update-permission')}>Разрешить установку в Android</button>
            {/if}
          {/if}
        {:else}
          <p class="muted">Источник подписанных обновлений не задан в сборке.</p>
        {/if}
      </section>
    {/if}
  {:else if !data.linked}
    {#if data.lockdown}
      <p class="notice" role="status">Android блокирует подключения без VPN.</p>
    {/if}
    <form class="card stack onboarding" onsubmit={event => { event.preventDefault(); void run('connect', { link }) }}>
      <span class="mark"><Link2 size={22} /></span>
      <h1>Подключите устройство</h1>
      <p class="muted">Вставьте персональную ссылку из HomeProxy Admin. Агент автоматически получит правила и резервные прокси.</p>
      <label>Персональная ссылка<input type="password" bind:value={link} required autocomplete="off" placeholder="https://…/connect#…" /></label>
      <button class="primary" disabled={busy || !link}>{busy ? 'Подключение…' : 'Подключить'}</button>
    </form>
    {#if android}
      <button disabled={busy} onclick={() => run('vpn-settings')}><Settings size={16} /> Настройки VPN Android</button>
    {/if}
    <button disabled={busy} onclick={showUpdates}><Download size={16} /> Обновления</button>
  {:else}
    <div class="between">
      <h1>Маршрутизация</h1>
      {#if data.alwaysOn}
        <span class="badge ok">Always-on VPN</span>
      {:else}
        <button disabled={busy || !data.revision} onclick={() => run('enable', { enabled: !data?.enabled })}><CirclePower size={17} /> {android ? (data.enabled ? 'Остановить VPN' : 'Запустить VPN') : data.tun ? (data.enabled ? 'Остановить TUN' : 'Запустить TUN') : (data.enabled ? 'Остановить прокси' : 'Запустить прокси')}</button>
      {/if}
    </div>
    <nav class="flex" class:mobile-nav={android} aria-label="Разделы">
      <button class:current={tab === 'connection'} onclick={() => tab = 'connection'}><Route size={16} /> Подключение</button>
      <button class:current={tab === 'rules'} onclick={() => tab = 'rules'}><Globe2 size={16} /> Сайты</button>
      <button class:current={tab === 'apps'} onclick={() => { tab = 'apps'; void run('list-apps') }}><Monitor size={16} /> Приложения</button>
      <button class:current={tab === 'diagnostics'} onclick={() => tab = 'diagnostics'}><Signal size={16} /> Диагностика</button>
      <button disabled={busy || data.tun} onclick={showUpdates}><Download size={16} /> Обновления</button>
    </nav>
    {#if tab === 'connection'}
      <section class="card stack">
        <div class="between">
          <div class="flex"><span class="mark"><Cable size={20} /></span><div class="card-head"><small class="muted">Маршрут по умолчанию</small><h2>{actual}</h2></div></div>
          {#if data.route.fallback && actual === selected?.name}<span class="badge wait">Активен резерв</span>{/if}
        </div>
        {#if !android}<p class="label">Локальный прокси <code>127.0.0.1:{data.proxyPort}</code></p>{/if}
        <form class="stack" onsubmit={event => { event.preventDefault(); void run('profile', { profile, action: custom }) }}>
          <label>Профиль <select bind:value={profile}>{#each Object.entries(profileNames) as [id, name]}<option value={id}>{name}</option>{/each}</select></label>
          {#if profile === 'CUSTOM'}<label>Маршрут <select bind:value={custom}>{#each ['PROXY', 'LOCAL_DIRECT', 'SERVER_DIRECT', 'BLOCK'] as id}<option value={id}>{actionNames[id as Action]}</option>{/each}</select></label>{/if}
          <button class="primary" disabled={busy || profile === data.profile && custom === data.custom}>Применить профиль</button>
        </form>
      </section>
      {#if android}
        <section class="card stack">
          <h2>Политика VPN Android</h2>
          {#if data.alwaysOn != null}
            <div class="between item policy-status"><span>Always-on VPN</span><span class="badge" class:ok={data.alwaysOn}>{data.alwaysOn ? 'Включено' : 'Выключено'}</span></div>
            <div class="between item policy-status"><span>Блокировка без VPN</span><span class="badge" class:ok={data.lockdown}>{data.lockdown ? 'Включено' : 'Выключено'}</span></div>
          {/if}
          <button disabled={busy} onclick={() => run('vpn-settings')}><Settings size={16} /> Настройки VPN Android</button>
        </section>
      {/if}
    {:else if tab === 'rules'}
      <section class="card stack">
        <h2>Правило сайта</h2>
        <form class="stack" onsubmit={updateRule}>
          <label>Домен<input required placeholder="example.com" bind:value={pattern} /></label>
          <div class="field-row">
            <label>Область<select bind:value={scope}><option value="LOCAL">LOCAL</option><option value="PERSONAL">PERSONAL</option></select></label>
            <label>Тип<select bind:value={kind}><option value="domain">Точный домен</option><option value="suffix">С поддоменами</option></select></label>
          </div>
          <label>Маршрут<select bind:value={action}>{#each Object.entries(actionNames) as [id, name]}<option value={id}>{name}</option>{/each}</select></label>
          <button class="primary" disabled={busy}>Сохранить правило</button>
        </form>
      </section>
      <section class="card stack">
        <h2>Действующие правила</h2>
        {#each [...data.rules, ...(data.remoteRules ?? [])].filter(siteRule) as rule}
          <div class="between item">
            <div class="card-head"><span class="mono">{rule.pattern}</span><small class="muted">{scopeOf(rule)} · {actionNames[rule.action]}</small></div>
            {#if !rule.id}<button class="small ghost" aria-label={'Удалить ' + rule.pattern} onclick={() => run('local-rule', { ...rule, action: 'INHERIT' })}><Trash2 size={15} /></button>{/if}
          </div>
        {:else}<p class="muted">Правил сайтов пока нет.</p>{/each}
        {#each data.pending.filter(siteRule) as rule}
          <div class="between item"><span class="mono">{rule.pattern}</span><span class="badge wait">В очереди</span>
            <button class="small" onclick={() => run('discard-pending', rule)}>Отменить отправку</button></div>
        {/each}
      </section>
    {:else if tab === 'apps'}
      <section class="card stack">
        <div class="between">
          <h2>Правило приложения</h2>
          <button class="small" disabled={busy} onclick={() => run('list-apps')}><RefreshCw size={15} /> {android ? 'Обновить список' : 'Обновить процессы'}</button>
        </div>
        {#if android}
          <label>Поиск приложения<input type="search" bind:value={appSearch} /></label>
          <div class="application-list">
            {#each filteredApps as item (item.path)}
              {@const rule = applicationRule(item.path)}
              <button type="button" class="app-choice" aria-pressed={appPattern === item.path} onclick={() => selectPackage(item.path)}>
                {#if item.icon}<img src={item.icon} alt="" width="32" height="32" />{:else}<Monitor size={24} />{/if}
                <span class="card-head">
                  <strong>{item.name}</strong>
                  <small class="muted mono">{item.path}</small>
                  <small class="muted">{data.exclusionsAllowed && excludedApps.includes(item.path)
                    ? (data.lockdown ? 'Вне VPN · Android блокирует' : 'Вне VPN · LOCAL')
                    : rule ? scopeOf(rule) + ' · ' + actionNames[rule.action] : 'По профилю VPN'}</small>
                </span>
              </button>
            {:else}
              <p class="muted">{busy ? 'Загрузка приложений…' : 'Приложения не найдены.'}</p>
            {/each}
          </div>
        {:else}
          <p class="label">{data.tun ? 'Правило применяется в системном туннеле Windows.' : 'Правило действует, когда приложение использует локальный прокси HomeProxy.'}</p>
        {/if}
        <form class="stack" onsubmit={updateAppRule}>
          {#if !android}
            <label>Запущенное приложение<select onchange={event => appPattern = event.currentTarget.value}>
              <option value="">Выберите процесс</option>
              {#each apps as item (item.path)}<option value={item.path}>{item.name} · {item.path}</option>{/each}
            </select></label>
          {/if}
          <label>{android ? 'Имя пакета' : 'Имя или путь EXE'}<input required maxlength={android ? 255 : 1024}
            placeholder={android ? 'com.example.app' : 'example.exe'} bind:value={appPattern} autocapitalize="none" /></label>
          <div class="field-row">
            <label>Область<select bind:value={appScope}><option value="LOCAL">LOCAL</option><option value="PERSONAL">PERSONAL</option></select></label>
            <label>Маршрут<select bind:value={appAction}>{#each Object.entries(actionNames) as [id, name]}<option value={id}>{name}</option>{/each}</select></label>
          </div>
          <button class="primary" disabled={busy}>Сохранить правило</button>
        </form>
      </section>
      <section class="card stack">
        <h2>Правила приложений</h2>
        {#each [...localApps, ...syncedApps] as rule}
          <div class="between item">
            <div class="card-head"><span class="mono">{rule.pattern}</span><small class="muted">{scopeOf(rule)} · {actionNames[rule.action]}</small></div>
            {#if !rule.id}<button class="small ghost" aria-label={'Удалить ' + rule.pattern} onclick={() => run('local-rule', { ...rule, action: 'INHERIT' })}><Trash2 size={15} /></button>{/if}
          </div>
        {:else}<p class="muted">Правил приложений пока нет.</p>{/each}
        {#each data.pending.filter(rule => rule.kind === appKind) as rule}
          <div class="between item"><span class="mono">{rule.pattern}</span><span class="badge wait">В очереди</span>
            <button class="small" onclick={() => run('discard-pending', rule)}>Отменить отправку</button></div>
        {/each}
      </section>
      {#if android}
        <section class="card stack" aria-label="Исключения из VPN">
          <h2>Исключения из VPN</h2>
          {#if !data.exclusionsAllowed}
            <p class="muted">Обязательные правила приостанавливают исключения.</p>
          {:else if data.lockdown}
            <p class="muted">Android блокирует трафик исключённых приложений.</p>
          {/if}
          {#each excludedApps as name (name)}
            <div class="between item">
              <span class="mono">{name}</span>
              <button class="small" disabled={busy} aria-label={'Вернуть в VPN ' + name}
                onclick={() => run('vpn-exclusion', { package: name, excluded: false })}>Вернуть в VPN</button>
            </div>
          {/each}
          <button disabled={busy || !data.revision || !data.exclusionsAllowed || !appPattern.trim() || excludedApps.includes(appPattern.trim())}
            onclick={excludePackage}>Исключить выбранное приложение</button>
        </section>
      {/if}
    {:else}
      <section class="card stack">
        <div class="between"><h2>Доступность маршрутов</h2><button class="small" disabled={busy} onclick={() => run('probe')}><RefreshCw size={15} /> Проверить</button></div>
        {#each data.route.candidates as route}
          <div class="between item"><span>{route.name}</span><span class="badge" class:ok={route.available} class:bad={!route.available}>{route.available ? 'Доступен' : 'Недоступен'}</span></div>
        {/each}
        <div class="between item"><span>Интернет сервера</span><span class="badge" class:ok={data.route.serverDirectAvailable}>{data.route.serverDirectAvailable ? 'Доступен' : 'Недоступен'}</span></div>
        {#if !android}<form class="stack" onsubmit={e => { e.preventDefault(); void run('explain', { host: testHost }) }}>
          <label>По какому правилу пойдёт домен<input bind:value={testHost} required placeholder="example.com" /></label>
          <button disabled={busy}>Проверить правило</button>
        </form>{/if}
        {#if explanation}<p class="notice" role="status">{actionNames[explanation.action]} · {explanation.scope} {explanation.rule?.pattern ?? ''}</p>{/if}
      </section>
      <section class="card stack">
        <div class="between"><h2>Синхронизация</h2><button class="small" disabled={busy} onclick={() => run('sync')}>Синхронизировать</button></div>
        <p class="label">Конфигурация <code>{data.revision ?? 'Нет данных'}</code> · Подтверждение <code>{data.ack || 'Нет данных'}</code></p>
        <button class="danger" disabled={busy || data.alwaysOn === true}
          title={data.alwaysOn ? 'Выключите Always-on VPN в настройках Android' : undefined}
          onclick={() => { if (window.confirm('Удалить с устройства данные подключения?')) void run('disconnect') }}>Отключить учётную запись</button>
      </section>
    {/if}
    <footer class="flex muted"><Shield size={15} /> {android ? 'Маршрутизация через Android VPN' : data.tun ? 'Системная маршрутизация Windows' : 'Маршрутизация приложений, использующих локальный прокси'}</footer>
  {/if}
</main>

<style>
  header { padding: max(16px, env(safe-area-inset-top)) clamp(16px, 4vw, 32px) 16px; border-bottom: 1px solid var(--border); background: var(--sidebar); }
  main { max-width: 840px; margin: auto; padding: 26px clamp(14px, 4vw, 32px) max(26px, env(safe-area-inset-bottom)); }
  .onboarding { width: min(100%, 550px); justify-self: center; margin-top: clamp(8px, 7vh, 64px); }
  nav button.current { background: #223355; border-color: #344c79; color: #b7caff; }
  .item { border-bottom: 1px solid var(--border); padding-bottom: 12px; }
  .policy-status { gap: 8px; }
  .application-list { display: flex; flex-direction: column; gap: 6px; max-height: 18rem; overflow-y: auto; }
  .app-choice { flex: none; justify-content: flex-start; text-align: left; min-width: 0; }
  .app-choice[aria-pressed="true"] { background: #223355; border-color: var(--accent); }
  .app-choice img { flex: none; }
  .app-choice .card-head { min-width: 0; overflow-wrap: anywhere; }
  @media (max-width: 420px) {
    .mobile-nav { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .mobile-nav button { padding-inline: 6px; }
  }
  footer { font-size: .82rem; }
</style>
