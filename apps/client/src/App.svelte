<script lang="ts">
  import { Activity, Cable, CirclePower, Download, Globe2, Layers, Link2, Monitor, RefreshCw, Route, Settings, Shield, Signal, Trash2 } from 'lucide-svelte'
  import { invoke } from '@tauri-apps/api/core'
  import { listen } from '@tauri-apps/api/event'
  import { onMount } from 'svelte'
  import Brand from '../../../packages/ui/Brand.svelte'
  import { actionNames, profileNames } from '../../../packages/shared/models'
  import type { Action, Profile, Rule, ServiceGroup } from '../../../packages/shared/models'

  type Candidate = { tag: string; name: string; available: boolean }
  type Application = { name: string; path: string; icon?: string }
  type ProxyListen = { bind: '127.0.0.1' | '0.0.0.0'; port: number; username: string; hasPassword: boolean }
  type DesktopSettings = { autostart: boolean; autoConnect: boolean; tunTaskInstalled: boolean }
  type RecentDomain = { domain: string; rule: string; chain: string; lastSeen: number; count: number }
  type Status = {
    platform?: 'android';
    windows?: boolean;
    tun?: boolean;
    strict?: boolean;
    autoStart?: boolean;
    alwaysOn?: boolean | null; lockdown?: boolean | null;
    excludedApps?: string[]; exclusionsAllowed?: boolean;
    linked: boolean; online: boolean; enabled: boolean; profile: Profile; custom: Action; revision: number | null;
    ack: number; proxyPort: number; proxyListen?: ProxyListen;
    error: string | null; rules: Rule[]; remoteRules: Rule[] | null; remoteGroups?: ServiceGroup[] | null; pending: Rule[];
    route: { selected: string | null; fallback: boolean; serverDirectAvailable: boolean; candidates: Candidate[] }
  }
  type Update = {
    configured: boolean; installed: string; allowed: boolean; active: boolean; confirm: boolean; paused?: boolean;
    notice: string | null; offer: { channel: string; version: string; size: number | null; notes: string | null } | null;
  }
  let data = $state<Status>()
  let android = $derived(data?.platform === 'android')
  let appKind = $derived(android ? 'package' : 'process')
  let tab = $state<'connection' | 'rules' | 'domains' | 'apps' | 'exclusions' | 'diagnostics' | 'updates'>('connection')
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
  let appIdentifier = $state<HTMLInputElement>()
  let appAction = $state<Action>('PROXY')
  let appScope = $state<'LOCAL' | 'PERSONAL'>('LOCAL')
  let exclusionSearch = $state('')
  let exclusionPackage = $state('')
  let explanation = $state<{ action: Action; scope: string; rule: Rule | null }>()
  let testHost = $state('')
  let update = $state<Update>()
  let channel = $state('stable')
  let desktop = $state<DesktopSettings>()
  let proxyBind = $state<'127.0.0.1' | '0.0.0.0'>('127.0.0.1')
  let proxyPortInput = $state(17770)
  let proxyUser = $state('')
  let proxyPass = $state('')
  let proxyHasPass = $state(false)
  let proxyDirty = $state(false)
  let recentDomains = $state<RecentDomain[]>([])
  let domainSearch = $state('')
  let selectedDomains = $state<string[]>([])
  let domainBulkScope = $state<'LOCAL' | 'PERSONAL'>('LOCAL')
  let domainBulkKind = $state<'domain' | 'suffix'>('suffix')
  let domainBulkAction = $state<Action>('PROXY')

  let filteredDomains = $derived(recentDomains.filter(d =>
    d.domain.toLowerCase().includes(domainSearch.trim().toLowerCase())))

  let filteredApps = $derived(apps.filter(app =>
    (app.name + ' ' + app.path).toLowerCase().includes(appSearch.trim().toLowerCase())))
  let syncedApps = $derived((data?.remoteRules ?? []).filter(rule => rule.kind === appKind))
  let localApps = $derived((data?.rules ?? []).filter(rule => rule.kind === appKind))
  let excludedApps = $derived(data?.excludedApps ?? [])
  let availableExclusions = $derived(apps.filter(app => !excludedApps.includes(app.path) &&
    (app.name + ' ' + app.path).toLowerCase().includes(exclusionSearch.trim().toLowerCase())))
  let canExclude = $derived(!busy && !!data?.revision && !!data?.exclusionsAllowed)
  const siteRule = (rule: Rule) => rule.kind === 'domain' || rule.kind === 'suffix'
  const exeName = (value: string) => value.split(/[\\/]/).pop() || value
  const profileDetails: Record<Profile, string> = {
    AUTO: 'Сначала напрямую к внешнему прокси с устройства, при сбое — через HomeProxy Server.',
    HOME_SERVER: 'Трафик прокси проходит через сервер HomeProxy.',
    DIRECT_HTTP: 'Agent подключается только напрямую к внешнему прокси с устройства.',
    DIRECT_INTERNET: 'По умолчанию используется интернет этого устройства; работают точечные правила.',
    CUSTOM: 'Выберите маршрут для трафика, для которого нет отдельного правила.'
  }
  const scopeLabel = (rule: { locked?: boolean; id?: string; userId?: string }) => rule.locked ? 'Обязательное правило'
    : !rule.id ? 'На этом устройстве' : rule.userId ? 'На моих устройствах' : 'Для всех пользователей'
  let selected = $derived(data?.route.candidates.find(c => c.tag === data?.route.selected))
  let actual = $derived(!data?.enabled ? (data?.alwaysOn ? 'Ожидание VPN' : 'Отключено')
    : data.profile === 'CUSTOM' && data.custom === 'BLOCK' ? 'Блокировка'
    : data.profile === 'DIRECT_INTERNET' || data.profile === 'CUSTOM' && data.custom === 'LOCAL_DIRECT' ? 'Интернет устройства'
    : data.profile === 'CUSTOM' && data.custom === 'SERVER_DIRECT' ? 'Интернет сервера'
    : selected?.name ?? 'Прокси недоступны')
  let quickMode = $derived<'off' | 'rules' | 'all' | 'custom'>(!data?.enabled ? 'off'
    : data.profile === 'DIRECT_INTERNET' ? 'rules'
    : data.profile === 'AUTO' ? 'all'
    : 'custom')

  function syncListenForm(result: Status) {
    if (proxyDirty || !result.proxyListen) return
    proxyBind = result.proxyListen.bind
    proxyPortInput = result.proxyListen.port
    proxyUser = result.proxyListen.username
    proxyHasPass = result.proxyListen.hasPassword
    proxyPass = ''
  }

  async function talk<T>(command: string, payload: unknown = null) {
    return invoke<T>('agent_command', { command, data: payload })
  }

  async function loadDesktopSettings() {
    try {
      desktop = await talk<DesktopSettings>('desktop-settings-get')
    } catch { /* non-Windows or unavailable */ }
  }

  async function run(command: string, payload: unknown = null) {
    if (busy) return
    busy = true; error = ''
    try {
      if (command === 'explain') explanation = await talk('explain', payload)
      else if (command === 'list-apps') apps = await talk('list-apps')
      else if (command === 'vpn-settings') await talk('vpn-settings')
      else if (command === 'update-permission' || command === 'update-confirm') await talk(command)
      else if (command === 'recent-domains') recentDomains = (await talk<{ domains: RecentDomain[] }>(command)).domains
      else if (command === 'clear-recent-domains') {
        recentDomains = (await talk<{ domains: RecentDomain[] }>(command)).domains
        selectedDomains = []
      }
      else if (command === 'desktop-settings-set') desktop = await talk<DesktopSettings>(command, payload)
      else if (command === 'install-tun-task') {
        const res = await talk<{ tunTaskInstalled: boolean }>(command)
        if (desktop) desktop = { ...desktop, tunTaskInstalled: res.tunTaskInstalled }
        else await loadDesktopSettings()
      }
      else if (command.startsWith('update-')) {
        if (command === 'update-check' && update) update.offer = null
        update = await talk<Update>(command, payload)
      }
      else {
        if (command === 'start') await invoke('start_agent')
        const result = await talk<Status>(command === 'start' ? 'status' : command, payload)
        data = result; profile = result.profile; custom = result.custom
        if (command === 'proxy-settings') proxyDirty = false
        syncListenForm(result)
        if (result.windows && !desktop) void loadDesktopSettings()
        if (command === 'connect') link = ''
        if ((command === 'local-rule' || command === 'personal-rule') && siteRule(payload as Rule)) pattern = ''
        if (command === 'bulk-domain-rules') selectedDomains = []
      }
    } catch (failure) { error = String(failure) }
    finally { busy = false }
  }

  async function setQuickMode(mode: 'off' | 'rules' | 'all') {
    await run('quick-mode', { mode })
  }

  function toggleDomainSelection(domain: string, checked: boolean) {
    if (checked) {
      if (!selectedDomains.includes(domain)) selectedDomains = [...selectedDomains, domain]
    } else {
      selectedDomains = selectedDomains.filter(item => item !== domain)
    }
  }

  function applyBulkDomains(event: SubmitEvent) {
    event.preventDefault()
    if (!selectedDomains.length) return
    void run('bulk-domain-rules', {
      domains: selectedDomains,
      scope: domainBulkScope,
      kind: domainBulkKind,
      action: domainBulkAction
    })
  }

  function toggleRuleEnabled(rule: Rule) {
    const nextEnabled = rule.enabled === false
    if (!rule.id) {
      void run('local-rule', { ...rule, enabled: nextEnabled })
    } else if (rule.userId && !rule.locked) {
      void run('personal-rule', { ...rule, enabled: nextEnabled })
    }
  }

  function removeRule(rule: Rule) {
    if (!rule.id) {
      void run('local-rule', { ...rule, action: 'INHERIT' })
    } else if (rule.userId && !rule.locked) {
      void run('delete-personal-rule', { id: rule.id })
    }
  }

  function saveProxySettings(event: SubmitEvent) {
    event.preventDefault()
    void run('proxy-settings', {
      bind: proxyBind,
      port: Number(proxyPortInput),
      username: proxyUser,
      password: proxyPass,
      keepPassword: proxyHasPass && proxyPass === ''
    })
  }

  onMount(() => {
    void run('status')
    let stopListen: (() => void) | undefined
    void listen<Status>('agent-updated', event => {
      if (!busy && event.payload) {
        data = event.payload
        profile = event.payload.profile
        custom = event.payload.custom
        syncListenForm(event.payload)
      }
    }).then(fn => { stopListen = fn }).catch(() => {})

    function refresh() {
      if (!busy && (!data || data.linked || android)) {
        void talk<Status>('status').then(value => {
          if (busy) return
          if (!data) { profile = value.profile; custom = value.custom; error = '' }
          data = value
          syncListenForm(value)
          if (value.windows && !desktop) void loadDesktopSettings()
        }).catch(() => {
          if (!busy && (data?.linked || android)) error = 'Локальный агент недоступен'
        })
      }
      if (!busy && tab === 'updates') {
        void talk<Update>('update-status').then(value => update = value).catch(() => { error = 'Статус обновления недоступен' })
      }
      if (!busy && android && tab === 'domains') {
        void talk<{ domains: RecentDomain[] }>('recent-domains').then(value => recentDomains = value.domains).catch(() => {})
      }
    }
    function resumed() {
      if ((android || tab === 'updates') && !document.hidden) refresh()
    }
    const timer = setInterval(refresh, 4000)
    document.addEventListener('visibilitychange', resumed)
    return () => {
      clearInterval(timer)
      document.removeEventListener('visibilitychange', resumed)
      stopListen?.()
    }
  })

  function updateRule(event: SubmitEvent) {
    event.preventDefault()
    const revision = data?.remoteRules?.find(r => r.userId && r.pattern === pattern.trim().toLowerCase() && r.kind === kind)?.revision ?? 0
    void run(scope === 'LOCAL' ? 'local-rule' : 'personal-rule', { pattern, kind, action, enabled: true, revision })
  }
  function updateAppRule(event: SubmitEvent) {
    event.preventDefault()
    const normalized = android ? appPattern.trim() : appPattern.trim().replaceAll('/', '\\').toLowerCase()
    const revision = syncedApps.find(r => r.userId && r.pattern === normalized)?.revision ?? 0
    void run(appScope === 'LOCAL' ? 'local-rule' : 'personal-rule', { pattern: normalized, kind: appKind, action: appAction, enabled: true, revision })
  }
  function applicationRule(id: string) {
    const matches = (rule: Rule) => rule.pattern === id && rule.action !== 'INHERIT'
    return localApps.find(matches) ?? syncedApps.find(rule => rule.userId && matches(rule)) ?? syncedApps.find(matches)
  }
  function selectApp(id: string, rule = applicationRule(id)) {
    appPattern = id
    appAction = rule?.action ?? 'PROXY'
    appScope = rule?.userId ? 'PERSONAL' : 'LOCAL'
  }
  function editAppRule(rule: Rule, pending = false) {
    selectApp(rule.pattern, rule)
    if (pending) appScope = 'PERSONAL'
    appIdentifier?.focus()
  }
  function updateExclusion(event: SubmitEvent) {
    event.preventDefault()
    const name = exclusionPackage.trim()
    if (!canExclude || !name || excludedApps.includes(name)) return
    void run('vpn-exclusion', { package: name, excluded: true }).then(() => {
      if (excludedApps.includes(name)) exclusionPackage = ''
    })
  }
  function showUpdates() {
    tab = 'updates'
    void run('update-status')
  }
</script>

<header class="between">
  <Brand caption={android ? 'Android VPN' : data?.tun ? 'Windows TUN' : 'Локальный агент'} />
  {#if data?.linked}
    <span class="badge" class:ok={data.online} class:wait={!data.online}>
      {data.online ? 'Сервер (API): онлайн' : 'Автономная работа'}
    </span>
  {/if}
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
        {#if update.paused}
          <p class="notice warning" role="status">Администратор приостановил обновления.</p>
          {#if update.active}<button disabled={busy} onclick={() => run('update-cancel')}>Отменить установку</button>{/if}
        {:else if update.configured}
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
        <button class:primary={!data.enabled} disabled={busy || !data.revision} onclick={() => run('enable', { enabled: !data?.enabled })}>
          <CirclePower size={17} /> {data.enabled ? 'Выключить' : 'Включить'}
        </button>
      {/if}
    </div>
    <nav class="flex" class:mobile-nav={android} aria-label="Разделы">
      <button class:current={tab === 'connection'} onclick={() => tab = 'connection'}><Route size={16} /> Подключение</button>
      <button class:current={tab === 'rules'} onclick={() => tab = 'rules'}><Globe2 size={16} /> Сайты</button>
      {#if android}
        <button class:current={tab === 'domains'} onclick={() => { tab = 'domains'; void run('recent-domains') }}><Activity size={16} /> Подключения</button>
      {/if}
      <button class:current={tab === 'apps'} onclick={() => { tab = 'apps'; void run('list-apps') }}><Monitor size={16} /> Приложения</button>
      {#if android}
        <button class:current={tab === 'exclusions'} onclick={() => { tab = 'exclusions'; void run('list-apps') }}><Shield size={16} /> Исключения</button>
      {/if}
      <button class:current={tab === 'diagnostics'} onclick={() => tab = 'diagnostics'}><Signal size={16} /> Диагностика</button>
      <button disabled={busy || data.strict} onclick={showUpdates}><Download size={16} /> Обновления</button>
    </nav>
    {#if tab === 'connection'}
      <div class="desktop-grid">
        <section class="card stack">
          <div class="between">
            <div class="flex"><span class="mark"><Cable size={20} /></span><div class="card-head"><small class="muted">Активный маршрут</small><h2>{actual}</h2></div></div>
            {#if data.enabled && data.route.fallback && actual === selected?.name}<span class="badge wait">Резервный маршрут</span>{/if}
          </div>
          <div class="mode-switch" role="group" aria-label="Быстрый выбор режима">
            <button type="button" class:mode-active={quickMode === 'off'} disabled={busy || data.alwaysOn === true || !data.revision} onclick={() => setQuickMode('off')}>Выкл</button>
            <button type="button" class:mode-active={quickMode === 'rules'} disabled={busy || !data.revision} onclick={() => setQuickMode('rules')}>Авто (правила)</button>
            <button type="button" class:mode-active={quickMode === 'all'} disabled={busy || !data.revision} onclick={() => setQuickMode('all')}>Весь трафик</button>
          </div>
          <p class="label">{profileDetails[data.profile]}</p>
          {#if !android && !data.tun}
            <p class="label">Адрес локального прокси: <code>{data.proxyListen?.bind ?? '127.0.0.1'}:{data.proxyPort}</code></p>
          {/if}
          <details>
            <summary>Расширенные режимы маршрутизации</summary>
            <form class="stack" onsubmit={event => { event.preventDefault(); void run('profile', { profile, action: custom }) }}>
              <label>Профиль<select bind:value={profile}>{#each Object.entries(profileNames) as [id, name]}<option value={id}>{name}</option>{/each}</select></label>
              <p class="label">{profileDetails[profile]}</p>
              {#if profile === 'CUSTOM'}<label>Маршрут <select bind:value={custom}>{#each ['PROXY', 'LOCAL_DIRECT', 'SERVER_DIRECT', 'BLOCK'] as id}<option value={id}>{actionNames[id as Action]}</option>{/each}</select></label>{/if}
              <button class="primary" disabled={busy || profile === data.profile && custom === data.custom}>Применить профиль</button>
            </form>
          </details>
        </section>
        {#if data.windows}
          <div class="stack">
            <section class="card stack" aria-label="Системный режим Windows">
              <div class="between">
                <div class="card-head">
                  <h2>Системный TUN</h2>
                  <span class="label">{data.strict ? 'Строгий TUN' : data.tun ? 'Системный TUN активен' : 'Локальный HTTP/SOCKS прокси'}</span>
                </div>
                {#if !data.strict}
                  <button disabled={busy || !data.revision} onclick={() => run('windows-tun', { tun: !data?.tun })}>
                    {data.tun ? 'Выключить TUN' : 'Включить TUN'}
                  </button>
                {/if}
              </div>
              <p class="label">{data.tun
                ? 'Весь трафик Windows перехватывается автоматически без настройки прокси в программах.'
                : desktop?.tunTaskInstalled
                  ? 'Задача Windows настроена — TUN запускается без запроса UAC.'
                  : 'Для запуска TUN без постоянного запроса UAC настройте задачу Windows один раз.'}</p>
              {#if desktop && !desktop.tunTaskInstalled && !data.strict}
                <button class="small" disabled={busy} onclick={() => run('install-tun-task')}>Настроить запуск TUN без UAC</button>
              {/if}
            </section>
            <section class="card stack" aria-label="Локальный прокси и автозапуск">
              <h2>Локальный прокси и автозапуск</h2>
              <form class="stack" onsubmit={saveProxySettings}>
                <div class="field-row">
                  <label>Адрес
                    <select bind:value={proxyBind} onchange={() => proxyDirty = true}>
                      <option value="127.0.0.1">Только этот ПК (127.0.0.1)</option>
                      <option value="0.0.0.0">Локальная сеть (0.0.0.0)</option>
                    </select>
                  </label>
                  <label>Порт
                    <input type="number" min="1024" max="65531" required bind:value={proxyPortInput} oninput={() => proxyDirty = true} />
                  </label>
                </div>
                <div class="field-row">
                  <label>Логин (опционально)
                    <input autocomplete="off" placeholder="Без авторизации" bind:value={proxyUser} oninput={() => proxyDirty = true} />
                  </label>
                  <label>Пароль (опционально)
                    <input type="password" autocomplete="new-password" placeholder={proxyHasPass ? 'Сохранён (оставьте пустым)' : 'Не задан'} bind:value={proxyPass} oninput={() => proxyDirty = true} />
                  </label>
                </div>
                <button disabled={busy}>Сохранить параметры прокси</button>
              </form>
              {#if desktop}
                <label class="check">
                  <input type="checkbox" checked={desktop.autostart} disabled={busy}
                    onchange={e => void run('desktop-settings-set', { autostart: e.currentTarget.checked })} />
                  Запускать HomeProxy при входе в Windows
                </label>
                <label class="check">
                  <input type="checkbox" checked={desktop.autoConnect} disabled={busy}
                    onchange={e => void run('desktop-settings-set', { autoConnect: e.currentTarget.checked })} />
                  Сразу включать прокси при запуске
                </label>
              {/if}
            </section>
          </div>
        {/if}
        {#if android}
          <section class="card stack">
            <h2>Политика VPN Android</h2>
            <label class="check">
              <input type="checkbox" checked={Boolean(data.autoStart)} disabled={busy}
                onchange={e => void run('android-autostart', { autoStart: e.currentTarget.checked })} />
              Запускать VPN автоматически после перезагрузки
            </label>
            {#if data.alwaysOn != null}
              <div class="between item policy-status"><span>Always-on VPN</span><span class="badge" class:ok={data.alwaysOn}>{data.alwaysOn ? 'Включено' : 'Выключено'}</span></div>
              <div class="between item policy-status"><span>Блокировка без VPN</span><span class="badge" class:ok={data.lockdown}>{data.lockdown ? 'Включено' : 'Выключено'}</span></div>
            {/if}
            <button disabled={busy} onclick={() => run('vpn-settings')}><Settings size={16} /> Настройки VPN Android</button>
          </section>
        {/if}
      </div>
    {:else if tab === 'rules'}
      <div class="desktop-grid">
        <section class="card stack">
          <h2>Правило сайта</h2>
          <form class="stack" onsubmit={updateRule}>
            <label>Домен<input required placeholder="example.com" bind:value={pattern} /></label>
            <div class="field-row">
              <label>Где действует<select bind:value={scope}><option value="LOCAL">На этом устройстве</option><option value="PERSONAL">На моих устройствах</option></select></label>
              <label>Тип<select bind:value={kind}><option value="domain">Точный домен</option><option value="suffix">С поддоменами</option></select></label>
            </div>
            <label>Маршрут<select bind:value={action}>{#each Object.entries(actionNames) as [id, name]}<option value={id}>{name}</option>{/each}</select></label>
            <button class="primary" disabled={busy}>Сохранить правило</button>
          </form>
        </section>
        <section class="card stack">
          <h2>Действующие правила</h2>
          {#each [...data.rules, ...(data.remoteRules ?? [])].filter(siteRule) as rule}
            {@const editable = !rule.id || (Boolean(rule.userId) && !rule.locked)}
            {@const activeRule = rule.enabled !== false}
            <div class="between item" class:rule-disabled={!activeRule}>
              <div class="card-head">
                <span class="mono">{rule.pattern}</span>
                <small class="muted">{scopeLabel(rule)} · {actionNames[rule.action]}{activeRule ? '' : ' · выключено'}</small>
              </div>
              <div class="flex">
                {#if editable}
                  <button class="small" disabled={busy} onclick={() => toggleRuleEnabled(rule)}>{activeRule ? 'Вкл' : 'Выкл'}</button>
                  <button class="small ghost" disabled={busy} aria-label={'Удалить ' + rule.pattern} onclick={() => removeRule(rule)}><Trash2 size={15} /></button>
                {/if}
              </div>
            </div>
          {:else}<p class="muted">Правил сайтов пока нет.</p>{/each}
          {#each data.pending.filter(siteRule) as rule}
            <div class="between item"><span class="mono">{rule.pattern}</span><span class="badge wait">В очереди</span>
              <button class="small" onclick={() => run('discard-pending', rule)}>Отменить отправку</button></div>
          {/each}
        </section>
        {#if (data.remoteGroups ?? []).length}
          <section class="card stack span-2">
            <div class="flex"><Layers size={18} /><h2>Группы сервисов</h2></div>
            {#each data.remoteGroups ?? [] as group (group.id ?? group.name)}
              <div class="between item">
                <div class="card-head">
                  <strong>{group.name}</strong>
                  <small class="muted">{scopeLabel(group)} · {actionNames[group.action]} · {group.entries.length} эл.</small>
                  {#if group.entries.length}
                    <small class="muted mono">{group.entries.slice(0, 4).map(e => e.pattern).join(', ')}{group.entries.length > 4 ? '…' : ''}</small>
                  {/if}
                </div>
              </div>
            {/each}
          </section>
        {/if}
      </div>
    {:else if android && tab === 'domains'}
      <div class="desktop-grid">
        <section class="card stack">
          <div class="between">
            <h2>Недавние подключения (DNS/SNI)</h2>
            <div class="flex">
              <button class="small" disabled={busy} onclick={() => run('recent-domains')}><RefreshCw size={15} /> Обновить</button>
              <button class="small ghost" disabled={busy || !recentDomains.length} onclick={() => run('clear-recent-domains')}>Очистить</button>
            </div>
          </div>
          <label>Поиск домена<input type="search" placeholder="api.example.com" bind:value={domainSearch} /></label>
          {#if !data.enabled}
            <p class="notice">Включите VPN, чтобы отслеживать обращения приложений к доменам в реальном времени.</p>
          {/if}
          <div class="application-list">
            {#each filteredDomains as item (item.domain)}
              <label class="check domain-row">
                <input type="checkbox" checked={selectedDomains.includes(item.domain)}
                  onchange={e => toggleDomainSelection(item.domain, e.currentTarget.checked)} />
                <span class="card-head">
                  <strong class="mono">{item.domain}</strong>
                  <small class="muted">{item.chain || 'direct'} · {item.count} зап.{item.rule ? ' · ' + item.rule : ''}</small>
                </span>
              </label>
            {:else}
              <p class="muted">Подключений пока нет. Откройте нужный сайт или приложение при включённом VPN.</p>
            {/each}
          </div>
        </section>
        <section class="card stack">
          <h2>Добавить выбранные в правило</h2>
          <form class="stack" onsubmit={applyBulkDomains}>
            <div class="field-row">
              <label>Где действует<select bind:value={domainBulkScope}><option value="LOCAL">На этом устройстве</option><option value="PERSONAL">На моих устройствах</option></select></label>
              <label>Тип<select bind:value={domainBulkKind}><option value="suffix">С поддоменами</option><option value="domain">Точный домен</option></select></label>
            </div>
            <label>Маршрут<select bind:value={domainBulkAction}>{#each Object.entries(actionNames) as [id, name]}<option value={id}>{name}</option>{/each}</select></label>
            <button class="primary" disabled={busy || !selectedDomains.length}>Добавить выбранные ({selectedDomains.length})</button>
          </form>
        </section>
      </div>
    {:else if tab === 'apps'}
      <div class="desktop-grid">
        <section class="card stack">
          <div class="between">
            <h2>Правило приложения</h2>
            <button class="small" disabled={busy} onclick={() => run('list-apps')}><RefreshCw size={15} /> {android ? 'Обновить список' : 'Обновить процессы'}</button>
          </div>
          {#if !android && !data.tun}
            <p class="notice">Прокси в приложении: <code>{data.proxyListen?.bind ?? '127.0.0.1'}:{data.proxyPort}</code>. Правило выбирает маршрут для трафика, который приложение отправило в Agent.</p>
          {/if}
          <label>{android ? 'Поиск приложения' : 'Поиск запущенного приложения'}<input type="search" bind:value={appSearch}
            placeholder={android ? 'Введите название' : 'Имя или путь EXE'} /></label>
          <div class="application-list">
            {#each filteredApps as item (item.path)}
              {@const rule = applicationRule(item.path)}
              {@const isExcluded = android && excludedApps.includes(item.path)}
              <div class="app-row">
                <button type="button" class="app-choice" aria-pressed={appPattern === item.path} onclick={() => selectApp(item.path)}>
                  {#if item.icon}<img src={item.icon} alt="" width="32" height="32" />{:else}<Monitor size={24} />{/if}
                  <span class="card-head">
                    <strong>{item.name}</strong>
                    <small class="muted mono app-path" title={item.path}>{item.path}</small>
                    {#if isExcluded}
                      <small class="warning">Вне VPN (исключено)</small>
                    {:else if rule}
                      <small class="muted">{scopeLabel(rule)} · {actionNames[rule.action]}</small>
                    {/if}
                  </span>
                </button>
                {#if android && data.revision}
                  <button type="button" class="small" disabled={!canExclude && !isExcluded}
                    onclick={() => run('vpn-exclusion', { package: item.path, excluded: !isExcluded })}>
                    {isExcluded ? 'В VPN' : 'Исключить'}
                  </button>
                {/if}
              </div>
            {:else}
              <p class="muted">{busy ? 'Загрузка приложений…' : 'Приложения не найдены.'}</p>
            {/each}
          </div>
          <form class="stack" onsubmit={updateAppRule}>
            <label>{android ? 'Имя пакета' : 'Имя или путь EXE'}<input required maxlength={android ? 255 : 1024}
              placeholder={android ? 'com.example.app' : 'example.exe'} bind:this={appIdentifier} bind:value={appPattern} autocapitalize="none" /></label>
            <div class="field-row">
              <label>Где действует<select bind:value={appScope}><option value="LOCAL">На этом устройстве</option><option value="PERSONAL">На моих устройствах</option></select></label>
              <label>Маршрут<select bind:value={appAction}>{#each Object.entries(actionNames) as [id, name]}<option value={id}>{name}</option>{/each}</select></label>
            </div>
            <button class="primary" disabled={busy}>Сохранить правило</button>
          </form>
        </section>
        <section class="card stack">
          <h2>Правила приложений</h2>
          {#each [...localApps, ...syncedApps] as rule}
            {@const editable = !rule.id || (Boolean(rule.userId) && !rule.locked)}
            {@const activeRule = rule.enabled !== false}
            <div class="between item" class:rule-disabled={!activeRule}>
              <div class="card-head app-rule-head">
                {#if !android}
                  <strong>{exeName(rule.pattern)}</strong>
                  {#if rule.pattern.includes('\\') || rule.pattern.includes('/')}
                    <small class="muted mono app-path" title={rule.pattern}>{rule.pattern}</small>
                  {/if}
                {:else}
                  <span class="mono">{rule.pattern}</span>
                {/if}
                <small class="muted">{scopeLabel(rule)} · {actionNames[rule.action]}{activeRule ? '' : ' · выключено'}</small>
              </div>
              <div class="flex">
                {#if editable}
                  <button class="small" disabled={busy} onclick={() => toggleRuleEnabled(rule)}>{activeRule ? 'Вкл' : 'Выкл'}</button>
                  <button class="small" onclick={() => editAppRule(rule)}>Редактировать</button>
                  <button class="small ghost" disabled={busy} aria-label={'Удалить ' + rule.pattern} onclick={() => removeRule(rule)}><Trash2 size={15} /></button>
                {/if}
              </div>
            </div>
          {:else}<p class="muted">Правил приложений пока нет.</p>{/each}
          {#each data.pending.filter(rule => rule.kind === appKind) as rule}
            <div class="between item"><span class="mono">{rule.pattern}</span><span class="badge wait">Ожидает отправки</span>
              <div class="flex">
                <button class="small" onclick={() => editAppRule(rule, true)}>Пересмотреть</button>
                <button class="small" onclick={() => run('discard-pending', rule)}>Отменить отправку</button>
              </div></div>
          {/each}
        </section>
      </div>
    {:else if android && tab === 'exclusions'}
      <section class="card stack" aria-label="Исключения из VPN">
        <div class="between">
          <h2>Приложения вне VPN</h2>
          <button class="small" onclick={() => { tab = 'apps'; void run('list-apps') }}>Правила приложений</button>
        </div>
        <p class="label">Исключённые приложения полностью обходят VPN-туннель; для маршрутизации внутри VPN (например, через внешний прокси или HomeProxy Server) используйте вкладку «Приложения».</p>
        {#if !data.revision}
          <p class="notice">Дождитесь получения настроек сервера.</p>
        {:else if !data.exclusionsAllowed}
          <p class="notice warning">Обязательные правила приостанавливают исключения.</p>
        {:else if data.lockdown}
          <p class="notice warning">Android блокирует сеть для исключённых приложений. Прямой доступ требует отключить «Блокировать подключения без VPN» в настройках Android.</p>
        {:else}
          <p class="label">Приложения из этого списка выходят в интернет напрямую с телефона.</p>
        {/if}
        {#each excludedApps as name (name)}
          {@const app = apps.find(item => item.path === name)}
          <div class="between item exclusion-row">
            <span class="card-head"><strong>{app?.name ?? name}</strong>
              {#if app}<small class="muted mono">{name}</small>{/if}
            </span>
            <button class="small" disabled={busy} aria-label={'Вернуть в VPN ' + (app?.name ?? name)} data-package={name}
              onclick={() => run('vpn-exclusion', { package: name, excluded: false })}>Вернуть в VPN</button>
          </div>
        {:else}
          <p class="muted">Список исключений пуст.</p>
        {/each}
      </section>
      <section class="card stack" aria-label="Добавить исключение">
        <h2>Добавить приложение</h2>
        <label>Поиск по названию или пакету<input type="search" bind:value={exclusionSearch} /></label>
        <div class="application-list">
          {#each availableExclusions as item (item.path)}
            <div class="exclusion-row exclusion-choice">
              {#if item.icon}<img src={item.icon} alt="" width="28" height="28" />{/if}
              <span class="card-head"><strong>{item.name}</strong><small class="muted mono app-path" title={item.path}>{item.path}</small></span>
              <button class="small" disabled={!canExclude} aria-label={'Исключить ' + item.name} data-package={item.path}
                onclick={() => run('vpn-exclusion', { package: item.path, excluded: true })}>Исключить</button>
            </div>
          {:else}
            <p class="muted">{busy ? 'Загрузка приложений…' : 'Приложения не найдены.'}</p>
          {/each}
        </div>
        <details>
          <summary>Добавить по имени пакета</summary>
          <form class="stack" onsubmit={updateExclusion}>
            <label>Имя пакета<input required maxlength="255" placeholder="com.example.app" bind:value={exclusionPackage} autocapitalize="none" /></label>
            <button disabled={!canExclude || !exclusionPackage.trim() || excludedApps.includes(exclusionPackage.trim())}>Добавить в исключения</button>
          </form>
        </details>
      </section>
    {:else}
      <div class="desktop-grid">
        <section class="card stack">
          <div class="between"><h2>Доступность маршрутов</h2><button class="small" disabled={busy || !data.enabled} onclick={() => run('probe')}><RefreshCw size={15} /> Проверить</button></div>
          <div class="between item"><span>Сервер управления (API)</span><span class="badge" class:ok={data.online} class:wait={!data.online}>{data.online ? 'Онлайн' : 'Офлайн'}</span></div>
          {#each data.route.candidates as route}
            <div class="between item"><span>{route.name}</span>
              {#if !data.enabled}
                <span class="badge">Остановлено</span>
              {:else}
                <span class="badge" class:ok={route.available} class:bad={!route.available}>{route.available ? 'Доступен' : 'Недоступен'}</span>
              {/if}
            </div>
          {/each}
          <div class="between item"><span>Интернет сервера (туннель)</span>
            {#if !data.enabled}
              <span class="badge">Остановлено</span>
            {:else}
              <span class="badge" class:ok={data.route.serverDirectAvailable}>{data.route.serverDirectAvailable ? 'Доступен' : 'Недоступен'}</span>
            {/if}
          </div>
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
      </div>
    {/if}
    <footer class="flex muted"><Shield size={15} /> {android ? 'Маршрутизация через Android VPN' : data.tun ? 'Системная маршрутизация Windows' : 'Маршрутизация приложений, использующих локальный прокси'}</footer>
  {/if}
</main>

<style>
  header { padding: max(16px, env(safe-area-inset-top)) clamp(16px, 4vw, 32px) 16px; border-bottom: 1px solid var(--border); background: var(--sidebar); }
  main { max-width: 1120px; margin: auto; padding: 26px clamp(14px, 4vw, 32px) max(26px, env(safe-area-inset-bottom)); }
  .desktop-grid { display: grid; gap: var(--space-md); align-items: start; }
  @media (min-width: 860px) {
    .desktop-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .span-2 { grid-column: 1 / -1; }
  }
  .mode-switch { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 8px; }
  .mode-switch button.mode-active { background: #3764e4; border-color: #527cf5; color: white; font-weight: 650; }
  .rule-disabled { opacity: .65; }
  .app-rule-head { min-width: 0; max-width: 100%; }
  .onboarding { width: min(100%, 550px); justify-self: center; margin-top: clamp(8px, 7vh, 64px); }
  nav button.current { background: #223355; border-color: #344c79; color: #b7caff; }
  .item { border-bottom: 1px solid var(--border); padding-bottom: 12px; }
  .policy-status { gap: 8px; }
  .application-list { display: flex; flex-direction: column; gap: 6px; max-height: 18rem; overflow: auto; }
  .app-row { display: flex; align-items: center; gap: 6px; }
  .app-row > button.small { flex: none; }
  .app-choice { flex: 1; justify-content: flex-start; text-align: left; min-width: 0; }
  .domain-row { align-items: flex-start; padding: 6px 4px; border-bottom: 1px solid var(--border); }
  .domain-row .card-head { min-width: 0; overflow-wrap: anywhere; }
  .app-choice[aria-pressed="true"] { background: #223355; border-color: var(--accent); }
  .app-choice img { flex: none; }
  .app-choice .card-head { min-width: 0; overflow-wrap: anywhere; }
  .app-path { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .exclusion-row .card-head { min-width: 0; overflow-wrap: anywhere; }
  .exclusion-choice { display: flex; align-items: center; gap: 8px; padding-block: 6px; }
  .exclusion-choice > img, .exclusion-choice > button { flex: none; }
  .exclusion-choice .card-head { flex: 1; }
  details[open] form { margin-top: 12px; }
  summary { cursor: pointer; font-size: .86rem; color: var(--secondary); }
  @media (max-width: 420px) {
    .mobile-nav { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .mobile-nav button { padding-inline: 6px; }
    .mode-switch { grid-template-columns: 1fr; }
  }
  footer { font-size: .82rem; }
</style>
