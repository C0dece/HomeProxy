<script lang="ts">
  import {
    ChevronDown, ChevronRight, CirclePower, Copy, Download, Eye, EyeOff,
    Globe, HardDrive, Layers, Monitor, Plus, RefreshCw, Settings, Shield, X
  } from 'lucide-svelte'
  import { invoke } from '@tauri-apps/api/core'
  import { listen } from '@tauri-apps/api/event'
  import { onMount } from 'svelte'
  import Brand from '../../../packages/ui/Brand.svelte'
  import { actionNames } from '../../../packages/shared/models'
  import type {
    Action, AutoBaseRoute, ConfigMode, CustomProxy, CustomProxyProtocol,
    Profile, RoutingMode, Rule, RuleKind, ServiceGroup, ServiceGroupEntry
  } from '../../../packages/shared/models'

  type Candidate = { tag: string; name: string; available: boolean; latencyMs?: number }
  type Application = { name: string; path: string; icon?: string }
  type ProxyListen = { bind: '127.0.0.1' | '0.0.0.0'; port: number; username: string; hasPassword: boolean }
  type DesktopSettings = { autostart: boolean; autoConnect: boolean; tunTaskInstalled: boolean }
  type RecentDomain = { domain: string; rule: string; chain: string; lastSeen: number; count: number }

  type Status = {
    platform?: 'android'
    windows?: boolean
    tun?: boolean
    strict?: boolean
    autoStart?: boolean
    alwaysOn?: boolean | null
    lockdown?: boolean | null
    excludedApps?: string[]
    exclusionsAllowed?: boolean
    linked: boolean
    online: boolean
    enabled: boolean
    profile: Profile
    custom: Action
    revision: number | null
    ack: number
    proxyPort: number
    proxyListen?: ProxyListen
    canEditGlobal?: boolean
    configMode?: ConfigMode
    customProxy?: CustomProxy | null
    routingMode?: RoutingMode
    autoBaseRoute?: AutoBaseRoute
    error: string | null
    rules: Rule[]
    localGroups?: ServiceGroup[]
    remoteRules: Rule[] | null
    remoteGroups?: ServiceGroup[] | null
    pending: Rule[]
    route: { selected: string | null; fallback: boolean; serverDirectAvailable: boolean; candidates: Candidate[] }
  }

  type Update = {
    configured: boolean
    installed: string
    allowed: boolean
    active: boolean
    confirm: boolean
    paused?: boolean
    notice: string | null
    offer: { channel: string; version: string; size: number | null; notes: string | null } | null
  }

  let data = $state<Status>()
  let android = $derived(data?.platform === 'android')
  let tab = $state<'home' | 'resources' | 'settings'>('home')
  let androidResSub = $state<'groups' | 'live'>('groups')
  let showOnboarding = $state(false)
  let onboardingStep = $state<'choose' | 'sub' | 'custom'>('choose')
  let expandedGroupKey = $state<string | null>(null)
  let inlineEntryInputs = $state<Record<string, string>>({})

  let error = $state('')
  let toast = $state<{ msg: string; kind: 'info' | 'success' | 'warn' } | null>(null)
  let toastTimer: ReturnType<typeof setTimeout> | undefined
  let busy = $state(false)
  let link = $state('')

  // Custom proxy form
  let customProto = $state<CustomProxyProtocol>('HTTP')
  let customHost = $state('')
  let customPort = $state(8443)
  let customUser = $state('')
  let customPass = $state('')
  let customHasPass = $state(false)
  let customTls = $state(false)
  let customShowPass = $state(false)
  let customDirty = $state(false)

  // Desktop proxy listen settings
  let proxyBind = $state<'127.0.0.1' | '0.0.0.0'>('127.0.0.1')
  let proxyPortInput = $state(17770)
  let proxyUser = $state('')
  let proxyPass = $state('')
  let proxyHasPass = $state(false)
  let proxyDirty = $state(false)
  let desktop = $state<DesktopSettings>()

  // Resources modal & apps
  let resourceModal = $state<HTMLDialogElement>()
  let apps = $state<Application[]>([])
  let appSearch = $state('')
  let customExePath = $state('')
  let newResName = $state('')
  let newResAddr = $state('')
  let newResStorage = $state<'local' | 'global'>('local')
  let newResRoute = $state<Action>('PROXY')

  // Android DNS live stream & exclusions
  let recentDomains = $state<RecentDomain[]>([])
  let selectedDomains = $state<string[]>([])
  let exclusionSearch = $state('')
  let exclusionPackage = $state('')

  // Diagnostics & updates
  let testHost = $state('')
  let explanation = $state<{ action: Action; scope: string; groupName?: string | null; rule: Rule | null }>()
  let update = $state<Update>()
  let channel = $state('stable')

  let configMode = $derived<ConfigMode>(data?.configMode ?? 'subscription')
  let routingMode = $derived<RoutingMode>(data?.routingMode ?? (!data?.enabled ? 'off' : data.profile === 'DIRECT_INTERNET' ? 'auto' : 'all'))
  let autoBaseRoute = $derived<AutoBaseRoute>(data?.autoBaseRoute ?? 'direct')
  let needsSetup = $derived(Boolean(data) && (showOnboarding || (!data?.linked && configMode !== 'custom')))

  let selectedCandidate = $derived(data?.route.candidates.find(c => c.tag === data?.route.selected) ?? data?.route.candidates[0])
  let filteredApps = $derived(apps.filter(app =>
    (app.name + ' ' + app.path).toLowerCase().includes(appSearch.trim().toLowerCase())
  ))
  let localGroups = $derived(data?.localGroups ?? [])
  let remoteGroups = $derived(data?.remoteGroups ?? [])
  let excludedApps = $derived(data?.excludedApps ?? [])
  let availableExclusions = $derived(apps.filter(app => !excludedApps.includes(app.path) &&
    (app.name + ' ' + app.path).toLowerCase().includes(exclusionSearch.trim().toLowerCase())
  ))
  let canExclude = $derived(!busy && Boolean(data?.revision) && Boolean(data?.exclusionsAllowed))

  function notify(msg: string, kind: 'info' | 'success' | 'warn' = 'info') {
    toast = { msg, kind }
    if (toastTimer) clearTimeout(toastTimer)
    toastTimer = setTimeout(() => { toast = null }, 2600)
  }

  function syncForms(result: Status) {
    if (!proxyDirty && result.proxyListen) {
      proxyBind = result.proxyListen.bind
      proxyPortInput = result.proxyListen.port
      proxyUser = result.proxyListen.username
      proxyHasPass = result.proxyListen.hasPassword
      proxyPass = ''
    }
    if (!customDirty && result.customProxy) {
      customProto = result.customProxy.protocol
      customHost = result.customProxy.host
      customPort = result.customProxy.port
      customUser = result.customProxy.username
      customHasPass = Boolean(result.customProxy.hasPassword)
      customTls = Boolean(result.customProxy.tls)
      customPass = ''
    }
  }

  async function talk<T>(command: string, payload: unknown = null) {
    return invoke<T>('agent_command', { command, data: payload })
  }

  async function loadDesktopSettings() {
    try {
      desktop = await talk<DesktopSettings>('desktop-settings-get')
    } catch { /* non-Windows */ }
  }

  async function run(command: string, payload: unknown = null) {
    if (busy) return
    busy = true
    error = ''
    try {
      if (command === 'explain') {
        explanation = await talk('explain', payload)
      } else if (command === 'list-apps') {
        apps = await talk('list-apps')
      } else if (command === 'vpn-settings') {
        await talk('vpn-settings')
      } else if (command === 'update-permission' || command === 'update-confirm') {
        await talk(command)
      } else if (command === 'recent-domains') {
        recentDomains = (await talk<{ domains: RecentDomain[] }>(command)).domains
      } else if (command === 'clear-recent-domains') {
        recentDomains = (await talk<{ domains: RecentDomain[] }>(command)).domains
        selectedDomains = []
      } else if (command === 'desktop-settings-set') {
        desktop = await talk<DesktopSettings>(command, payload)
      } else if (command === 'install-tun-task') {
        const res = await talk<{ tunTaskInstalled: boolean }>(command)
        if (desktop) desktop = { ...desktop, tunTaskInstalled: res.tunTaskInstalled }
        else await loadDesktopSettings()
        notify('Задача TUN без UAC настроена', 'success')
      } else if (command.startsWith('update-')) {
        if (command === 'update-check' && update) update.offer = null
        update = await talk<Update>(command, payload)
      } else {
        if (command === 'start') await invoke('start_agent')
        const result = await talk<Status>(command === 'start' ? 'status' : command, payload)
        data = result
        if (command === 'proxy-settings') proxyDirty = false
        if (command === 'save-custom-proxy') customDirty = false
        syncForms(result)
        if (result.windows && !desktop) void loadDesktopSettings()
        if (command === 'connect') {
          link = ''
          showOnboarding = false
          tab = 'home'
          notify('Конфигурация получена по подписке', 'success')
        }
      }
    } catch (failure) {
      error = String(failure)
    } finally {
      busy = false
    }
  }

  function routePillClass(act: Action): string {
    if (act === 'BLOCK') return 'block'
    if (act === 'LOCAL_DIRECT' || act === 'SERVER_DIRECT') return 'direct'
    return 'proxy'
  }

  function routeLabel(act: Action): string {
    if (act === 'PROXY') return 'Прокси'
    if (act === 'LOCAL_DIRECT') return 'Прямой'
    if (act === 'SERVER_DIRECT') return 'Сервер'
    if (act === 'BLOCK') return 'Блок'
    return actionNames[act] ?? act
  }

  function entryBadge(kind: RuleKind): string {
    if (kind === 'ip_cidr') return 'ip'
    if (kind === 'process' || kind === 'package') return 'app'
    return 'dns'
  }

  function detectEntryKind(raw: string): { kind: RuleKind; pattern: string } {
    const trimmed = raw.trim()
    if (/\.exe$/i.test(trimmed)) return { kind: 'process', pattern: trimmed }
    if (android && /^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+){2,}$/.test(trimmed) &&
        /^(com|org|ru|net|io|dev|app)\./i.test(trimmed)) {
      return { kind: 'package', pattern: trimmed }
    }
    if (trimmed.includes('/') || /^\d{1,3}(\.\d{1,3}){3}$/.test(trimmed) || trimmed.includes(':')) {
      return { kind: 'ip_cidr', pattern: trimmed }
    }
    if (trimmed.startsWith('*.')) return { kind: 'suffix', pattern: trimmed.slice(2) }
    return { kind: 'domain', pattern: trimmed }
  }

  async function togglePower() {
    if (!data) return
    if (data.alwaysOn) return
    const nextMode: RoutingMode = routingMode === 'off' ? 'auto' : 'off'
    await run('quick-mode', { mode: nextMode, baseRoute: autoBaseRoute })
    notify(nextMode === 'off' ? 'Отключено' : 'Включено (Авто)', nextMode === 'off' ? 'warn' : 'success')
  }

  async function setMode(mode: RoutingMode) {
    await run('quick-mode', { mode, baseRoute: autoBaseRoute })
  }

  async function setBaseRoute(base: AutoBaseRoute) {
    await run('quick-mode', { mode: 'auto', baseRoute: base })
    notify(`Основной трафик: ${base === 'direct' ? 'Прямой' : 'Через прокси'}`)
  }

  async function saveCustomProxyForm(finishOnboardingFlow = false) {
    await run('save-custom-proxy', {
      protocol: customProto,
      host: customHost,
      port: Number(customPort),
      username: customUser,
      password: customPass,
      keepPassword: customHasPass && customPass === '',
      tls: customProto === 'VLESS' ? true : customTls
    })
    if (!error) {
      if (finishOnboardingFlow) {
        showOnboarding = false
        tab = 'home'
      }
      notify('Свой прокси настроен', 'success')
    }
  }

  function copyProxyAddress() {
    const addr = `${data?.proxyListen?.bind ?? '127.0.0.1'}:${data?.proxyPort ?? 17770}`
    if (navigator.clipboard?.writeText) {
      navigator.clipboard.writeText(addr).catch(() => {})
    }
    notify(`Скопировано: ${addr}`, 'success')
  }

  function openAddResourceModal() {
    appSearch = ''
    customExePath = ''
    newResName = ''
    newResAddr = ''
    newResStorage = 'local'
    newResRoute = 'PROXY'
    void run('list-apps')
    resourceModal?.showModal()
  }

  async function saveGroup(group: ServiceGroup, storage: 'local' | 'global', msgText?: string) {
    const cmd = storage === 'local' ? 'save-local-group' : 'save-shared-group'
    await run(cmd, group)
    if (!error && msgText) notify(msgText, 'success')
  }

  async function addResourceFromApp(app: Application) {
    const entryKind: RuleKind = android ? 'package' : 'process'
    const newGroup: ServiceGroup = {
      name: app.name,
      action: 'PROXY',
      enabled: true,
      entries: [{ kind: entryKind, pattern: app.path, enabled: true }]
    }
    await saveGroup(newGroup, 'local', `Добавлено приложение: ${app.name}`)
    if (!error) {
      resourceModal?.close()
      const created = data?.localGroups?.find(g => g.name.toLowerCase() === app.name.toLowerCase())
      if (created?.id) expandedGroupKey = 'local:' + created.id
    }
  }

  async function addResourceFromExePath() {
    const fullPath = customExePath.trim()
    if (!fullPath) return
    const exe = fullPath.split('\\').pop()?.split('/').pop() || fullPath
    const name = exe.replace(/\.exe$/i, '') || exe
    const newGroup: ServiceGroup = {
      name,
      action: 'PROXY',
      enabled: true,
      entries: [{ kind: 'process', pattern: fullPath, enabled: true }]
    }
    await saveGroup(newGroup, 'local', `Добавлен процесс: ${exe}`)
    if (!error) {
      resourceModal?.close()
      const created = data?.localGroups?.find(g => g.name.toLowerCase() === name.toLowerCase())
      if (created?.id) expandedGroupKey = 'local:' + created.id
    }
  }

  async function confirmCustomResource(event: SubmitEvent) {
    event.preventDefault()
    const name = newResName.trim()
    if (!name) return
    const rawItems = (newResAddr.trim() || name).split(',').map(x => x.trim()).filter(Boolean)
    const entries: ServiceGroupEntry[] = rawItems.map(item => ({ ...detectEntryKind(item), enabled: true }))
    const storage = newResStorage === 'global' && data?.canEditGlobal ? 'global' : 'local'
    await saveGroup({
      name,
      action: newResRoute,
      enabled: true,
      entries
    }, storage, `Ресурс «${name}» добавлен`)
    if (!error) {
      resourceModal?.close()
    }
  }

  async function moveGroupStorage(group: ServiceGroup, currentStorage: 'local' | 'global') {
    if (!data?.canEditGlobal) return
    const target = currentStorage === 'local' ? 'global' : 'local'
    const clone: ServiceGroup = {
      name: group.name,
      action: group.action,
      enabled: group.enabled,
      entries: group.entries.map(e => ({ kind: e.kind, pattern: e.pattern, enabled: e.enabled !== false }))
    }
    await saveGroup(clone, target)
    if (!error && group.id) {
      await run(currentStorage === 'local' ? 'delete-local-group' : 'delete-shared-group', { id: group.id })
      notify(`«${group.name}» перемещён в ${target === 'global' ? 'Общие' : 'Локальные'}`, 'success')
    }
  }

  async function deleteGroup(group: ServiceGroup, storage: 'local' | 'global') {
    if (!group.id) return
    await run(storage === 'local' ? 'delete-local-group' : 'delete-shared-group', { id: group.id })
    if (!error) notify('Ресурс удалён')
  }

  async function addInlineItem(group: ServiceGroup, storage: 'local' | 'global', key: string) {
    const raw = (inlineEntryInputs[key] ?? '').trim()
    if (!raw) return
    const parsed = detectEntryKind(raw)
    if (group.entries.some(e => e.kind === parsed.kind && e.pattern.toLowerCase() === parsed.pattern.toLowerCase())) {
      notify('Такой адрес уже есть в группе', 'warn')
      return
    }
    const updated: ServiceGroup = {
      ...group,
      entries: [...group.entries, { kind: parsed.kind, pattern: parsed.pattern, enabled: true }]
    }
    await saveGroup(updated, storage, `Добавлено в «${group.name}»: ${parsed.pattern}`)
    if (!error) inlineEntryInputs = { ...inlineEntryInputs, [key]: '' }
  }

  async function addSelectedLiveDomains() {
    if (!selectedDomains.length) return
    const group: ServiceGroup = {
      name: selectedDomains[0],
      action: 'PROXY',
      enabled: true,
      entries: selectedDomains.map(d => ({ kind: 'suffix', pattern: d, enabled: true }))
    }
    await saveGroup(group, 'local', `Создан ресурс из ${selectedDomains.length} доменов`)
    if (!error) {
      selectedDomains = []
      androidResSub = 'groups'
    }
  }

  function toggleDomainSelection(domain: string, checked: boolean) {
    if (checked) {
      if (!selectedDomains.includes(domain)) selectedDomains = [...selectedDomains, domain]
    } else {
      selectedDomains = selectedDomains.filter(item => item !== domain)
    }
  }

  function toggleRuleEnabled(rule: Rule) {
    const nextEnabled = rule.enabled === false
    if (!rule.id) void run('local-rule', { ...rule, enabled: nextEnabled })
    else if (rule.userId && !rule.locked) void run('personal-rule', { ...rule, enabled: nextEnabled })
  }

  function removeRule(rule: Rule) {
    if (!rule.id) void run('local-rule', { ...rule, action: 'INHERIT' })
    else if (rule.userId && !rule.locked) void run('delete-personal-rule', { id: rule.id })
  }

  function saveProxySettings(event?: SubmitEvent) {
    event?.preventDefault()
    void run('proxy-settings', {
      bind: proxyBind,
      port: Number(proxyPortInput),
      username: proxyUser,
      password: proxyPass,
      keepPassword: proxyHasPass && proxyPass === ''
    }).then(() => {
      if (!error) notify('Параметры локального прокси сохранены', 'success')
    })
  }

  function updateExclusion(event: SubmitEvent) {
    event.preventDefault()
    const name = exclusionPackage.trim()
    if (!canExclude || !name || excludedApps.includes(name)) return
    void run('vpn-exclusion', { package: name, excluded: true }).then(() => {
      if (excludedApps.includes(name)) exclusionPackage = ''
    })
  }

  onMount(() => {
    void run('status')
    let stopListen: (() => void) | undefined
    void listen<Status>('agent-updated', event => {
      if (!busy && event.payload) {
        data = event.payload
        syncForms(event.payload)
      }
    }).then(fn => { stopListen = fn }).catch(() => {})

    function refresh() {
      if (!busy && (!data || data.linked || android || configMode === 'custom')) {
        void talk<Status>('status').then(value => {
          if (busy) return
          if (!data) error = ''
          data = value
          syncForms(value)
          if (value.windows && !desktop) void loadDesktopSettings()
        }).catch(() => {
          if (!busy && (data?.linked || android)) error = 'Локальный агент недоступен'
        })
      }
      if (!busy && tab === 'settings') {
        void talk<Update>('update-status').then(value => update = value).catch(() => {})
      }
      if (!busy && android && tab === 'resources' && androidResSub === 'live') {
        void talk<{ domains: RecentDomain[] }>('recent-domains').then(value => recentDomains = value.domains).catch(() => {})
      }
    }

    function resumed() {
      if ((android || tab === 'settings') && !document.hidden) refresh()
    }
    const timer = setInterval(refresh, 4000)
    document.addEventListener('visibilitychange', resumed)
    return () => {
      clearInterval(timer)
      document.removeEventListener('visibilitychange', resumed)
      stopListen?.()
    }
  })
</script>

{#if !data}
  <div class="shell-frame">
    <main class="stage-center">
      <section class="hp-card stack onboarding-card">
        <div class="center-stack">
          <Brand title="" size={40} />
          <h1>Локальный агент</h1>
          <p class="muted">Агент продолжает обслуживать прокси после закрытия окна.</p>
        </div>
        {#if error}<p class="notice error" role="alert">{error}</p>{/if}
        <button class="primary" disabled={busy} onclick={() => run('start')}>
          <CirclePower size={17} /> {busy ? 'Запуск…' : 'Запустить агент'}
        </button>
      </section>
    </main>
  </div>

{:else if needsSetup}
  <div class="shell-frame" class:mobile-frame={android}>
    <header class="app-header between">
      <Brand title="HomeProxy" size={android ? 24 : 26} />
      {#if showOnboarding}
        <button type="button" class="small ghost" onclick={() => showOnboarding = false}>Закрыть</button>
      {/if}
    </header>
    <main class="stage-body">
      <div class="onboarding-wrap stack">
        <div class="center-stack">
          <Brand title="" size={40} />
          <h1>Первый запуск</h1>
          <p class="muted">Выберите способ подключения</p>
        </div>

        {#if error}<p class="notice error" role="alert">{error}</p>{/if}

        {#if onboardingStep === 'choose'}
          <div class="stack">
            <button type="button" class="hp-card choice-card between" onclick={() => onboardingStep = 'sub'}>
              <span class="card-head">
                <strong>По подписке (ссылка)</strong>
                <small class="muted">Получить прокси и общие ресурсы с сервера</small>
              </span>
              <ChevronRight size={16} />
            </button>
            <button type="button" class="hp-card choice-card between" onclick={() => onboardingStep = 'custom'}>
              <span class="card-head">
                <strong>Свой прокси (без сервера)</strong>
                <small class="muted">Ввести адрес, порт и логин вручную</small>
              </span>
              <ChevronRight size={16} />
            </button>
          </div>
        {:else if onboardingStep === 'sub'}
          <form class="hp-card stack" onsubmit={e => { e.preventDefault(); void run('connect', { link }) }}>
            <span class="field-title">Вставьте ссылку подписки</span>
            <input type="password" class="mono" bind:value={link} required autocomplete="off" placeholder="https://…/connect#…" />
            <div class="flex">
              <button type="button" onclick={() => onboardingStep = 'choose'}>Назад</button>
              <button class="primary flex-1" disabled={busy || !link}>{busy ? 'Подключение…' : 'Подключить'}</button>
            </div>
          </form>
        {:else}
          <form class="hp-card stack" onsubmit={e => { e.preventDefault(); void saveCustomProxyForm(true) }}>
            <span class="field-title">Данные вашего прокси</span>
            <div class="proto-row">
              <select bind:value={customProto} onchange={() => customDirty = true}>
                <option value="HTTP">HTTP</option>
                <option value="SOCKS5">SOCKS5</option>
                <option value="VLESS">VLESS</option>
              </select>
              <input class="mono" bind:value={customHost} oninput={() => customDirty = true} placeholder="Сервер" required />
            </div>
            <div class="field-row">
              <input type="number" min="1" max="65535" class="mono" bind:value={customPort} oninput={() => customDirty = true} placeholder="Порт" required />
              <input class="mono" bind:value={customUser} oninput={() => customDirty = true} placeholder={customProto === 'VLESS' ? 'UUID' : 'Логин'} />
            </div>
            {#if customProto !== 'VLESS'}
              <input type="password" class="mono" bind:value={customPass} oninput={() => customDirty = true} placeholder={customHasPass ? 'Сохранён (оставьте пустым)' : 'Пароль'} />
            {/if}
            {#if customProto === 'HTTP'}
              <label class="check"><input type="checkbox" bind:checked={customTls} onchange={() => customDirty = true} /> TLS</label>
            {/if}
            <div class="flex">
              <button type="button" onclick={() => onboardingStep = 'choose'}>Назад</button>
              <button class="primary flex-1" disabled={busy}>Готово</button>
            </div>
          </form>
        {/if}

        {#if android}
          <div class="flex center-row">
            <button type="button" class="small ghost" disabled={busy} onclick={() => run('vpn-settings')}>
              <Settings size={14} /> Настройки VPN
            </button>
            <button type="button" class="small ghost" disabled={busy} onclick={() => { showOnboarding = false; tab = 'settings'; void run('update-status') }}>
              <Download size={14} /> Обновления
            </button>
          </div>
        {/if}
      </div>
    </main>
  </div>

{:else}
  <div class="shell-frame" class:mobile-frame={android}>
    <header class="app-header between">
      <Brand title="HomeProxy" size={android ? 24 : 26} />
      {#if !android}
        <nav class="hp-segmented top-tabs" aria-label="Разделы">
          <button type="button" class:active-soft={tab === 'home'} onclick={() => tab = 'home'}>Главная</button>
          <button type="button" class:active-soft={tab === 'resources'} onclick={() => tab = 'resources'}>Ресурсы</button>
          <button type="button" class:active-soft={tab === 'settings'} onclick={() => { tab = 'settings'; void run('update-status') }}>Настройки</button>
        </nav>
      {/if}
      <div class="flex">
        {#if configMode === 'custom'}
          <span class="signal-bars online">
            <span class="signal-bars-graph"><span></span><span></span><span></span></span>
            <span class="mono">{selectedCandidate?.latencyMs ? `${selectedCandidate.latencyMs} ms` : 'Свой'}</span>
          </span>
        {:else if data.online}
          <span class="signal-bars online">
            <span class="signal-bars-graph"><span></span><span></span><span></span></span>
            <span class="mono">{selectedCandidate?.latencyMs ? `${selectedCandidate.latencyMs} ms` : 'Онлайн'}</span>
          </span>
        {:else}
          <span class="signal-bars offline">
            <span class="signal-dot"></span>
            <span>Автономно</span>
          </span>
        {/if}
      </div>
    </header>

    <main class="stage-body stack">
      {#if error}<p class="notice error" role="alert">{error}</p>{/if}
      {#if data.error}<p class="notice warning" role="status">{data.error}</p>{/if}

      {#if tab === 'home'}
        <div class="home-panel stack">
          <div class="power-zone">
            <button
              type="button"
              class="power-btn"
              class:mobile={android}
              class:active={routingMode !== 'off'}
              class:hp-glow-active={routingMode !== 'off'}
              disabled={busy || data.alwaysOn === true || (configMode === 'subscription' && !data.revision)}
              aria-label={routingMode === 'off' ? 'Включить' : 'Выключить'}
              onclick={togglePower}
            >
              <CirclePower size={android ? 34 : 28} />
            </button>
            <div class="power-status">
              <div class="status-title">
                {#if android}
                  {routingMode === 'off' ? (data.alwaysOn ? 'Ожидание VPN' : 'Отключено') : 'Защищено'}
                {:else}
                  {routingMode === 'off' ? 'Подключение остановлено' : routingMode === 'auto' ? 'Авто-маршрутизация' : 'Весь трафик через прокси'}
                {/if}
              </div>
              <div class="status-sub">
                {#if routingMode === 'off'}
                  {android ? 'Нажмите для подключения' : 'Прямое соединение'}
                {:else if configMode === 'custom' && data.customProxy}
                  <span>{data.customProxy.host}:{data.customProxy.port}</span>
                  {#if selectedCandidate?.latencyMs} · <span class="mono telemetry-txt">{selectedCandidate.latencyMs} ms</span>{/if}
                {:else}
                  <span>{selectedCandidate?.name ?? 'Поиск узла…'}</span>
                  {#if selectedCandidate?.latencyMs} · <span class="mono telemetry-txt">{selectedCandidate.latencyMs} ms</span>{/if}
                  {#if data.route.fallback} · <span class="warn-txt">Резервный</span>{/if}
                {/if}
              </div>
            </div>
          </div>

          <div class="stack mode-box">
            <div class="hp-segmented three-cols" role="group" aria-label="Режим маршрутизации">
              <button
                type="button"
                class:active-muted={routingMode === 'off'}
                disabled={busy || data.alwaysOn === true}
                onclick={() => setMode('off')}
              >Выкл</button>
              <button
                type="button"
                class:active={routingMode === 'auto'}
                disabled={busy || (configMode === 'subscription' && !data.revision)}
                onclick={() => setMode('auto')}
              >Авто</button>
              <button
                type="button"
                class:active={routingMode === 'all'}
                disabled={busy || (configMode === 'subscription' && !data.revision)}
                onclick={() => setMode('all')}
              >Весь трафик</button>
            </div>

            {#if routingMode === 'auto'}
              <div class="base-route-bar between">
                <span class="muted">Основной трафик:</span>
                <div class="hp-segmented two-cols mini">
                  <button type="button" class:active-muted={autoBaseRoute === 'direct'} disabled={busy} onclick={() => setBaseRoute('direct')}>Прямой</button>
                  <button type="button" class:active-soft={autoBaseRoute === 'proxy'} disabled={busy} onclick={() => setBaseRoute('proxy')}>Через прокси</button>
                </div>
              </div>
            {/if}
          </div>

          {#if configMode === 'custom' && data.customProxy}
            <div class="proxy-pick selected between">
              <div class="card-head">
                <strong class="mono">{data.customProxy.host}:{data.customProxy.port}</strong>
                <small class="mono muted">{data.customProxy.protocol} · Свой прокси</small>
              </div>
              <span class="signal-bars" class:online={Boolean(selectedCandidate?.available)} class:offline={!selectedCandidate?.available}>
                <span class="signal-dot"></span>
                <span class="mono">{selectedCandidate?.latencyMs ? `${selectedCandidate.latencyMs} ms` : (selectedCandidate?.available ? 'Онлайн' : 'Ожидание')}</span>
              </span>
            </div>
          {:else if data.route.candidates.length > 1}
            <div class="stack node-list">
              <div class="node-label">Выходной узел</div>
              {#each data.route.candidates as cand (cand.tag)}
                {@const isSelected = data.route.selected === cand.tag}
                <button
                  type="button"
                  class="proxy-pick between"
                  class:selected={isSelected}
                  disabled={busy || !data.enabled}
                  onclick={() => run('select-proxy', { tag: cand.tag })}
                >
                  <span class="flex">
                    <span class="node-dot" class:on={isSelected}></span>
                    <span class="card-head">
                      <strong>{cand.name}</strong>
                      <small class="mono muted">{cand.tag === 'home' ? 'VLESS + REALITY' : 'HTTP CONNECT'}</small>
                    </span>
                  </span>
                  {#if cand.available}
                    <span class="signal-bars online">
                      <span class="signal-bars-graph"><span></span><span></span><span></span></span>
                      <span class="mono">{cand.latencyMs ? `${cand.latencyMs} ms` : 'Онлайн'}</span>
                    </span>
                  {:else}
                    <span class="signal-bars offline">
                      <span class="signal-dot"></span>
                      <span>Офлайн</span>
                    </span>
                  {/if}
                </button>
              {/each}
            </div>
          {/if}

          {#if !android}
            <div class="agent-footer between">
              <button
                type="button"
                class="tun-pill"
                disabled={busy || data.strict || (!data.revision && configMode !== 'custom')}
                onclick={() => run('windows-tun', { tun: !data?.tun })}
              >
                <span class="tun-dot" class:on={data.tun}></span>
                <span>TUN: {data.tun ? 'Вкл' : 'Выкл'}</span>
              </button>
              <button type="button" class="addr-copy mono" title="Скопировать адрес прокси" onclick={copyProxyAddress}>
                {data.proxyListen?.bind ?? '127.0.0.1'}:{data.proxyPort}
                <Copy size={12} />
              </button>
            </div>
          {/if}
        </div>

      {:else if tab === 'resources'}
        <div class="stack">
          {#if android}
            <div class="hp-segmented two-cols">
              <button type="button" class:active-soft={androidResSub === 'groups'} onclick={() => androidResSub = 'groups'}>Ресурсы и группы</button>
              <button type="button" class:active-soft={androidResSub === 'live'} onclick={() => { androidResSub = 'live'; void run('recent-domains') }}>Поток DNS</button>
            </div>
          {/if}

          {#if android && androidResSub === 'live'}
            <section class="hp-card stack">
              <div class="between">
                <span class="section-title">Поток DNS ({recentDomains.length})</span>
                <div class="flex">
                  <button type="button" class="small" disabled={busy} onclick={() => run('recent-domains')}><RefreshCw size={13} /></button>
                  <button type="button" class="small ghost" disabled={busy || !recentDomains.length} onclick={() => run('clear-recent-domains')}>Очистить</button>
                </div>
              </div>
              {#if !data.enabled}
                <p class="notice">Включите VPN, чтобы видеть домены в реальном времени.</p>
              {/if}
              {#if recentDomains.length}
                <div class="list-divide">
                  {#each recentDomains as item (item.domain)}
                    <label class="live-row">
                      <input
                        type="checkbox"
                        checked={selectedDomains.includes(item.domain)}
                        onchange={e => toggleDomainSelection(item.domain, e.currentTarget.checked)}
                      />
                      <span class="card-head">
                        <strong class="mono">{item.domain}</strong>
                        <small class="muted">{item.count} зап. · {item.chain || 'direct'}</small>
                      </span>
                    </label>
                  {/each}
                </div>
                <button type="button" class="primary" disabled={busy || !selectedDomains.length} onclick={addSelectedLiveDomains}>
                  Создать ресурс из выбранных ({selectedDomains.length})
                </button>
              {:else}
                <p class="empty">Запросов пока нет.</p>
              {/if}
            </section>
          {:else}
            <div class="between">
              <span></span>
              <button type="button" class="primary small" onclick={openAddResourceModal}>
                <Plus size={14} /> Добавить ресурс
              </button>
            </div>

            <!-- Локальные ресурсы -->
            <section class="hp-card flush">
              <div class="card-bar between">
                <span class="flex"><HardDrive size={14} /> <span class="section-title">Локальные ресурсы</span></span>
                <small class="muted">Хранятся на устройстве</small>
              </div>
              {#if !localGroups.length && !data.rules.length}
                <p class="empty pad">Нет локальных ресурсов</p>
              {:else}
                <div class="list-divide">
                  {#each localGroups as group (group.id ?? group.name)}
                    {@const gKey = 'local:' + (group.id ?? group.name)}
                    {@const expanded = expandedGroupKey === gKey}
                    {@const activeEntries = group.entries.filter(e => e.enabled !== false).length}
                    <div>
                      <div class="res-header between">
                        <button type="button" class="res-trigger" onclick={() => expandedGroupKey = expanded ? null : gKey}>
                          {#if expanded}<ChevronDown size={14} />{:else}<ChevronRight size={14} />{/if}
                          <span class="res-icon"><Layers size={14} /></span>
                          <span class="card-head">
                            <span class="flex">
                              <strong>{group.name}</strong>
                              <span class="mono count-tag">{activeEntries}/{group.entries.length}</span>
                            </span>
                            <span class="route-pill {routePillClass(group.action)}">{routeLabel(group.action)}</span>
                          </span>
                        </button>
                        <button
                          type="button"
                          class="hp-toggle"
                          role="switch"
                          aria-checked={group.enabled}
                          aria-label={`Переключить ${group.name}`}
                          disabled={busy}
                          onclick={() => saveGroup({ ...group, enabled: !group.enabled }, 'local')}
                        >
                          <span class="hp-toggle-thumb"></span>
                        </button>
                      </div>

                      {#if expanded}
                        <div class="res-body stack">
                          <div class="between">
                            <div class="flex">
                              {#each [{ id: 'PROXY', label: 'Прокси' }, { id: 'LOCAL_DIRECT', label: 'Прямой' }, { id: 'BLOCK', label: 'Блок' }] as rt}
                                <button
                                  type="button"
                                  class="small route-choice"
                                  class:selected={group.action === rt.id}
                                  disabled={busy}
                                  onclick={() => saveGroup({ ...group, action: rt.id as Action }, 'local', `${group.name}: ${rt.label}`)}
                                >{rt.label}</button>
                              {/each}
                            </div>
                            <div class="flex">
                              {#if data.canEditGlobal}
                                <button type="button" class="small ghost" disabled={busy} onclick={() => moveGroupStorage(group, 'local')}>На сервер</button>
                              {/if}
                              <button type="button" class="small ghost danger" disabled={busy} onclick={() => deleteGroup(group, 'local')}>Удалить</button>
                            </div>
                          </div>

                          {#if group.entries.length}
                            <div class="entries-box-card list-divide">
                              {#each group.entries as entry, idx (entry.kind + ':' + entry.pattern)}
                                {@const enabled = entry.enabled !== false}
                                <div class="entry-item between">
                                  <div class="flex entry-left">
                                    <span class="type-chip mono">{entryBadge(entry.kind)}</span>
                                    <span class="mono entry-val" class:disabled={!enabled}>{entry.pattern}</span>
                                  </div>
                                  <div class="flex">
                                    <button
                                      type="button"
                                      class="inline-toggle"
                                      class:on={enabled}
                                      disabled={busy}
                                      onclick={() => saveGroup({
                                        ...group,
                                        entries: group.entries.map((it, i) => i === idx ? { ...it, enabled: !enabled } : it)
                                      }, 'local')}
                                    >{enabled ? 'Вкл' : 'Выкл'}</button>
                                    <button
                                      type="button"
                                      class="icon-x"
                                      aria-label={`Удалить ${entry.pattern}`}
                                      disabled={busy}
                                      onclick={() => saveGroup({
                                        ...group,
                                        entries: group.entries.filter((_, i) => i !== idx)
                                      }, 'local')}
                                    ><X size={13} /></button>
                                  </div>
                                </div>
                              {/each}
                            </div>
                          {/if}

                          <div class="inline-add">
                            <input
                              type="text"
                              class="mono"
                              placeholder={android ? 'Добавить домен или пакет…' : 'Добавить домен или .exe в группу…'}
                              value={inlineEntryInputs[gKey] ?? ''}
                              oninput={e => inlineEntryInputs = { ...inlineEntryInputs, [gKey]: e.currentTarget.value }}
                              onkeydown={e => { if (e.key === 'Enter') { e.preventDefault(); void addInlineItem(group, 'local', gKey) } }}
                            />
                            <button type="button" class="small" disabled={busy} onclick={() => addInlineItem(group, 'local', gKey)}>+</button>
                          </div>
                        </div>
                      {/if}
                    </div>
                  {/each}

                  {#each data.rules as rule (rule.kind + ':' + rule.pattern)}
                    {@const activeRule = rule.enabled !== false}
                    <div class="res-header between">
                      <div class="card-head">
                        <span class="mono rule-pat" class:disabled={!activeRule}>{rule.pattern}</span>
                        <span class="route-pill {routePillClass(rule.action)}">{routeLabel(rule.action)}</span>
                      </div>
                      <div class="flex">
                        <button type="button" class="inline-toggle" class:on={activeRule} disabled={busy} onclick={() => toggleRuleEnabled(rule)}>
                          {activeRule ? 'Вкл' : 'Выкл'}
                        </button>
                        <button type="button" class="icon-x" aria-label={`Удалить ${rule.pattern}`} disabled={busy} onclick={() => removeRule(rule)}>
                          <X size={14} />
                        </button>
                      </div>
                    </div>
                  {/each}
                </div>
              {/if}
            </section>

            <!-- Общие ресурсы -->
            {#if configMode === 'subscription' || remoteGroups.length || (data.remoteRules ?? []).length}
              <section class="hp-card flush">
                <div class="card-bar between">
                  <span class="flex"><Globe size={14} /> <span class="section-title">Общие ресурсы</span></span>
                  {#if data.canEditGlobal}
                    <small class="muted">На сервере · Все устройства</small>
                  {:else}
                    <span class="ro-badge">Только чтение</span>
                  {/if}
                </div>
                {#if !remoteGroups.length && !(data.remoteRules ?? []).length}
                  <p class="empty pad">Нет общих ресурсов</p>
                {:else}
                  <div class="list-divide">
                    {#each remoteGroups as group (group.id ?? group.name)}
                      {@const gKey = 'global:' + (group.id ?? group.name)}
                      {@const expanded = expandedGroupKey === gKey}
                      {@const locked = !data.canEditGlobal || Boolean(group.locked)}
                      {@const activeEntries = group.entries.filter(e => e.enabled !== false).length}
                      <div>
                        <div class="res-header between">
                          <button type="button" class="res-trigger" onclick={() => expandedGroupKey = expanded ? null : gKey}>
                            {#if expanded}<ChevronDown size={14} />{:else}<ChevronRight size={14} />{/if}
                            <span class="res-icon"><Globe size={14} /></span>
                            <span class="card-head">
                              <span class="flex">
                                <strong>{group.name}</strong>
                                <span class="mono count-tag">{activeEntries}/{group.entries.length}</span>
                              </span>
                              <span class="route-pill {routePillClass(group.action)}">{routeLabel(group.action)}</span>
                            </span>
                          </button>
                          <button
                            type="button"
                            class="hp-toggle"
                            role="switch"
                            aria-checked={group.enabled}
                            aria-label={`Переключить ${group.name}`}
                            disabled={busy || locked}
                            onclick={() => saveGroup({ ...group, enabled: !group.enabled }, 'global')}
                          >
                            <span class="hp-toggle-thumb"></span>
                          </button>
                        </div>

                        {#if expanded}
                          <div class="res-body stack">
                            <div class="between">
                              <div class="flex">
                                {#each [{ id: 'PROXY', label: 'Прокси' }, { id: 'LOCAL_DIRECT', label: 'Прямой' }, { id: 'BLOCK', label: 'Блок' }] as rt}
                                  <button
                                    type="button"
                                    class="small route-choice"
                                    class:selected={group.action === rt.id}
                                    disabled={busy || locked}
                                    onclick={() => saveGroup({ ...group, action: rt.id as Action }, 'global', `${group.name}: ${rt.label}`)}
                                  >{rt.label}</button>
                                {/each}
                              </div>
                              {#if !locked}
                                <div class="flex">
                                  <button type="button" class="small ghost" disabled={busy} onclick={() => moveGroupStorage(group, 'global')}>Локально</button>
                                  <button type="button" class="small ghost danger" disabled={busy} onclick={() => deleteGroup(group, 'global')}>Удалить</button>
                                </div>
                              {/if}
                            </div>

                            {#if group.entries.length}
                              <div class="entries-box-card list-divide">
                                {#each group.entries as entry, idx (entry.kind + ':' + entry.pattern)}
                                  {@const enabled = entry.enabled !== false}
                                  <div class="entry-item between">
                                    <div class="flex entry-left">
                                      <span class="type-chip mono">{entryBadge(entry.kind)}</span>
                                      <span class="mono entry-val" class:disabled={!enabled}>{entry.pattern}</span>
                                    </div>
                                    {#if !locked}
                                      <div class="flex">
                                        <button
                                          type="button"
                                          class="inline-toggle"
                                          class:on={enabled}
                                          disabled={busy}
                                          onclick={() => saveGroup({
                                            ...group,
                                            entries: group.entries.map((it, i) => i === idx ? { ...it, enabled: !enabled } : it)
                                          }, 'global')}
                                        >{enabled ? 'Вкл' : 'Выкл'}</button>
                                        <button
                                          type="button"
                                          class="icon-x"
                                          aria-label={`Удалить ${entry.pattern}`}
                                          disabled={busy}
                                          onclick={() => saveGroup({
                                            ...group,
                                            entries: group.entries.filter((_, i) => i !== idx)
                                          }, 'global')}
                                        ><X size={13} /></button>
                                      </div>
                                    {/if}
                                  </div>
                                {/each}
                              </div>
                            {/if}

                            {#if !locked}
                              <div class="inline-add">
                                <input
                                  type="text"
                                  class="mono"
                                  placeholder={android ? 'Добавить домен или пакет…' : 'Добавить домен или .exe в группу…'}
                                  value={inlineEntryInputs[gKey] ?? ''}
                                  oninput={e => inlineEntryInputs = { ...inlineEntryInputs, [gKey]: e.currentTarget.value }}
                                  onkeydown={e => { if (e.key === 'Enter') { e.preventDefault(); void addInlineItem(group, 'global', gKey) } }}
                                />
                                <button type="button" class="small" disabled={busy} onclick={() => addInlineItem(group, 'global', gKey)}>+</button>
                              </div>
                            {/if}
                          </div>
                        {/if}
                      </div>
                    {/each}

                    {#each data.remoteRules ?? [] as rule (rule.id ?? rule.pattern)}
                      {@const editable = Boolean(rule.userId) && !rule.locked}
                      {@const activeRule = rule.enabled !== false}
                      <div class="res-header between">
                        <div class="card-head">
                          <span class="mono rule-pat" class:disabled={!activeRule}>{rule.pattern}</span>
                          <span class="route-pill {routePillClass(rule.action)}">{routeLabel(rule.action)}</span>
                        </div>
                        {#if editable}
                          <div class="flex">
                            <button type="button" class="inline-toggle" class:on={activeRule} disabled={busy} onclick={() => toggleRuleEnabled(rule)}>
                              {activeRule ? 'Вкл' : 'Выкл'}
                            </button>
                            <button type="button" class="icon-x" aria-label={`Удалить ${rule.pattern}`} disabled={busy} onclick={() => removeRule(rule)}>
                              <X size={14} />
                            </button>
                          </div>
                        {/if}
                      </div>
                    {/each}
                  </div>
                {/if}
              </section>
            {/if}
          {/if}
        </div>

      {:else}
        <div class="stack settings-panel">
          <!-- Источник подключения -->
          <section class="hp-card stack">
            <div class="between">
              <span class="section-title">Источник подключения</span>
              <button type="button" class="link-btn" onclick={() => { showOnboarding = true; onboardingStep = 'choose' }}>Экран 1-го входа</button>
            </div>
            <div class="hp-segmented two-cols">
              <button
                type="button"
                class:active={configMode === 'subscription'}
                disabled={busy}
                onclick={() => run('set-config-mode', { mode: 'subscription' })}
              >По подписке</button>
              <button
                type="button"
                class:active={configMode === 'custom'}
                disabled={busy}
                onclick={() => run('set-config-mode', { mode: 'custom' })}
              >Свой прокси</button>
            </div>

            {#if configMode === 'subscription'}
              <div class="stack sub-box">
                <div class="between row-sm">
                  <span class="muted">Кэш конфигурации <code class="mono">v{data.revision ?? '—'}</code></span>
                  <span class="telemetry-txt">Работает автономно</span>
                </div>
                <div class="flex">
                  <button type="button" class="flex-1" disabled={busy || !data.linked} onclick={() => run('sync').then(() => { if (!error) notify('Конфигурация обновлена', 'success') })}>
                    Обновить с сервера
                  </button>
                  <button type="button" onclick={() => { showOnboarding = true; onboardingStep = 'sub' }}>Ссылка</button>
                  {#if data.linked}
                    <button
                      type="button"
                      class="ghost danger"
                      disabled={busy || data.alwaysOn === true}
                      onclick={() => { if (window.confirm('Удалить данные подписки с устройства?')) void run('disconnect') }}
                    >Отвязать</button>
                  {/if}
                </div>
              </div>
            {:else}
              <form class="stack sub-box" onsubmit={e => { e.preventDefault(); void saveCustomProxyForm(false) }}>
                <div class="proto-row">
                  <select bind:value={customProto} onchange={() => customDirty = true}>
                    <option value="HTTP">HTTP</option>
                    <option value="SOCKS5">SOCKS5</option>
                    <option value="VLESS">VLESS</option>
                  </select>
                  <input class="mono" bind:value={customHost} oninput={() => customDirty = true} placeholder="Сервер" required />
                </div>
                <div class="field-row">
                  <input type="number" min="1" max="65535" class="mono" bind:value={customPort} oninput={() => customDirty = true} placeholder="Порт" required />
                  <input class="mono" bind:value={customUser} oninput={() => customDirty = true} placeholder={customProto === 'VLESS' ? 'UUID' : 'Логин'} />
                </div>
                {#if customProto !== 'VLESS'}
                  <div class="pass-wrap">
                    <input
                      type={customShowPass ? 'text' : 'password'}
                      class="mono"
                      bind:value={customPass}
                      oninput={() => customDirty = true}
                      placeholder={customHasPass ? 'Сохранён (оставьте пустым)' : 'Пароль'}
                    />
                    <button type="button" class="eye-btn" aria-label="Показать пароль" onclick={() => customShowPass = !customShowPass}>
                      {#if customShowPass}<EyeOff size={14} />{:else}<Eye size={14} />{/if}
                    </button>
                  </div>
                {/if}
                <button class="primary" disabled={busy}>Сохранить прокси</button>
              </form>
            {/if}
          </section>

          {#if data.windows}
            <section class="hp-card flush">
              <div class="list-divide">
                <div class="setting-row between">
                  <div class="card-head">
                    <strong>Системный TUN</strong>
                    <small class="muted">
                      {desktop?.tunTaskInstalled ? 'Перехват всего ПК без запроса UAC' : 'Для работы без UAC настройте задачу Windows'}
                    </small>
                  </div>
                  <div class="flex">
                    {#if desktop && !desktop.tunTaskInstalled && !data.strict}
                      <button type="button" class="small" disabled={busy} onclick={() => run('install-tun-task')}>Без UAC</button>
                    {/if}
                    {#if !data.strict}
                      <button
                        type="button"
                        class="hp-toggle"
                        role="switch"
                        aria-checked={Boolean(data.tun)}
                        aria-label="Системный TUN"
                        disabled={busy || (configMode === 'subscription' && !data.revision)}
                        onclick={() => run('windows-tun', { tun: !data?.tun })}
                      ><span class="hp-toggle-thumb"></span></button>
                    {/if}
                  </div>
                </div>

                {#if desktop}
                  <div class="setting-row between">
                    <span>Запускать при входе в Windows</span>
                    <button
                      type="button"
                      class="hp-toggle"
                      role="switch"
                      aria-checked={desktop.autostart}
                      aria-label="Запускать при входе в Windows"
                      disabled={busy}
                      onclick={() => run('desktop-settings-set', { autostart: !desktop?.autostart })}
                    ><span class="hp-toggle-thumb"></span></button>
                  </div>
                  <div class="setting-row between">
                    <span>Включать прокси при запуске</span>
                    <button
                      type="button"
                      class="hp-toggle"
                      role="switch"
                      aria-checked={desktop.autoConnect}
                      aria-label="Включать прокси при запуске"
                      disabled={busy}
                      onclick={() => run('desktop-settings-set', { autoConnect: !desktop?.autoConnect })}
                    ><span class="hp-toggle-thumb"></span></button>
                  </div>
                {/if}

                <div class="setting-row between">
                  <span>Локальный порт</span>
                  <input
                    type="number"
                    min="1024"
                    max="65531"
                    class="mono port-input"
                    bind:value={proxyPortInput}
                    oninput={() => proxyDirty = true}
                    onchange={() => saveProxySettings()}
                  />
                </div>
              </div>
              <details class="adv-details">
                <summary>Расширенные параметры локального прокси</summary>
                <form class="stack adv-form" onsubmit={saveProxySettings}>
                  <div class="field-row">
                    <label>Адрес
                      <select bind:value={proxyBind} onchange={() => proxyDirty = true}>
                        <option value="127.0.0.1">Только этот ПК (127.0.0.1)</option>
                        <option value="0.0.0.0">Локальная сеть (0.0.0.0)</option>
                      </select>
                    </label>
                    <label>Логин
                      <input autocomplete="off" placeholder="Без авторизации" bind:value={proxyUser} oninput={() => proxyDirty = true} />
                    </label>
                  </div>
                  <label>Пароль
                    <input type="password" autocomplete="new-password" placeholder={proxyHasPass ? 'Сохранён' : 'Не задан'} bind:value={proxyPass} oninput={() => proxyDirty = true} />
                  </label>
                  <button type="submit" class="small" disabled={busy}>Сохранить</button>
                </form>
              </details>
            </section>
          {/if}

          {#if android}
            <section class="hp-card flush">
              <div class="list-divide">
                <div class="setting-row between">
                  <span>Автозапуск после перезагрузки</span>
                  <button
                    type="button"
                    class="hp-toggle"
                    role="switch"
                    aria-checked={Boolean(data.autoStart)}
                    aria-label="Автозапуск после перезагрузки"
                    disabled={busy}
                    onclick={() => run('android-autostart', { autoStart: !data?.autoStart })}
                  ><span class="hp-toggle-thumb"></span></button>
                </div>
                {#if data.alwaysOn != null}
                  <div class="setting-row between">
                    <span>Always-on VPN</span>
                    <span class="badge" class:ok={data.alwaysOn}>{data.alwaysOn ? 'Включено' : 'Выключено'}</span>
                  </div>
                  <div class="setting-row between">
                    <span>Блокировать без VPN</span>
                    <span class="badge" class:ok={data.lockdown}>{data.lockdown ? 'Включено' : 'Выключено'}</span>
                  </div>
                {/if}
              </div>
              <div class="setting-row">
                <button type="button" class="small full-w" disabled={busy} onclick={() => run('vpn-settings')}>
                  <Settings size={14} /> Настройки VPN Android
                </button>
              </div>
              <details class="adv-details" ontoggle={e => { if (e.currentTarget.open && !apps.length) void run('list-apps') }}>
                <summary>Исключения из VPN ({excludedApps.length})</summary>
                <div class="stack adv-form">
                  {#each excludedApps as name (name)}
                    <div class="between row-sm">
                      <span class="mono">{name}</span>
                      <button type="button" class="small" disabled={busy} onclick={() => run('vpn-exclusion', { package: name, excluded: false })}>Вернуть</button>
                    </div>
                  {/each}
                  <input type="search" placeholder="Поиск приложения для исключения" bind:value={exclusionSearch} />
                  <div class="app-scroll">
                    {#each availableExclusions.slice(0, 12) as item (item.path)}
                      <div class="between row-sm">
                        <span class="card-head">
                          <strong>{item.name}</strong>
                          <small class="mono muted">{item.path}</small>
                        </span>
                        <button type="button" class="small" disabled={!canExclude} onclick={() => run('vpn-exclusion', { package: item.path, excluded: true })}>Исключить</button>
                      </div>
                    {/each}
                  </div>
                  <form class="inline-add" onsubmit={updateExclusion}>
                    <input class="mono" placeholder="com.example.app" bind:value={exclusionPackage} />
                    <button type="submit" class="small" disabled={!canExclude || !exclusionPackage.trim()}>+</button>
                  </form>
                </div>
              </details>
            </section>
          {/if}

          {#if !android}
            <section class="hp-card stack">
              <span class="section-label">Проверка домена</span>
              <form class="inline-add" onsubmit={e => { e.preventDefault(); void run('explain', { host: testHost }) }}>
                <input class="mono" bind:value={testHost} placeholder="openai.com" required />
                <button type="submit" class="small" disabled={busy}>Проверить</button>
              </form>
              {#if explanation}
                <div class="diag-res">
                  {actionNames[explanation.action]} · {explanation.groupName ? `Группа «${explanation.groupName}»` : explanation.scope}
                </div>
              {/if}
            </section>
          {/if}

          <section class="hp-card stack">
            <div class="between">
              <div class="card-head">
                <span class="section-title">Обновления</span>
                <small class="mono muted">{update ? `v${update.installed}` : 'Проверка версии'}</small>
              </div>
              <button type="button" class="small" disabled={busy || update?.active} onclick={() => run('update-check', { channel })}>
                <RefreshCw size={13} /> Проверить
              </button>
            </div>
            {#if update?.paused}
              <p class="notice warning">Администратор приостановил обновления.</p>
            {:else if update?.notice}
              <p class="muted">{update.notice}</p>
            {/if}
            {#if update?.confirm}
              <button type="button" class="primary small" disabled={busy} onclick={() => run('update-confirm')}>Подтвердить установку</button>
            {:else if update?.offer?.channel === channel}
              <div class="between">
                <span>Доступна v{update.offer.version}</span>
                {#if update.allowed}
                  <button type="button" class="primary small" disabled={busy} onclick={() => run('update-install', { channel, version: update?.offer?.version })}>
                    <Download size={13} /> Установить
                  </button>
                {:else}
                  <button type="button" class="small" disabled={busy} onclick={() => run('update-permission')}>Разрешить установку</button>
                {/if}
              </div>
            {/if}
          </section>
        </div>
      {/if}
    </main>

    {#if android}
      <nav class="bottom-nav" aria-label="Разделы">
        <button type="button" class:current={tab === 'home'} onclick={() => tab = 'home'}>
          <Shield size={16} />
          <span>Главная</span>
        </button>
        <button type="button" class:current={tab === 'resources'} onclick={() => tab = 'resources'}>
          <Layers size={16} />
          <span>Ресурсы</span>
        </button>
        <button type="button" class:current={tab === 'settings'} onclick={() => { tab = 'settings'; void run('update-status') }}>
          <Settings size={16} />
          <span>Настройки</span>
        </button>
      </nav>
    {/if}
  </div>
{/if}

<dialog bind:this={resourceModal} onclick={e => { if (e.target === resourceModal) resourceModal?.close() }}>
  <div class="stack">
    <div class="between">
      <h2>Добавить ресурс</h2>
      <button type="button" class="small ghost" aria-label="Закрыть" onclick={() => resourceModal?.close()}><X size={16} /></button>
    </div>

    <div class="stack modal-section">
      <div class="between">
        <span class="modal-label">{android ? 'Установленные приложения' : 'Открытые приложения'}</span>
        <button type="button" class="small ghost" disabled={busy} onclick={() => run('list-apps')}><RefreshCw size={12} /></button>
      </div>
      <input type="search" placeholder={android ? 'Поиск приложения…' : 'Поиск процесса (.exe)…'} bind:value={appSearch} />
      <div class="app-scroll bordered">
        {#each filteredApps as item (item.path)}
          <button type="button" class="app-pick between" disabled={busy} onclick={() => addResourceFromApp(item)}>
            <span class="flex app-pick-left">
              {#if item.icon}<img src={item.icon} alt="" width="24" height="24" />{:else}<Monitor size={18} />{/if}
              <span class="card-head">
                <strong>{item.name}</strong>
                <small class="mono muted app-path">{item.path}</small>
              </span>
            </span>
            <span class="pick-cta">Выбрать</span>
          </button>
        {:else}
          <p class="empty pad">{busy ? 'Загрузка…' : 'Приложения не найдены'}</p>
        {/each}
      </div>
    </div>

    {#if !android}
      <div class="stack modal-section">
        <span class="modal-label">Или путь к программе (.exe)</span>
        <div class="inline-add">
          <input
            type="text"
            class="mono"
            placeholder="C:\Program Files\App\app.exe"
            bind:value={customExePath}
            onkeydown={e => { if (e.key === 'Enter') { e.preventDefault(); void addResourceFromExePath() } }}
          />
          <button type="button" class="small" disabled={busy || !customExePath.trim()} onclick={addResourceFromExePath}>Добавить</button>
        </div>
      </div>
    {/if}

    <form class="stack modal-section bordered-top" onsubmit={confirmCustomResource}>
      <span class="modal-label">Сайт или группа</span>
      <input required placeholder="Название (YouTube, dev.local)" bind:value={newResName} />
      <input class="mono" placeholder="Домены через запятую" bind:value={newResAddr} />
      <div class="field-row">
        <select bind:value={newResStorage}>
          <option value="local">Локально</option>
          {#if data?.canEditGlobal}
            <option value="global">На сервер</option>
          {/if}
        </select>
        <select bind:value={newResRoute}>
          <option value="PROXY">Прокси</option>
          <option value="LOCAL_DIRECT">Прямой</option>
          <option value="BLOCK">Блок</option>
        </select>
      </div>
      <button class="primary" disabled={busy}>Создать</button>
    </form>
  </div>
</dialog>

{#if toast}
  <div class="toast-float" role="status">
    <span class="toast-dot {toast.kind}"></span>
    <span>{toast.msg}</span>
  </div>
{/if}

<style>
  .shell-frame {
    min-height: 100vh;
    max-width: 720px;
    margin: 0 auto;
    display: flex;
    flex-direction: column;
    background: #0E0E11;
    border-left: 1px solid rgba(255, 255, 255, 0.07);
    border-right: 1px solid rgba(255, 255, 255, 0.07);
  }
  .shell-frame.mobile-frame { max-width: 480px; background: var(--hp-bg); border: 0; }
  .app-header {
    padding: max(12px, env(safe-area-inset-top)) 18px 12px;
    border-bottom: 1px solid rgba(255, 255, 255, 0.07);
    background: #0E0E11;
    gap: 10px;
  }
  .mobile-frame .app-header { background: var(--hp-surface); padding-inline: 14px; }
  .top-tabs { display: inline-grid; grid-auto-flow: column; grid-auto-columns: max-content; }
  .stage-center { flex: 1; display: grid; place-items: center; padding: 24px; }
  .stage-body { flex: 1; padding: 18px; overflow-y: auto; }
  .mobile-frame .stage-body { padding: 14px; padding-bottom: 84px; }

  .onboarding-card { width: min(100%, 380px); padding: 24px; gap: 18px; }
  .onboarding-wrap { max-width: 380px; margin: 16px auto; }
  .center-stack { display: grid; gap: 8px; justify-items: center; text-align: center; }
  .center-row { justify-content: center; }
  .choice-card { width: 100%; text-align: left; padding: 14px 16px; border-radius: 14px; }
  .choice-card:hover { border-color: rgba(255, 255, 255, 0.25); }
  .field-title { font-size: .82rem; font-weight: 600; color: #FFFFFF; }
  .flex-1 { flex: 1; }

  .home-panel { max-width: 460px; margin: 4px auto; width: 100%; gap: 18px; }
  .power-zone { display: grid; gap: 12px; justify-items: center; text-align: center; padding: 8px 0; }
  .power-btn {
    width: 68px;
    height: 68px;
    border-radius: 18px;
    border: 1px solid rgba(255, 255, 255, 0.12);
    background: rgba(255, 255, 255, 0.04);
    color: #A1A1AA;
    padding: 0;
  }
  .power-btn.mobile { width: 92px; height: 92px; border-radius: 999px; border-width: 2px; }
  .power-btn:hover:not(:disabled) { color: #FFFFFF; background: rgba(255, 255, 255, 0.07); }
  .power-btn.active {
    background: rgba(16, 185, 129, 0.1);
    border-color: rgba(16, 185, 129, 0.48);
    color: #6EE7B7;
  }
  .status-title { font-size: 1.05rem; font-weight: 600; color: #FFFFFF; }
  .status-sub { font-size: .78rem; color: #A1A1AA; margin-top: 2px; }
  .telemetry-txt { color: #6EE7B7; font-size: .74rem; }
  .warn-txt { color: #FCD34D; }

  .mode-box { gap: 8px; }
  .three-cols { grid-template-columns: repeat(3, minmax(0, 1fr)); }
  .two-cols { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .base-route-bar {
    padding: 8px 12px;
    border-radius: 12px;
    background: rgba(255, 255, 255, 0.025);
    border: 1px solid rgba(255, 255, 255, 0.06);
    font-size: .76rem;
  }
  .mini { padding: 2px; border-radius: 9px; }
  .mini > button { min-height: 24px; padding: 2px 9px; font-size: .74rem; border-radius: 7px; }

  .node-list { gap: 6px; }
  .node-label { font-size: .74rem; font-weight: 500; color: #A1A1AA; padding-left: 2px; }
  .proxy-pick {
    width: 100%;
    padding: 10px 14px;
    border-radius: 12px;
    border: 1px solid rgba(255, 255, 255, 0.07);
    background: rgba(9, 9, 11, 0.6);
    text-align: left;
    justify-content: space-between;
  }
  .proxy-pick.selected { background: rgba(255, 255, 255, 0.06); border-color: rgba(255, 255, 255, 0.25); }
  .node-dot { width: 8px; height: 8px; border-radius: 999px; background: #52525B; flex: none; }
  .node-dot.on { background: #F4F4F5; }

  .agent-footer {
    padding-top: 12px;
    border-top: 1px solid rgba(255, 255, 255, 0.06);
    font-size: .76rem;
  }
  .tun-pill, .addr-copy {
    background: transparent;
    border-color: transparent;
    min-height: 28px;
    padding: 4px 6px;
    color: #A1A1AA;
    font-size: .76rem;
  }
  .tun-pill:hover:not(:disabled), .addr-copy:hover:not(:disabled) {
    background: rgba(255, 255, 255, 0.05);
    border-color: transparent;
    color: #FFFFFF;
  }
  .tun-dot { width: 8px; height: 8px; border-radius: 999px; background: #52525B; }
  .tun-dot.on { background: #34D399; }

  .hp-card.flush { padding: 0; overflow: hidden; }
  .card-bar { padding: 10px 14px; border-bottom: 1px solid rgba(255, 255, 255, 0.06); background: rgba(255, 255, 255, 0.02); }
  .section-title { font-size: .8rem; font-weight: 600; color: #E4E4E7; }
  .section-label { font-size: .72rem; font-weight: 600; text-transform: uppercase; letter-spacing: .04em; color: #A1A1AA; }
  .ro-badge { font-size: .7rem; color: #FCD34D; }
  .list-divide > div { border-bottom: 1px solid rgba(255, 255, 255, 0.06); }
  .list-divide > div:last-child { border-bottom: 0; }
  .pad { padding: 14px; }

  .res-header { padding: 10px 14px; }
  .res-header:hover { background: rgba(255, 255, 255, 0.02); }
  .res-trigger {
    flex: 1;
    min-width: 0;
    justify-content: flex-start;
    background: transparent;
    border-color: transparent;
    padding: 0;
    min-height: 0;
    text-align: left;
    gap: 10px;
  }
  .res-trigger:hover { background: transparent; border-color: transparent; }
  .res-icon {
    width: 28px;
    height: 28px;
    border-radius: 8px;
    background: rgba(255, 255, 255, 0.05);
    border: 1px solid rgba(255, 255, 255, 0.1);
    display: grid;
    place-items: center;
    color: #D4D4D8;
    flex: none;
  }
  .count-tag { font-size: .68rem; color: #71717A; }
  .res-body {
    background: rgba(9, 9, 11, 0.72);
    border-top: 1px solid rgba(255, 255, 255, 0.05);
    padding: 12px 14px;
    gap: 10px;
  }
  .route-choice { min-height: 26px; padding: 3px 9px; font-size: .72rem; background: transparent; color: #A1A1AA; }
  .route-choice.selected { background: #F4F4F5; color: #09090B; border-color: #F4F4F5; font-weight: 600; }

  .entries-box-card {
    border-radius: 12px;
    border: 1px solid rgba(255, 255, 255, 0.06);
    background: rgba(18, 18, 21, 0.72);
  }
  .entry-item { padding: 8px 10px; font-size: .76rem; }
  .entry-left { min-width: 0; flex: 1; }
  .type-chip {
    font-size: .6rem;
    text-transform: uppercase;
    padding: 2px 6px;
    border-radius: 5px;
    background: rgba(255, 255, 255, 0.06);
    color: #A1A1AA;
  }
  .entry-val, .rule-pat { font-size: .74rem; color: #E4E4E7; }
  .entry-val.disabled, .rule-pat.disabled { color: #71717A; text-decoration: line-through; }
  .inline-toggle {
    min-height: 22px;
    padding: 2px 7px;
    font-size: .68rem;
    background: transparent;
    border-color: transparent;
    color: #71717A;
  }
  .inline-toggle.on { color: #34D399; }
  .icon-x { min-height: 24px; padding: 3px; background: transparent; border-color: transparent; color: #71717A; }
  .icon-x:hover:not(:disabled) { color: #FB7185; background: transparent; border-color: transparent; }

  .inline-add { display: flex; gap: 6px; }
  .inline-add input { min-height: 32px; padding: 5px 10px; font-size: .75rem; border-radius: 8px; }
  .inline-add button { min-height: 32px; padding: 4px 11px; border-radius: 8px; }

  .live-row { display: flex; align-items: center; gap: 10px; padding: 9px 2px; cursor: pointer; }
  .settings-panel { gap: 14px; }
  .sub-box { gap: 10px; padding-top: 4px; }
  .row-sm { font-size: .78rem; }
  .link-btn {
    min-height: 0;
    padding: 0;
    border: 0;
    background: transparent;
    color: #A1A1AA;
    font-size: .74rem;
    text-decoration: underline;
  }
  .link-btn:hover:not(:disabled) { color: #FFFFFF; background: transparent; }
  .proto-row { display: grid; grid-template-columns: 112px minmax(0, 1fr); gap: 8px; }
  .pass-wrap { position: relative; }
  .pass-wrap input { padding-right: 36px; }
  .eye-btn {
    position: absolute;
    right: 4px;
    top: 4px;
    min-height: 30px;
    padding: 4px 8px;
    background: transparent;
    border-color: transparent;
    color: #A1A1AA;
  }
  .eye-btn:hover { color: #FFFFFF; background: transparent; border-color: transparent; }

  .setting-row { padding: 12px 14px; font-size: .8rem; }
  .port-input { width: 92px; min-height: 32px; padding: 4px 8px; text-align: right; font-size: .78rem; }
  .adv-details { border-top: 1px solid rgba(255, 255, 255, 0.06); padding: 10px 14px; font-size: .78rem; }
  .adv-details summary { cursor: pointer; color: #A1A1AA; }
  .adv-form { margin-top: 10px; gap: 10px; }
  .full-w { width: 100%; }
  .diag-res { font-size: .8rem; color: #E4E4E7; font-weight: 500; }

  .bottom-nav {
    position: sticky;
    bottom: 0;
    z-index: 20;
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 4px;
    padding: 8px 10px max(10px, env(safe-area-inset-bottom));
    background: var(--hp-surface);
    border-top: 1px solid rgba(255, 255, 255, 0.07);
  }
  .bottom-nav button {
    flex-direction: column;
    gap: 3px;
    min-height: 44px;
    padding: 6px 4px;
    border-radius: 12px;
    border-color: transparent;
    background: transparent;
    color: #A1A1AA;
    font-size: .68rem;
  }
  .bottom-nav button.current { background: rgba(255, 255, 255, 0.1); color: #FFFFFF; }

  .modal-section { gap: 8px; }
  .modal-label { font-size: .74rem; font-weight: 500; color: #A1A1AA; }
  .bordered-top { padding-top: 12px; border-top: 1px solid rgba(255, 255, 255, 0.08); }
  .app-scroll { display: flex; flex-direction: column; max-height: 165px; overflow-y: auto; gap: 2px; }
  .app-scroll.bordered { border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 12px; background: #09090B; }
  .app-pick {
    width: 100%;
    padding: 8px 10px;
    border-radius: 0;
    border: 0;
    border-bottom: 1px solid rgba(255, 255, 255, 0.06);
    background: transparent;
    text-align: left;
  }
  .app-pick:last-child { border-bottom: 0; }
  .app-pick:hover:not(:disabled) { background: rgba(255, 255, 255, 0.05); border-color: rgba(255, 255, 255, 0.06); }
  .app-pick-left { min-width: 0; flex: 1; }
  .app-path { font-size: .68rem; max-width: 240px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .pick-cta { font-size: .7rem; color: #E4E4E7; flex: none; }

  .toast-float {
    position: fixed;
    right: 16px;
    bottom: 16px;
    z-index: 60;
    padding: 9px 14px;
    border-radius: 12px;
    border: 1px solid rgba(255, 255, 255, 0.1);
    background: var(--hp-surface);
    color: #F4F4F5;
    font-size: .76rem;
    font-weight: 500;
    display: flex;
    align-items: center;
    gap: 8px;
    box-shadow: 0 18px 40px -10px rgba(0, 0, 0, 0.85);
  }
  .toast-dot { width: 6px; height: 6px; border-radius: 999px; background: #E4E4E7; }
  .toast-dot.success { background: #34D399; }
  .toast-dot.warn { background: #FBBF24; }

  @media (max-width: 420px) {
    .app-header { padding: 10px 12px; }
    .top-tabs > button { padding: 5px 8px; font-size: .72rem; }
  }
</style>
