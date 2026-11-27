<script lang="ts">
  import {
    Activity, ArrowRight, ChevronDown, ChevronRight, Copy, DatabaseBackup,
    Globe, HardDrive, KeyRound, Layers, LayoutDashboard, Link2, LogOut,
    Monitor, Plus, QrCode, RefreshCw, Router, Settings, Shield, Trash2, X
  } from 'lucide-svelte'
  import { onMount } from 'svelte'
  import Brand from '../../../packages/ui/Brand.svelte'
  import { actionNames, scopeOf } from '../../../packages/shared/models'
  import type { Action, Rule, RuleKind, ServiceGroup, ServiceGroupEntry } from '../../../packages/shared/models'
  import { admin } from './api'
  import type { Device, Proxy, State, UpdateEntry, UpdatePolicy, User } from './api'
  import { qrToSvg } from './qr'

  const TOKEN_KEY = 'homeproxy_admin_token'

  const views = [
    { id: 'overview', label: 'Обзор', icon: LayoutDashboard },
    { id: 'network', label: 'Ресурсы и сеть', icon: Layers },
    { id: 'access', label: 'Доступ и ссылки', icon: KeyRound },
    { id: 'settings', label: 'Система', icon: Settings }
  ] as const

  const eventNames: Record<string, string> = {
    'user.created': 'Создан профиль',
    'user.updated': 'Изменён профиль',
    'user.permissions': 'Обновлены права профиля',
    'user.deleted': 'Удалён профиль',
    'proxy.saved': 'Сохранён прокси',
    'proxy.deleted': 'Удалён прокси',
    'device.invited': 'Создана ссылка',
    'device.sub_link': 'Выпущена iOS-ссылка',
    'device.sub_activated': 'Подключён профиль sing-box (iOS)',
    'device.connected': 'Устройство подключено',
    'device.access_updated': 'Изменён доступ устройства',
    'device.revoked': 'Ссылка закрыта',
    'device.history_cleared': 'Очищена история устройств',
    'rule.saved': 'Сохранено правило',
    'rule.deleted': 'Удалено правило',
    'group.saved': 'Сохранён ресурс',
    'group.deleted': 'Удалён ресурс',
    'routes.saved': 'Назначены прокси',
    'client-update-policy.saved': 'Изменена политика обновлений клиентов'
  }

  const entryKindNames: Record<RuleKind, string> = {
    domain: 'Домен',
    suffix: 'Поддомены',
    ip_cidr: 'IP / CIDR',
    process: 'Приложение Windows',
    package: 'Приложение Android'
  }

  const releasePlatforms: Record<string, string> = {
    windows: 'Windows',
    android: 'Android',
    browser: 'Расширение',
    ios: 'iOS (sing-box)'
  }

  const updateOutcomes: Record<UpdateEntry['outcome'], string> = {
    installed: 'Установлено',
    'no-update': 'Нет совместимого обновления',
    completed: 'Проверка завершена',
    failed: 'Ошибка',
    paused: 'Пропущено по политике'
  }

  const updatePhases: Record<UpdateEntry['phase'], string> = {
    prerequisites: 'Подготовка',
    recovery: 'Восстановление',
    apply: 'Проверка и установка',
    policy: 'Чтение политики'
  }

  type Dialog = 'invite' | 'ios' | 'proxy' | 'user' | 'routes' | 'rule' | 'group'
  const dialogNames: Record<Dialog, string> = {
    invite: 'Новая ссылка',
    ios: 'Для iOS (sing-box)',
    proxy: 'Прокси-узел',
    user: 'Профиль',
    routes: 'Очередь прокси',
    rule: 'Точечное правило',
    group: 'Ресурс'
  }

  let view = $state<typeof views[number]['id']>('overview')
  let overviewSub = $state<'active' | 'history'>('active')
  let netSub = $state<'resources' | 'proxies'>('resources')
  let expandedGroupId = $state<string | null>(null)
  let inlineEntryInputs = $state<Record<string, string>>({})

  let data = $state<State>()
  let token = $state('')
  let keyInput = $state('')
  let search = $state('')
  let error = $state('')
  let message = $state('')
  let connected = $state(false)
  let busy = $state(false)
  let modal = $state<HTMLDialogElement>()
  let dialog = $state<Dialog>('invite')

  let userId = $state('')
  let label = $state('')
  let inviteLinkType = $state<'permanent' | 'temp'>('permanent')
  let inviteDurationVal = $state(24)
  let inviteDurationUnit = $state<'h' | 'd' | 'm'>('h')
  let inviteCanEditGlobal = $state(false)
  let link = $state('')
  let subLink = $state('')
  let iosDeepLink = $state('')
  let iosDeviceLabel = $state('')

  let editingProxy = $state<Proxy>()
  let proxyHeadersText = $state('')
  let editingUser = $state<User>()
  let editingRule = $state<Rule>()
  let editingGroup = $state<ServiceGroup>()
  let groupName = $state('')
  let groupAction = $state<Action>('PROXY')
  let groupEnabled = $state(true)
  let groupLocked = $state(false)
  let groupEntries = $state<ServiceGroupEntry[]>([])
  let newEntryKind = $state<RuleKind>('domain')
  let newEntryPattern = $state('')
  let ruleKind = $state<Rule['kind']>('domain')
  let selected = $state<string[]>([])
  let candidate = $state('')
  let systemHealth = $state<boolean | null>(null)
  let serverRelease = $state<{ version: string; api: number; dbSchema: number } | null>(null)
  let updateHistory = $state<Promise<UpdateEntry[] | null>>()
  let updatePolicy = $state<Promise<UpdatePolicy | null>>()
  let clientUpdatePolicy = $state<Promise<{ paused: boolean } | null>>()

  let title = $derived(views.find(item => item.id === view)?.label ?? 'Обзор')
  let activeDevices = $derived((data?.devices ?? []).filter(d => d.status !== 'revoked' && !d.expired))
  let historyDevices = $derived((data?.devices ?? []).filter(d => d.status === 'revoked' || Boolean(d.expired)))
  let onlineCount = $derived(activeDevices.filter(d => d.online).length)

  function matches(...fields: string[]) {
    return fields.join(' ').toLowerCase().includes(search.trim().toLowerCase())
  }

  const stamp = (value?: number) => value
    ? new Intl.DateTimeFormat('ru', { dateStyle: 'short', timeStyle: 'short' }).format(value * 1000)
    : 'Нет данных'

  const username = (id?: string) => data?.users.find(user => user.id === id)?.name ?? 'Общий профиль'

  function platformLabel(device: Device): string {
    if (device.platform) return releasePlatforms[device.platform] ?? device.platform
    if (device.universal && device.status === 'invited') return 'Автоопределение'
    return device.transport === 'browser' ? 'Расширение' : 'ПК / Android'
  }

  function formatLinkBadge(device: Device): string {
    if (device.linkType === 'permanent' || device.expires === 0) return 'Бессрочная'
    const sec = device.linkDurationSec || 0
    if (sec > 0) {
      if (sec % 86400 === 0) return `Временная · ${sec / 86400}д`
      if (sec % 3600 === 0) return `Временная · ${sec / 3600}ч`
      return `Временная · ${Math.max(1, Math.round(sec / 60))}мин`
    }
    return 'Временная'
  }

  function routePillClass(act: Action): string {
    if (act === 'BLOCK') return 'block'
    if (act === 'LOCAL_DIRECT' || act === 'SERVER_DIRECT') return 'direct'
    return 'proxy'
  }

  function routeLabel(act: Action): string {
    if (act === 'PROXY') return 'Прокси'
    if (act === 'LOCAL_DIRECT') return 'Прямой'
    if (act === 'SERVER_DIRECT') return 'Через сервер'
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
    if (trimmed.includes('/') || /^\d{1,3}(\.\d{1,3}){3}$/.test(trimmed) || trimmed.includes(':')) {
      return { kind: 'ip_cidr', pattern: trimmed }
    }
    if (trimmed.startsWith('*.')) return { kind: 'suffix', pattern: trimmed.slice(2) }
    return { kind: 'domain', pattern: trimmed }
  }

  async function load() {
    data = await admin<State>(token, 'state')
    connected = true
    if (expandedGroupId === null && data.groups.length > 0) {
      expandedGroupId = data.groups[0].id ?? null
    }
    try {
      const health = await fetch('/healthz', { signal: AbortSignal.timeout(2000) })
      serverRelease = health.ok || health.status === 503 ? await health.json() : null
      systemHealth = health.ok
    } catch {
      serverRelease = null
      systemHealth = false
    }
    if (view === 'settings') loadUpdates()
  }

  function loadUpdates() {
    updateHistory = admin<UpdateEntry[]>(token, 'update-history').catch(() => null)
    updatePolicy = admin<UpdatePolicy>(token, 'update-policy').catch(() => null)
    clientUpdatePolicy = admin<{ paused: boolean }>(token, 'client-update-policy').catch(() => null)
  }

  function setUpdatesPaused(paused: boolean) {
    void task(async () => {
      const key = token
      const policy = await admin<UpdatePolicy>(key, 'update-policy', 'PUT', { paused })
      if (token === key && view === 'settings') updatePolicy = Promise.resolve(policy)
    })
  }

  function setClientUpdatesPaused(paused: boolean) {
    void task(async () => {
      const key = token
      const policy = await admin<{ paused: boolean }>(key, 'client-update-policy', 'PUT', { paused })
      if (token === key && view === 'settings') clientUpdatePolicy = Promise.resolve(policy)
    })
  }

  async function task(work: () => Promise<void>) {
    busy = true; error = ''; message = ''
    try { await work() }
    catch (e) { error = e instanceof Error ? e.message : 'Операция прервана' }
    finally { busy = false }
  }

  function signIn(event: SubmitEvent) {
    event.preventDefault()
    token = keyInput.trim()
    void task(async () => {
      await load()
      try { sessionStorage.setItem(TOKEN_KEY, token) } catch { /* ignore */ }
      keyInput = ''
    })
  }

  function signOut() {
    connected = false
    data = undefined
    token = ''
    try { sessionStorage.removeItem(TOKEN_KEY) } catch { /* ignore */ }
    navigate('overview')
  }

  function navigate(next: typeof view) {
    view = next; search = ''; error = ''; message = ''
    if (next === 'settings') loadUpdates()
    else { updateHistory = undefined; updatePolicy = undefined; clientUpdatePolicy = undefined }
  }

  function formatHeaders(headers?: Record<string, string>) {
    if (!headers) return ''
    return Object.entries(headers).map(([k, v]) => `${k}: ${v}`).join('\n')
  }

  function parseHeaders(text: string): Record<string, string> {
    const out: Record<string, string> = {}
    for (const rawLine of text.split(/\r?\n/)) {
      const line = rawLine.trim()
      if (!line) continue
      const idx = line.indexOf(':')
      if (idx <= 0) throw new Error('Некорректный формат заголовка (ожидается Имя: Значение)')
      const key = line.slice(0, idx).trim()
      const val = line.slice(idx + 1).trim()
      out[key] = val
    }
    return out
  }

  function open(type: Dialog, item?: Proxy | Rule | User | ServiceGroup) {
    error = ''; message = ''; dialog = type; link = ''; subLink = ''; iosDeepLink = ''; iosDeviceLabel = ''; label = ''; candidate = ''
    inviteLinkType = 'permanent'
    inviteDurationVal = 24
    inviteDurationUnit = 'h'
    inviteCanEditGlobal = false
    editingProxy = type === 'proxy' ? item as Proxy | undefined : undefined
    proxyHeadersText = type === 'proxy' ? formatHeaders((item as Proxy | undefined)?.headers) : ''
    editingUser = type === 'user' ? item as User | undefined : undefined
    editingRule = type === 'rule' ? item as Rule | undefined : undefined
    editingGroup = type === 'group' ? item as ServiceGroup | undefined : undefined
    groupName = editingGroup?.name ?? ''
    groupAction = editingGroup?.action ?? 'PROXY'
    groupEnabled = editingGroup?.enabled ?? true
    groupLocked = Boolean(editingGroup?.locked)
    groupEntries = editingGroup?.entries ? editingGroup.entries.map(e => ({ ...e })) : []
    newEntryKind = 'domain'
    newEntryPattern = ''
    ruleKind = editingRule?.kind ?? 'domain'
    userId = type === 'rule'
      ? (editingRule?.userId ?? '')
      : type === 'group'
        ? (editingGroup?.userId ?? '')
        : (data?.users[0]?.id ?? '')
    selectUser(userId)
    modal?.showModal()
  }

  function addGroupEntry() {
    const pattern = newEntryPattern.trim()
    if (!pattern) return
    if (groupEntries.some(e => e.kind === newEntryKind && e.pattern.toLowerCase() === pattern.toLowerCase())) {
      error = 'Такая запись уже есть в группе'
      return
    }
    error = ''
    groupEntries = [...groupEntries, { kind: newEntryKind, pattern, enabled: true }]
    newEntryPattern = ''
  }

  function toggleUserPerm(user: User) {
    void task(async () => {
      await admin(token, `users/${user.id}/permissions`, 'PUT', { canEditGlobal: !user.canEditGlobal })
      await load()
      message = `${user.name}: общие ресурсы ${!user.canEditGlobal ? 'разрешены' : 'только чтение'}`
    })
  }

  function buildSingboxDeepLink(subUrl: string): string {
    return `sing-box://import-remote-profile?url=${encodeURIComponent(subUrl)}#HomeProxy`
  }

  async function copyText(text: string): Promise<boolean> {
    try {
      await navigator.clipboard.writeText(text)
      return true
    } catch {
      return false
    }
  }

  function showIosSubscription(device: Device) {
    void task(async () => {
      let url = device.subUrl ?? ''
      if (!url) {
        const issued = await admin<{ subUrl: string }>(token, `devices/${device.id}/sub-link`, 'POST')
        url = issued.subUrl
        await load()
      }
      const deep = buildSingboxDeepLink(url)
      const copied = await copyText(deep)
      error = ''
      dialog = 'ios'
      iosDeviceLabel = device.label
      iosDeepLink = deep
      modal?.showModal()
      message = copied ? 'Ссылка для sing-box MT скопирована' : 'Отсканируйте QR-код камерой iPhone'
    })
  }

  async function activateModalIosQr() {
    if (!subLink) return
    const deep = buildSingboxDeepLink(subLink)
    iosDeepLink = deep
    const copied = await copyText(deep)
    message = copied ? 'Ссылка для sing-box MT скопирована' : 'Отсканируйте QR-код камерой iPhone'
  }

  function toggleDeviceAccess(device: Device) {
    const next = device.accessEnabled === false
    void task(async () => {
      await admin(token, `devices/${device.id}/access`, 'PUT', { accessEnabled: next })
      await load()
      message = `${device.label}: доступ ${next ? 'включён' : 'приостановлен'}`
    })
  }

  function clearHistory() {
    void task(async () => {
      await admin(token, 'devices/history', 'DELETE')
      await load()
      message = 'История очищена'
    })
  }

  function toggleRule(rule: Rule) {
    void task(async () => {
      await admin(token, 'rules', 'PUT', {
        userId: rule.userId ?? '',
        pattern: rule.pattern,
        kind: rule.kind,
        action: rule.action,
        enabled: !(rule.enabled ?? true),
        locked: Boolean(rule.locked),
        revision: rule.revision ?? 0
      })
      await load()
      message = 'Изменения сохранены'
    })
  }

  function saveGroupSnapshot(nextGroup: ServiceGroup, noticeText = 'Изменения сохранены') {
    void task(async () => {
      await admin(token, 'groups', 'PUT', nextGroup)
      await load()
      message = noticeText
    })
  }

  function toggleGroup(group: ServiceGroup) {
    saveGroupSnapshot({ ...group, enabled: !group.enabled })
  }

  function setGroupRoute(group: ServiceGroup, nextAction: Action) {
    saveGroupSnapshot({ ...group, action: nextAction }, `${group.name}: ${routeLabel(nextAction)}`)
  }

  function toggleGroupEntry(group: ServiceGroup, idx: number) {
    const entries = group.entries.map((entry, i) => i === idx ? { ...entry, enabled: entry.enabled === false } : entry)
    saveGroupSnapshot({ ...group, entries })
  }

  function removeGroupEntry(group: ServiceGroup, idx: number) {
    const entries = group.entries.filter((_, i) => i !== idx)
    saveGroupSnapshot({ ...group, entries })
  }

  function addInlineEntry(group: ServiceGroup) {
    const gid = group.id ?? group.name
    const raw = (inlineEntryInputs[gid] ?? '').trim()
    if (!raw) return
    const parsed = detectEntryKind(raw)
    if (group.entries.some(e => e.kind === parsed.kind && e.pattern.toLowerCase() === parsed.pattern.toLowerCase())) {
      error = 'Такая запись уже есть в группе'
      return
    }
    const entries = [...group.entries, { kind: parsed.kind, pattern: parsed.pattern, enabled: true }]
    inlineEntryInputs = { ...inlineEntryInputs, [gid]: '' }
    saveGroupSnapshot({ ...group, entries }, `Добавлено в «${group.name}»: ${parsed.pattern}`)
  }

  function selectUser(id: string) {
    userId = id
    selected = data?.routes.filter(route => route.userId === id).map(route => route.proxyId) ?? []
  }

  function move(index: number, offset: number) {
    const clone = [...selected]
    const other = index + offset
    if (other < 0 || other >= clone.length) return
    const current = clone[index]
    clone[index] = clone[other]
    clone[other] = current
    selected = clone
  }

  function save(event: SubmitEvent) {
    event.preventDefault()
    const fields = new FormData(event.currentTarget as HTMLFormElement)
    const field = (key: string) => String(fields.get(key) ?? '')
    void task(async () => {
      if (dialog === 'invite') {
        const mult = inviteDurationUnit === 'd' ? 1440 : inviteDurationUnit === 'h' ? 60 : 1
        const durationMinutes = Math.max(1, Math.min(525600, Math.round((Number(inviteDurationVal) || 24) * mult)))
        const item = await admin<{ link: string; subUrl?: string }>(token, 'invites', 'POST', {
          userId: '',
          label: label.trim() || 'Устройство',
          universal: true,
          linkType: inviteLinkType,
          durationMinutes: inviteLinkType === 'temp' ? durationMinutes : 0,
          canEditGlobal: inviteCanEditGlobal
        })
        link = item.link
        subLink = item.subUrl ?? ''
        iosDeepLink = ''
        if (navigator.clipboard?.writeText) {
          await navigator.clipboard.writeText(item.link).catch(() => {})
        }
      } else {
        if (dialog === 'proxy') await admin(token, 'proxies', 'PUT', {
          id: editingProxy?.id ?? '', name: field('name'), host: field('host'), port: Number(field('port')),
          tls: fields.has('tls'), username: field('username'), password: field('password'),
          headers: parseHeaders(proxyHeadersText)
        })
        if (dialog === 'user') {
          await admin(token, editingUser ? 'users/' + editingUser.id : 'users',
            editingUser ? 'PUT' : 'POST', { name: field('name') })
        }
        if (dialog === 'routes') await admin(token, 'routes', 'PUT', { userId, proxyIds: selected })
        if (dialog === 'rule') await admin(token, 'rules', 'PUT', {
          userId, pattern: field('pattern'), kind: field('kind'), action: field('action') as Action,
          enabled: fields.has('enabled'), locked: fields.has('locked'), revision: editingRule?.revision ?? 0
        })
        if (dialog === 'group') {
          const saved = await admin<ServiceGroup>(token, 'groups', 'PUT', {
            id: editingGroup?.id ?? '', name: groupName, userId, action: groupAction,
            enabled: groupEnabled, locked: groupLocked, revision: editingGroup?.revision ?? 0,
            entries: groupEntries
          })
          expandedGroupId = saved.id ?? expandedGroupId
        }
        modal?.close()
      }
      await load()
      message = dialog === 'invite'
        ? (inviteLinkType === 'permanent' ? 'Бессрочная ссылка создана и скопирована' : 'Временная ссылка создана и скопирована')
        : 'Изменения сохранены'
    })
  }

  function remove(path: string, question: string) {
    if (!window.confirm(question)) return
    void task(async () => { await admin(token, path, 'DELETE'); await load(); message = 'Изменения сохранены' })
  }

  function probe(proxy: Proxy) {
    void task(async () => {
      const result = await admin<{ reachable: boolean }>(token, 'probes/' + proxy.id, 'POST')
      if (!result.reachable) throw new Error('Контрольный запрос через ' + proxy.name + ' не прошёл')
      message = 'Прокси ' + proxy.name + ' доступен'
    })
  }

  function backup() {
    void task(async () => {
      const result = await admin<{ file: string }>(token, 'backups', 'POST')
      message = 'Сохранена копия ' + result.file
    })
  }

  onMount(() => {
    try {
      const stored = sessionStorage.getItem(TOKEN_KEY)
      if (stored) {
        token = stored
        void load().catch(() => {
          token = ''
          connected = false
          try { sessionStorage.removeItem(TOKEN_KEY) } catch { /* ignore */ }
        })
      }
    } catch { /* ignore */ }
  })
</script>

{#if !connected}
  <main class="login">
    <form class="hp-card stack" onsubmit={signIn}>
      <Brand caption="Панель управления" title="HomeProxy Server" size={32} />
      <div class="card-head">
        <h1>Вход администратора</h1>
        <p class="muted">Единственный администратор сервера · укажите ключ доступа.</p>
      </div>
      <label>Ключ доступа
        <input type="password" bind:value={keyInput} placeholder="Вставьте ключ" required autocomplete="off" />
      </label>
      {#if error}<p class="notice error" role="alert">{error}</p>{/if}
      <button class="primary" disabled={busy}>
        {busy ? 'Подключение…' : 'Войти'}
        <ArrowRight size={15} />
      </button>
    </form>
  </main>
{:else if data}
  <div class="shell">
    <aside>
      <div class="aside-brand">
        <Brand title="HomeProxy Server" size={24} />
      </div>
      <nav aria-label="Разделы">
        {#each views as item}
          <button
            class:current={item.id === view}
            aria-current={item.id === view ? 'page' : undefined}
            onclick={() => navigate(item.id)}
          >
            <item.icon size={15} />{item.label}
          </button>
        {/each}
      </nav>
      <button class="ghost exit" onclick={signOut}><LogOut size={15} /> Выход</button>
    </aside>

    <div class="workspace">
      <header class="between">
        <div class="flex">
          <Shield size={15} />
          <span>Администратор сервера</span>
        </div>
        <div class="flex">
          {#if systemHealth}
            <span class="signal-bars online">
              <span class="signal-bars-graph"><span></span><span></span><span></span></span>
              <span>Сервер онлайн</span>
            </span>
          {:else}
            <span class="signal-bars offline">
              <span class="signal-dot"></span>
              <span>Проверьте сервер</span>
            </span>
          {/if}
          <button class="small ghost" aria-label="Обновить данные" title="Обновить данные" onclick={() => task(load)} disabled={busy}>
            <RefreshCw size={14} />
          </button>
        </div>
      </header>

      <main class="content stack">
        <div class="between page-title">
          <h1>{title}</h1>
          <button class="primary small" disabled={busy} onclick={() => open('invite')}>
            <Plus size={14} /> Создать ссылку
          </button>
        </div>

        {#if error && !modal?.open}<p class="notice error" role="alert">{error}</p>{/if}
        {#if message && !modal?.open}<p class="notice success" role="status">{message}</p>{/if}

        {#if view === 'overview'}
          <div class="metrics">
            <div class="hp-card metric">
              <strong>{onlineCount} / {activeDevices.length}</strong>
              <small>Устройства онлайн</small>
            </div>
            <div class="hp-card metric">
              <strong>{data.proxies.length}</strong>
              <small>Прокси-узлы</small>
            </div>
            <div class="hp-card metric">
              <strong class="mono">v{data.revision}</strong>
              <small>Конфигурация</small>
            </div>
          </div>

          <section class="hp-card flush">
            <div class="card-bar between">
              <div class="hp-segmented sub-switch">
                <button type="button" class:active-soft={overviewSub === 'active'} onclick={() => overviewSub = 'active'}>
                  Активные устройства ({activeDevices.length})
                </button>
                <button type="button" class:active-soft={overviewSub === 'history'} onclick={() => overviewSub = 'history'}>
                  История ({historyDevices.length})
                </button>
              </div>
              {#if overviewSub === 'history' && historyDevices.length}
                <button type="button" class="small ghost danger" disabled={busy} onclick={clearHistory}>
                  <Trash2 size={13} /> Очистить
                </button>
              {/if}
            </div>

            {#if overviewSub === 'active'}
              {#if !activeDevices.length}
                <p class="empty pad">Нет активных устройств. Нажмите «+ Создать ссылку».</p>
              {:else}
                <div class="list-divide">
                  {#each activeDevices as device (device.id)}
                    <div class="device-row between">
                      <div class="card-head">
                        <div class="flex">
                          <strong class="device-name">{device.label}</strong>
                          <span class="link-badge" class:perm={device.linkType === 'permanent' || device.expires === 0}>
                            {formatLinkBadge(device)}
                          </span>
                        </div>
                        <small class="muted">
                          {username(device.userId)} · {platformLabel(device)}
                          {#if device.ackRevision} · v{device.ackRevision}{/if}
                        </small>
                      </div>
                      <div class="flex">
                        {#if device.online}
                          <span class="signal-bars online">
                            <span class="signal-bars-graph"><span></span><span></span><span></span></span>
                            <span class="mono">{device.activeConnections ? `${device.activeConnections} соед.` : 'Онлайн'}</span>
                          </span>
                        {:else}
                          <span class="signal-bars offline">
                            <span class="signal-dot"></span>
                            <span>{device.status === 'invited' ? 'Ожидает' : 'Офлайн'}</span>
                          </span>
                        {/if}
                        <button
                          type="button"
                          class="hp-toggle"
                          role="switch"
                          aria-checked={device.accessEnabled !== false}
                          aria-label={`Доступ для ${device.label}`}
                          disabled={busy}
                          onclick={() => toggleDeviceAccess(device)}
                        >
                          <span class="hp-toggle-thumb"></span>
                        </button>
                        <button
                          type="button"
                          class="small"
                          title="Для iOS (sing-box)"
                          aria-label={`Для iOS (sing-box) · ${device.label}`}
                          disabled={busy}
                          onclick={() => showIosSubscription(device)}
                        >
                          <QrCode size={13} /> Для iOS (sing-box)
                        </button>
                        <button
                          type="button"
                          class="small ghost danger"
                          title="Закрыть ссылку"
                          aria-label={`Закрыть ссылку ${device.label}`}
                          disabled={busy}
                          onclick={() => remove('devices/' + device.id, 'Закрыть ссылку и перенести устройство в историю?')}
                        >
                          <X size={15} />
                        </button>
                      </div>
                    </div>
                  {/each}
                </div>
              {/if}
            {:else if !historyDevices.length}
              <p class="empty pad">История пуста</p>
            {:else}
              <div class="list-divide">
                {#each historyDevices as item (item.id)}
                  <div class="device-row between">
                    <div class="flex">
                      <span class="history-name">{item.label}</span>
                      <small class="muted">{username(item.userId)} · {platformLabel(item)}</small>
                    </div>
                    <small class="muted">
                      {item.closedReason || (item.expired ? 'Срок истёк' : 'Ссылка закрыта')} · {stamp(item.closedAt || item.accessExpires || item.seen)}
                    </small>
                  </div>
                {/each}
              </div>
            {/if}
          </section>

        {:else if view === 'network'}
          <div class="between">
            <div class="hp-segmented sub-switch">
              <button type="button" class:active-soft={netSub === 'resources'} onclick={() => netSub = 'resources'}>
                Общие ресурсы
              </button>
              <button type="button" class:active-soft={netSub === 'proxies'} onclick={() => netSub = 'proxies'}>
                Прокси-узлы
              </button>
            </div>
            {#if netSub === 'resources'}
              <div class="flex">
                <input class="search" aria-label="Поиск ресурсов" placeholder="Поиск ресурсов" bind:value={search} />
                <button type="button" class="primary small" onclick={() => open('group')}>
                  <Plus size={14} /> Добавить ресурс
                </button>
              </div>
            {:else}
              <div class="flex">
                <button type="button" class="small" disabled={!data.users.length} onclick={() => open('routes')}>Очередь прокси</button>
                <button type="button" class="primary small" onclick={() => open('proxy')}>
                  <Plus size={14} /> Добавить прокси
                </button>
              </div>
            {/if}
          </div>

          {#if netSub === 'resources'}
            <section class="hp-card flush">
              <div class="card-bar between">
                <div class="flex">
                  <Globe size={15} />
                  <span class="section-title">Общие ресурсы</span>
                </div>
                <small class="muted">Редактирование с сервера · Все устройства</small>
              </div>
              {#if !data.groups.length}
                <p class="empty pad">Нет общих ресурсов. Создайте ресурс, например ChatGPT или Рабочие ресурсы.</p>
              {:else}
                <div class="list-divide">
                  {#each data.groups.filter(g => matches(g.name, username(g.userId), ...g.entries.map(e => e.pattern))) as group (group.id)}
                    {@const gid = group.id ?? group.name}
                    {@const expanded = expandedGroupId === gid}
                    {@const activeEntries = group.entries.filter(e => e.enabled !== false).length}
                    <div>
                      <div class="res-header between">
                        <button type="button" class="res-trigger" onclick={() => expandedGroupId = expanded ? null : gid}>
                          {#if expanded}<ChevronDown size={14} />{:else}<ChevronRight size={14} />{/if}
                          <span class="res-icon"><Layers size={14} /></span>
                          <span class="card-head">
                            <span class="flex">
                              <strong>{group.name}</strong>
                              <span class="mono count-tag">{activeEntries}/{group.entries.length}</span>
                              {#if group.userId}<span class="scope-tag">{username(group.userId)}</span>{/if}
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
                          onclick={() => toggleGroup(group)}
                        >
                          <span class="hp-toggle-thumb"></span>
                        </button>
                      </div>

                      {#if expanded}
                        <div class="res-body stack">
                          <div class="between">
                            <div class="flex route-btns">
                              {#each [{ id: 'PROXY', label: 'Прокси' }, { id: 'LOCAL_DIRECT', label: 'Прямой' }, { id: 'BLOCK', label: 'Блок' }] as rt}
                                <button
                                  type="button"
                                  class="small route-choice"
                                  class:selected={group.action === rt.id}
                                  disabled={busy}
                                  onclick={() => setGroupRoute(group, rt.id as Action)}
                                >
                                  {rt.label}
                                </button>
                              {/each}
                            </div>
                            <div class="flex">
                              <button type="button" class="small ghost" onclick={() => open('group', group)}>Изменить</button>
                              <button type="button" class="small ghost danger" onclick={() => remove('groups/' + group.id, 'Удалить ресурс?')}>Удалить</button>
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
                                      onclick={() => toggleGroupEntry(group, idx)}
                                    >
                                      {enabled ? 'Вкл' : 'Выкл'}
                                    </button>
                                    <button
                                      type="button"
                                      class="icon-x"
                                      aria-label={`Удалить ${entry.pattern}`}
                                      disabled={busy}
                                      onclick={() => removeGroupEntry(group, idx)}
                                    >
                                      <X size={13} />
                                    </button>
                                  </div>
                                </div>
                              {/each}
                            </div>
                          {/if}

                          <div class="inline-add">
                            <input
                              type="text"
                              class="mono"
                              placeholder="Добавить домен, IP или .exe в группу…"
                              value={inlineEntryInputs[gid] ?? ''}
                              oninput={e => inlineEntryInputs = { ...inlineEntryInputs, [gid]: e.currentTarget.value }}
                              onkeydown={e => { if (e.key === 'Enter') { e.preventDefault(); addInlineEntry(group) } }}
                            />
                            <button type="button" class="small" disabled={busy} onclick={() => addInlineEntry(group)}>+</button>
                          </div>
                        </div>
                      {/if}
                    </div>
                  {/each}
                </div>
              {/if}
            </section>

            <section class="hp-card stack">
              <div class="between">
                <div class="flex">
                  <HardDrive size={15} />
                  <h2>Точечные правила ({data.rules.length})</h2>
                </div>
                <button type="button" class="small" onclick={() => open('rule')}>
                  <Plus size={14} /> Добавить правило
                </button>
              </div>
              {#if !data.rules.length}
                <p class="empty">Точечных правил пока нет.</p>
              {:else}
                <div class="table-scroll">
                  <table>
                    <thead><tr><th>Шаблон</th><th>Область</th><th>Маршрут</th><th>Статус</th><th>Действия</th></tr></thead>
                    <tbody>
                      {#each data.rules.filter(r => matches(r.pattern, username(r.userId))) as rule (rule.id)}
                        <tr>
                          <td data-label="Шаблон" class="mono">{rule.pattern}</td>
                          <td data-label="Область">{scopeOf(rule)}{rule.userId ? ' · ' + username(rule.userId) : ''}</td>
                          <td data-label="Маршрут">{actionNames[rule.action]}</td>
                          <td data-label="Статус">
                            <button type="button" class="small" disabled={busy} onclick={() => toggleRule(rule)}>
                              {rule.enabled !== false ? 'Вкл' : 'Выкл'}
                            </button>
                          </td>
                          <td>
                            <div class="flex">
                              <button type="button" class="small" onclick={() => open('rule', rule)}>Изменить</button>
                              <button type="button" class="small danger" onclick={() => remove('rules/' + rule.id, 'Удалить правило?')}>Удалить</button>
                            </div>
                          </td>
                        </tr>
                      {/each}
                    </tbody>
                  </table>
                </div>
              {/if}
            </section>
          {:else}
            {#if !data.proxies.length}
              <div class="hp-card"><p class="empty">Добавьте прокси-узел и назначьте его профилю.</p></div>
            {:else}
              <div class="proxy-grid">
                {#each data.proxies.filter(p => matches(p.name, p.host)) as proxy (proxy.id)}
                  <div class="hp-card stack proxy-card">
                    <div class="between">
                      <div class="card-head">
                        <h2>{proxy.name}</h2>
                        <small class="mono muted">
                          {proxy.tls ? 'HTTPS CONNECT' : 'HTTP CONNECT'} · {proxy.host}:{proxy.port}
                          {#if proxy.headers && Object.keys(proxy.headers).length} · +{Object.keys(proxy.headers).length} заг.{/if}
                        </small>
                      </div>
                      <Router size={16} />
                    </div>
                    <div class="flex">
                      <button type="button" class="small" disabled={busy} onclick={() => probe(proxy)}>Проверить</button>
                      <button type="button" class="small" onclick={() => open('proxy', proxy)}>Изменить</button>
                      <button type="button" class="small danger" onclick={() => remove('proxies/' + proxy.id, 'Удалить прокси?')}>Удалить</button>
                    </div>
                  </div>
                {/each}
              </div>
            {/if}
          {/if}

        {:else if view === 'access'}
          <div class="hp-card between">
            <div class="card-head">
              <h2>Админ-панель без пароля пользователей</h2>
              <small class="muted">Единственный администратор сервера · универсальные ссылки выдаются клиентам</small>
            </div>
            <span class="badge ok">Активно</span>
          </div>

          <section class="hp-card flush">
            <div class="card-bar between">
              <span class="section-title">Профили и права на общие ресурсы</span>
              <button type="button" class="small" onclick={() => open('user')}>
                <Plus size={14} /> Добавить профиль
              </button>
            </div>
            {#if !data.users.length}
              <p class="empty pad">Профилей пока нет.</p>
            {:else}
              <div class="list-divide">
                {#each data.users as user (user.id)}
                  <div class="device-row between">
                    <div class="card-head">
                      <strong>{user.name}</strong>
                      <small class="muted">
                        Разрешить изменять общие ресурсы
                        {#if data.routes.some(r => r.userId === user.id)}
                          · Прокси: {data.routes.filter(r => r.userId === user.id).map(r => data?.proxies.find(p => p.id === r.proxyId)?.name).filter(Boolean).join(', ')}
                        {/if}
                      </small>
                    </div>
                    <div class="flex">
                      <button
                        type="button"
                        class="hp-toggle"
                        role="switch"
                        aria-checked={Boolean(user.canEditGlobal)}
                        aria-label={`Права на общие ресурсы для ${user.name}`}
                        disabled={busy}
                        onclick={() => toggleUserPerm(user)}
                      >
                        <span class="hp-toggle-thumb"></span>
                      </button>
                      <button type="button" class="small" onclick={() => open('user', user)}>Имя</button>
                      <button type="button" class="small" onclick={() => { open('routes'); selectUser(user.id) }}>Прокси</button>
                      <button type="button" class="small danger" onclick={() => remove('users/' + user.id, 'Удалить профиль и все его устройства?')}>Удалить</button>
                    </div>
                  </div>
                {/each}
              </div>
            {/if}
          </section>

        {:else if view === 'settings'}
          <section class="hp-card flush">
            <div class="list-divide">
              <div class="device-row between">
                <div class="card-head">
                  <strong>HomeProxy Server</strong>
                  <small class="muted mono">
                    {#if serverRelease?.version}v{serverRelease.version} · API {serverRelease.api} · SQLite v{serverRelease.dbSchema}{:else}Версия недоступна{/if}
                  </small>
                </div>
                <a class="small-link" href="https://github.com/C0dece/HomeProxy/releases/latest" target="_blank" rel="noopener noreferrer">GitHub Releases</a>
              </div>

              <div class="device-row between">
                <div class="card-head">
                  <span>Автообновления сервера</span>
                  {#await updatePolicy}
                    <small class="muted">Загрузка…</small>
                  {:then policy}
                    {#if policy && !policy.managed}
                      <small class="muted">Отключено в конфигурации сервера</small>
                    {/if}
                  {/await}
                </div>
                {#await updatePolicy then policy}
                  {#if policy?.managed}
                    <div class="flex">
                      <span class="badge" class:wait={policy.paused} class:ok={!policy.paused}>{policy.paused ? 'На паузе' : 'Разрешены'}</span>
                      <button type="button" class="small" disabled={busy} onclick={() => setUpdatesPaused(!policy.paused)}>
                        {policy.paused ? 'Возобновить' : 'Приостановить'}
                      </button>
                    </div>
                  {/if}
                {/await}
              </div>

              <div class="device-row between">
                <span>Автообновления клиентов (Windows / Android)</span>
                {#await clientUpdatePolicy}
                  <small class="muted">Загрузка…</small>
                {:then policy}
                  {#if policy}
                    <div class="flex">
                      <span class="badge" class:wait={policy.paused} class:ok={!policy.paused}>{policy.paused ? 'На паузе' : 'Разрешены'}</span>
                      <button type="button" class="small" disabled={busy} onclick={() => setClientUpdatesPaused(!policy.paused)}>
                        {policy.paused ? 'Возобновить у клиентов' : 'Приостановить у клиентов'}
                      </button>
                    </div>
                  {/if}
                {/await}
              </div>
            </div>
          </section>

          <section class="hp-card stack">
            <h2>Версии клиентских устройств</h2>
            {#if !data.devices.length}
              <p class="empty">Устройств пока нет.</p>
            {:else}
              <div class="table-scroll">
                <table>
                  <thead><tr><th>Устройство</th><th>Платформа</th><th>Версия</th><th>Отчёт</th></tr></thead>
                  <tbody>
                    {#each data.devices as device (device.id)}
                      <tr>
                        <td data-label="Устройство">{device.label}{#if device.status === 'revoked'} <span class="badge bad">Закрыта</span>{/if}</td>
                        <td data-label="Платформа">{platformLabel(device)}</td>
                        <td data-label="Версия" class="mono">{device.installedVersion || 'Нет данных'}</td>
                        <td data-label="Отчёт">{stamp(device.reportedAt ?? 0)}</td>
                      </tr>
                    {/each}
                  </tbody>
                </table>
              </div>
            {/if}
          </section>

          <section class="hp-card stack">
            <h2>История обновлений сервера</h2>
            {#await updateHistory}
              <p class="muted" role="status">Загрузка истории…</p>
            {:then entries}
              {#if !entries}
                <p class="notice error" role="alert">История обновлений недоступна.</p>
              {:else if !entries.length}
                <p class="empty">Пока нет записей об обновлениях.</p>
              {:else}
                <div class="table-scroll">
                  <table>
                    <thead><tr><th>Время завершения</th><th>Результат</th><th>Подробности</th></tr></thead>
                    <tbody>
                      {#each entries as entry}
                        <tr>
                          <td data-label="Время">{stamp(entry.finishedAt)}</td>
                          <td data-label="Результат">
                            <span class="badge update-outcome" class:ok={entry.outcome === 'installed'} class:bad={entry.outcome === 'failed'}>
                              {updateOutcomes[entry.outcome]}
                            </span>
                          </td>
                          <td data-label="Подробности">
                            {#if entry.version}Версия {entry.version}
                            {:else if entry.outcome === 'failed'}{updatePhases[entry.phase]}{#if entry.exitCode !== undefined}, код {entry.exitCode}{/if}
                            {:else}Стабильный канал{/if}
                          </td>
                        </tr>
                      {/each}
                    </tbody>
                  </table>
                </div>
              {/if}
            {/await}
          </section>

          <section class="hp-card stack">
            <div class="between">
              <h2>Журнал событий и резервные копии</h2>
              <button type="button" class="small" disabled={busy} onclick={backup}>
                <DatabaseBackup size={14} /> Создать копию SQLite
              </button>
            </div>
            {#if !data.audit.length}
              <p class="empty">В журнале пока нет событий.</p>
            {:else}
              <div class="table-scroll">
                <table>
                  <thead><tr><th>Версия</th><th>Событие</th><th>Время</th></tr></thead>
                  <tbody>
                    {#each data.audit.slice(0, 20) as entry (entry.revision)}
                      <tr>
                        <td data-label="Версия" class="mono">v{entry.revision}</td>
                        <td data-label="Событие">{eventNames[entry.event] ?? entry.event}</td>
                        <td data-label="Время">{stamp(entry.time)}</td>
                      </tr>
                    {/each}
                  </tbody>
                </table>
              </div>
            {/if}
          </section>
        {/if}
      </main>
    </div>
  </div>
{/if}

{#if connected && data}
  <dialog bind:this={modal} onclick={e => { if (e.target === modal) modal?.close() }} onclose={() => { error = ''; link = ''; subLink = ''; iosDeepLink = ''; iosDeviceLabel = '' }}>
    <div class="stack">
      <div class="between">
        <h2>{dialog === 'user' ? (editingUser ? 'Изменить имя' : 'Добавить профиль') : dialogNames[dialog]}</h2>
        <button type="button" class="small ghost" aria-label="Закрыть" onclick={() => modal?.close()}><X size={16} /></button>
      </div>
      {#if error}<p class="notice error" role="alert">{error}</p>{/if}
      {#if dialog === 'ios' && iosDeepLink}
        <div class="stack">
          {#if iosDeviceLabel}<small class="muted">Устройство: <strong>{iosDeviceLabel}</strong></small>{/if}
          <div class="qr-panel">
            <div class="qr-svg">{@html qrToSvg(iosDeepLink)}</div>
            <small class="qr-hint">Отсканируйте камерой iPhone — профиль импортируется в <strong>sing-box MT</strong> в один тап.</small>
          </div>
          <div class="link-box mono">{iosDeepLink}</div>
          <button type="button" class="primary" onclick={() => task(async () => { await navigator.clipboard.writeText(iosDeepLink); message = 'Ссылка для sing-box MT скопирована' })}>
            <Copy size={14} /> Скопировать ссылку для sing-box
          </button>
          {#if message}<p role="status" class="success">{message}</p>{/if}
        </div>
      {:else if link}
        <div class="stack">
          <div class="link-box mono">{link}</div>
          <div class="flex">
            <button type="button" class="primary" onclick={() => task(async () => { await navigator.clipboard.writeText(link); message = 'Ссылка скопирована' })}>
              <Copy size={14} /> Скопировать ссылку
            </button>
            {#if subLink}
              <button type="button" onclick={() => void activateModalIosQr()}>
                <QrCode size={14} /> Для iOS (sing-box)
              </button>
            {/if}
          </div>
          {#if iosDeepLink}
            <div class="qr-panel">
              <div class="qr-svg">{@html qrToSvg(iosDeepLink)}</div>
              <small class="qr-hint">Отсканируйте камерой iPhone — профиль импортируется в <strong>sing-box MT</strong> в один тап.</small>
            </div>
            <div class="link-box mono">{iosDeepLink}</div>
          {/if}
          {#if message}<p role="status" class="success">{message}</p>{/if}
        </div>
      {:else}
        <form class="stack" onsubmit={save}>
          {#if dialog === 'invite'}
            <input required bind:value={label} maxlength="100" placeholder="Для кого (например, Мария, Планшет, Гость)" />
            <div class="hp-segmented two-cols">
              <button type="button" class:active={inviteLinkType === 'permanent'} onclick={() => inviteLinkType = 'permanent'}>Бессрочная</button>
              <button type="button" class:active={inviteLinkType === 'temp'} onclick={() => inviteLinkType = 'temp'}>Временная</button>
            </div>
            {#if inviteLinkType === 'temp'}
              <div class="field-row">
                <input type="number" min="1" max="365" bind:value={inviteDurationVal} class="mono" />
                <select bind:value={inviteDurationUnit}>
                  <option value="h">часов</option>
                  <option value="d">дней</option>
                  <option value="m">минут</option>
                </select>
              </div>
            {/if}
            <div class="between perm-row">
              <span>Разрешить изменять общие ресурсы</span>
              <button
                type="button"
                class="hp-toggle"
                role="switch"
                aria-checked={inviteCanEditGlobal}
                aria-label="Разрешить изменять общие ресурсы"
                onclick={() => inviteCanEditGlobal = !inviteCanEditGlobal}
              >
                <span class="hp-toggle-thumb"></span>
              </button>
            </div>
            <div class="flex modal-actions">
              <button type="button" class="ghost" onclick={() => modal?.close()}>Отмена</button>
              <button class="primary" disabled={busy}>{busy ? 'Создание…' : 'Создать и скопировать'}</button>
            </div>

          {:else if dialog === 'user'}
            <label>Имя<input required maxlength="100" name="name" value={editingUser?.name ?? ''} /></label>
            <button class="primary" disabled={busy}>Сохранить</button>

          {:else if dialog === 'routes'}
            <label>Профиль
              <select value={userId} onchange={e => selectUser(e.currentTarget.value)} required>
                {#each data.users as user}<option value={user.id}>{user.name}</option>{/each}
              </select>
            </label>
            {#each selected as id, index (id)}
              <div class="between">
                <span class="mono">{index + 1}. {data.proxies.find(proxy => proxy.id === id)?.name}</span>
                <div class="flex">
                  <button class="small" type="button" aria-label="Повысить приоритет" onclick={() => move(index, -1)} disabled={index === 0}>↑</button>
                  <button class="small" type="button" aria-label="Понизить приоритет" onclick={() => move(index, 1)} disabled={index === selected.length - 1}>↓</button>
                  <button class="small" type="button" onclick={() => selected = selected.filter(item => item !== id)}>Убрать</button>
                </div>
              </div>
            {/each}
            <label>Прокси
              <select bind:value={candidate}>
                <option value="">Выберите прокси</option>
                {#each data.proxies.filter(p => !selected.includes(p.id)) as proxy}<option value={proxy.id}>{proxy.name}</option>{/each}
              </select>
            </label>
            <button type="button" disabled={!candidate} onclick={() => { selected = [...selected, candidate]; candidate = '' }}>Добавить в очередь</button>
            <button class="primary" disabled={busy}>Сохранить</button>

          {:else if dialog === 'proxy'}
            <label>Имя<input name="name" value={editingProxy?.name ?? ''} required maxlength="100" /></label>
            <div class="field-row">
              <label>Адрес<input name="host" value={editingProxy?.host ?? ''} required /></label>
              <label>Порт<input name="port" type="number" min="1" max="65535" value={editingProxy?.port ?? 8080} required /></label>
            </div>
            <div class="field-row">
              <label>Логин<input name="username" autocomplete="off" /></label>
              <label>Пароль<input name="password" type="password" autocomplete="new-password" /></label>
            </div>
            <label>HTTP-заголовки (по строке <code>Имя: Значение</code>)
              <textarea name="headers" rows="3" bind:value={proxyHeadersText} placeholder="X-Custom-Auth: token"></textarea>
            </label>
            {#if editingProxy}<small class="muted">Введите действующие учётные данные для проверки новой конфигурации.</small>{/if}
            <label class="check"><input name="tls" type="checkbox" checked={Boolean(editingProxy?.tls)} /> TLS к прокси</label>
            <button class="primary" disabled={busy}>Сохранить</button>

          {:else if dialog === 'group'}
            <label>Название<input required maxlength="100" bind:value={groupName} placeholder="Например, ChatGPT" /></label>
            <div class="field-row">
              <label>Область
                <select bind:value={userId}>
                  <option value="">Общие ресурсы (все)</option>
                  {#each data.users as user}<option value={user.id}>Профиль · {user.name}</option>{/each}
                </select>
              </label>
              <label>Маршрут
                <select bind:value={groupAction}>
                  {#each Object.entries(actionNames) as [act, name]}<option value={act}>{name}</option>{/each}
                </select>
              </label>
            </div>
            <div class="field-row">
              <label class="check"><input type="checkbox" bind:checked={groupEnabled} /> Ресурс включён</label>
              <label class="check"><input type="checkbox" bind:checked={groupLocked} /> Приоритет над локальными</label>
            </div>
            <div class="stack entries-box">
              <span class="label">Адреса и приложения ({groupEntries.length})</span>
              <div class="entry-add">
                <select bind:value={newEntryKind}>
                  {#each Object.entries(entryKindNames) as [k, lbl]}<option value={k}>{lbl}</option>{/each}
                </select>
                <input
                  bind:value={newEntryPattern}
                  class="mono"
                  placeholder={newEntryKind === 'ip_cidr' ? '1.2.3.0/24' : newEntryKind === 'process' ? 'app.exe' : newEntryKind === 'package' ? 'com.example.app' : 'example.com'}
                  onkeydown={e => { if (e.key === 'Enter') { e.preventDefault(); addGroupEntry() } }}
                />
                <button type="button" class="small" onclick={addGroupEntry}>+</button>
              </div>
              {#if groupEntries.length}
                <div class="entries-list">
                  {#each groupEntries as entry, i (entry.kind + ':' + entry.pattern)}
                    <div class="between entry-row">
                      <span><span class="type-chip mono">{entryBadge(entry.kind)}</span> <code class="mono">{entry.pattern}</code></span>
                      <button type="button" class="small ghost" aria-label="Удалить элемент" onclick={() => groupEntries = groupEntries.filter((_, idx) => idx !== i)}><X size={13} /></button>
                    </div>
                  {/each}
                </div>
              {/if}
            </div>
            <button class="primary" disabled={busy}>Сохранить</button>

          {:else}
            <label>Область
              <select bind:value={userId} disabled={Boolean(editingRule)}>
                <option value="">GLOBAL</option>
                {#each data.users as user}<option value={user.id}>PERSONAL · {user.name}</option>{/each}
              </select>
            </label>
            <div class="field-row">
              <label>Тип
                <select name="kind" bind:value={ruleKind} disabled={Boolean(editingRule)}>
                  <option value="domain">Домен</option>
                  <option value="suffix">Домен и поддомены</option>
                  <option value="process">Приложение Windows</option>
                  <option value="package">Приложение Android</option>
                </select>
                {#if editingRule}<input type="hidden" name="kind" value={editingRule.kind} />{/if}
              </label>
              <label>Шаблон
                <input
                  name="pattern"
                  value={editingRule?.pattern ?? ''}
                  readonly={Boolean(editingRule)}
                  placeholder={ruleKind === 'package' ? 'com.example.app' : ruleKind === 'process' ? 'Имя или путь .exe' : 'example.com'}
                  required
                />
              </label>
            </div>
            <label>Маршрут
              <select name="action" value={editingRule?.action ?? 'PROXY'}>
                {#each Object.entries(actionNames) as [act, name]}<option value={act}>{name}</option>{/each}
              </select>
            </label>
            <label class="check"><input name="enabled" type="checkbox" checked={editingRule?.enabled !== false} /> Правило включено</label>
            {#if ruleKind === 'domain' || ruleKind === 'suffix'}
              <label class="check"><input name="locked" type="checkbox" checked={Boolean(editingRule?.locked)} /> Приоритет над локальными правилами</label>
            {/if}
            <button class="primary" disabled={busy}>Сохранить</button>
          {/if}
        </form>
      {/if}
    </div>
  </dialog>
{/if}

<style>
  .login { min-height: 100vh; display: grid; place-items: center; padding: 24px; }
  .login form { width: min(100%, 400px); gap: 18px; }
  .shell { min-height: 100vh; display: grid; grid-template-columns: 230px minmax(0, 1fr); background: var(--hp-bg); }
  aside {
    padding: 16px 12px;
    border-right: 1px solid var(--hp-border);
    background: #09090B;
    display: flex;
    flex-direction: column;
    gap: 16px;
  }
  .aside-brand { padding: 6px 8px; }
  nav { display: grid; gap: 4px; }
  nav button, .exit {
    justify-content: flex-start;
    background: transparent;
    border-color: transparent;
    color: #A1A1AA;
    width: 100%;
    font-size: .82rem;
    font-weight: 500;
    border-radius: 12px;
    padding: 9px 12px;
  }
  nav button:hover, .exit:hover { color: #FFFFFF; background: rgba(255, 255, 255, 0.04); border-color: transparent; }
  nav button.current { background: rgba(255, 255, 255, 0.1); color: #FFFFFF; border-color: transparent; }
  .exit { margin-top: auto; }
  .workspace { min-width: 0; background: #0E0E11; }
  header {
    min-height: 54px;
    padding: 10px clamp(16px, 3vw, 28px);
    border-bottom: 1px solid var(--hp-border);
    color: #A1A1AA;
    font-size: .8rem;
    background: #09090B;
  }
  .content { max-width: 1120px; margin: auto; padding: 22px clamp(16px, 3vw, 28px); gap: 16px; }
  .metrics { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px; }
  .metric { display: grid; gap: 4px; padding: 16px; }
  .metric strong { font-size: 1.55rem; font-weight: 700; color: #FFFFFF; line-height: 1.15; }
  .metric small { color: #A1A1AA; font-size: .76rem; }

  .hp-card.flush { padding: 0; overflow: hidden; }
  .card-bar { padding: 11px 16px; border-bottom: 1px solid rgba(255, 255, 255, 0.06); background: rgba(255, 255, 255, 0.02); }
  .section-title { font-size: .8rem; font-weight: 600; color: #E4E4E7; }
  .sub-switch { display: inline-grid; grid-auto-flow: column; grid-auto-columns: max-content; }
  .list-divide > div { border-bottom: 1px solid rgba(255, 255, 255, 0.06); }
  .list-divide > div:last-child { border-bottom: 0; }
  .pad { padding: 16px; }

  .device-row { padding: 12px 16px; font-size: .8rem; }
  .device-name { color: #FFFFFF; font-weight: 500; }
  .history-name { color: #D4D4D8; font-weight: 500; }
  .link-badge {
    font-size: .65rem;
    padding: 2px 7px;
    border-radius: 6px;
    border: 1px solid rgba(245, 158, 11, 0.25);
    background: rgba(245, 158, 11, 0.1);
    color: #FCD34D;
  }
  .link-badge.perm {
    border-color: rgba(255, 255, 255, 0.15);
    background: rgba(255, 255, 255, 0.06);
    color: #E4E4E7;
  }

  .res-header { padding: 11px 16px; transition: background-color 0.15s; }
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
  .scope-tag { font-size: .68rem; color: #A1A1AA; }

  .res-body {
    background: rgba(9, 9, 11, 0.72);
    border-top: 1px solid rgba(255, 255, 255, 0.05);
    padding: 12px 16px;
    gap: 10px;
  }
  .route-choice { min-height: 26px; padding: 3px 9px; font-size: .72rem; background: transparent; color: #A1A1AA; }
  .route-choice.selected { background: #F4F4F5; color: #09090B; border-color: #F4F4F5; font-weight: 600; }

  .entries-box-card {
    border-radius: 12px;
    border: 1px solid rgba(255, 255, 255, 0.06);
    background: rgba(18, 18, 21, 0.72);
  }
  .entry-item { padding: 8px 12px; font-size: .78rem; }
  .entry-left { min-width: 0; flex: 1; }
  .type-chip {
    font-size: .6rem;
    text-transform: uppercase;
    padding: 2px 6px;
    border-radius: 5px;
    background: rgba(255, 255, 255, 0.06);
    color: #A1A1AA;
  }
  .entry-val { font-size: .74rem; color: #E4E4E7; }
  .entry-val.disabled { color: #71717A; text-decoration: line-through; }
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

  .proxy-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; }
  .proxy-card { padding: 16px; gap: 12px; }
  .small-link { font-size: .78rem; color: #D4D4D8; }

  .search { width: min(100%, 220px); min-height: 32px; padding: 5px 10px; font-size: .8rem; }
  .two-cols { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .perm-row { font-size: .82rem; color: #D4D4D8; padding: 4px 0; }
  .link-box {
    padding: 12px;
    border-radius: 12px;
    background: #09090B;
    border: 1px solid rgba(255, 255, 255, 0.12);
    font-size: .74rem;
    color: #E4E4E7;
    word-break: break-all;
  }
  .qr-panel {
    display: grid;
    justify-items: center;
    gap: 10px;
    padding: 14px;
    border-radius: 12px;
    background: rgba(255, 255, 255, 0.03);
    border: 1px solid var(--hp-border);
    text-align: center;
  }
  .qr-svg {
    width: 204px;
    height: 204px;
    border-radius: 10px;
    overflow: hidden;
    background: #ffffff;
    box-shadow: 0 8px 24px rgba(0, 0, 0, 0.35);
  }
  .qr-svg :global(svg) {
    display: block;
    width: 100%;
    height: 100%;
  }
  .qr-hint {
    font-size: .76rem;
    color: var(--muted);
    max-width: 320px;
  }
  .modal-actions { justify-content: flex-end; }
  .entries-box { gap: 10px; border: 1px solid var(--hp-border); padding: 12px; border-radius: 12px; background: #09090B; }
  .entry-add { display: grid; grid-template-columns: 150px minmax(0, 1fr) auto; gap: 6px; align-items: center; }
  .entries-list { display: grid; gap: 6px; max-height: 160px; overflow: auto; }
  .entry-row { padding: 4px 0; border-bottom: 1px solid rgba(255, 255, 255, 0.06); }
  .entry-row:last-child { border-bottom: 0; }
  .update-outcome { white-space: normal; }

  @media (max-width: 800px) {
    .shell { display: block; }
    aside { gap: 10px; padding: 12px; border-right: 0; border-bottom: 1px solid var(--hp-border); }
    nav { display: flex; flex-wrap: wrap; }
    nav button, .exit { width: auto; min-height: 34px; }
    .metrics { grid-template-columns: repeat(3, minmax(0, 1fr)); }
    .proxy-grid { grid-template-columns: 1fr; }
  }
  @media (max-width: 560px) {
    .metrics { grid-template-columns: 1fr; }
    .entry-add { grid-template-columns: 1fr; }
    table, tbody, tr, td { display: block; }
    thead { position: absolute; clip-path: inset(50%); width: 1px; height: 1px; overflow: hidden; }
    tr { border-top: 1px solid rgba(255, 255, 255, 0.06); padding: 8px 0; }
    td { padding: 4px 0; border-bottom: 0; }
    td[data-label] { display: grid; grid-template-columns: minmax(84px, 36%) minmax(0, 1fr); gap: 8px; }
    td[data-label]::before { content: attr(data-label); color: var(--muted); font-size: .75rem; }
  }
</style>
