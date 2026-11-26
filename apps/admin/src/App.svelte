<script lang="ts">
  import { Activity, ArrowRight, Cable, DatabaseBackup, Globe2, Layers, LayoutDashboard, Link2, ListFilter, LogOut, Monitor, PackageCheck, Plus, RefreshCw, Router, Shield, Users, X } from 'lucide-svelte'
  import Brand from '../../../packages/ui/Brand.svelte'
  import { actionNames, scopeOf } from '../../../packages/shared/models'
  import type { Action, Rule, RuleKind, ServiceGroup, ServiceGroupEntry } from '../../../packages/shared/models'
  import { admin } from './api'
  import type { Proxy, State, UpdateEntry, UpdatePolicy, User } from './api'

  const views = [
    { id: 'overview', label: 'Обзор', icon: LayoutDashboard },
    { id: 'proxies', label: 'Прокси', icon: Router },
    { id: 'users', label: 'Пользователи', icon: Users },
    { id: 'devices', label: 'Устройства', icon: Monitor },
    { id: 'rules', label: 'Правила', icon: ListFilter },
    { id: 'groups', label: 'Группы сервисов', icon: Layers },
    { id: 'updates', label: 'Обновления', icon: PackageCheck },
    { id: 'audit', label: 'Журнал и копии', icon: DatabaseBackup }
  ] as const
  const eventNames: Record<string, string> = {
    'user.created': 'Создан пользователь', 'user.updated': 'Изменено имя пользователя', 'user.deleted': 'Удалён пользователь',
    'proxy.saved': 'Сохранён прокси', 'proxy.deleted': 'Удалён прокси',
    'device.invited': 'Создана ссылка', 'device.connected': 'Устройство подключено', 'device.revoked': 'Доступ отозван',
    'rule.saved': 'Сохранено правило', 'rule.deleted': 'Удалено правило',
    'group.saved': 'Сохранена группа сервисов', 'group.deleted': 'Удалена группа сервисов',
    'routes.saved': 'Назначены прокси',
    'client-update-policy.saved': 'Изменена политика обновлений клиентов'
  }
  const deviceStates: Record<string, string> = { connected: 'Подключено', invited: 'Ожидает', revoked: 'Отозвано' }
  const entryKindNames: Record<RuleKind, string> = {
    domain: 'Домен', suffix: 'Поддомены', ip_cidr: 'IP / CIDR', process: 'Приложение Windows', package: 'Приложение Android'
  }
  const releasePlatforms = { windows: 'Windows', android: 'Android', browser: 'Расширение' }
  const updateOutcomes: Record<UpdateEntry['outcome'], string> = {
    installed: 'Установлено', 'no-update': 'Нет совместимого обновления', completed: 'Проверка завершена', failed: 'Ошибка', paused: 'Пропущено по политике'
  }
  const updatePhases: Record<UpdateEntry['phase'], string> = {
    prerequisites: 'Подготовка', recovery: 'Восстановление', apply: 'Проверка и установка', policy: 'Чтение политики'
  }
  type Dialog = 'invite' | 'proxy' | 'user' | 'routes' | 'rule' | 'group'
  const dialogNames: Record<Dialog, string> = {
    invite: 'Ссылка подключения', proxy: 'Прокси', user: 'Пользователь',
    routes: 'Очередь прокси', rule: 'Правило', group: 'Группа сервисов'
  }

  let view = $state<typeof views[number]['id']>('overview')
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
  let transport = $state('agent')
  let link = $state('')
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
  let title = $derived(views.find(item => item.id === view)?.label)
  let active = $derived(data?.devices.filter(d => d.status === 'connected').length ?? 0)
  let onlineCount = $derived(data?.devices.filter(d => d.online).length ?? 0)

  function matches(...fields: string[]) {
    return fields.join(' ').toLowerCase().includes(search.trim().toLowerCase())
  }
  const stamp = (value: number) => value ? new Intl.DateTimeFormat('ru', { dateStyle: 'short', timeStyle: 'short' }).format(value * 1000) : 'Нет данных'
  const username = (id?: string) => data?.users.find(user => user.id === id)?.name ?? 'Все пользователи'

  async function load() {
    data = await admin<State>(token, 'state')
    connected = true
    try {
      const health = await fetch('/healthz', { signal: AbortSignal.timeout(2000) })
      serverRelease = health.ok || health.status === 503 ? await health.json() : null
      systemHealth = health.ok
    } catch {
      serverRelease = null
      systemHealth = false
    }
    if (view === 'updates') loadUpdates()
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
      if (token === key && view === 'updates') updatePolicy = Promise.resolve(policy)
    })
  }
  function setClientUpdatesPaused(paused: boolean) {
    void task(async () => {
      const key = token
      const policy = await admin<{ paused: boolean }>(key, 'client-update-policy', 'PUT', { paused })
      if (token === key && view === 'updates') clientUpdatePolicy = Promise.resolve(policy)
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
    void task(async () => { await load(); keyInput = '' })
  }
  function navigate(next: typeof view) {
    view = next; search = ''; error = ''; message = ''
    if (next === 'updates') loadUpdates()
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
    error = ''; message = ''; dialog = type; link = ''; label = ''; transport = 'agent'; candidate = ''
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
    groupEntries = [...groupEntries, { kind: newEntryKind, pattern }]
    newEntryPattern = ''
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
  function toggleGroup(group: ServiceGroup) {
    void task(async () => {
      await admin(token, 'groups', 'PUT', {
        ...group,
        enabled: !group.enabled
      })
      await load()
      message = 'Изменения сохранены'
    })
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
        const item = await admin<{ link: string }>(token, 'invites', 'POST', { userId, label, transport, minutes: Number(field('minutes')) })
        link = item.link
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
        if (dialog === 'group') await admin(token, 'groups', 'PUT', {
          id: editingGroup?.id ?? '', name: groupName, userId, action: groupAction,
          enabled: groupEnabled, locked: groupLocked, revision: editingGroup?.revision ?? 0,
          entries: groupEntries
        })
        modal?.close()
      }
      await load()
      message = dialog === 'invite' ? 'Ссылка создана' : 'Изменения сохранены'
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
</script>

{#if !connected}
  <main class="login">
    <form class="card stack" onsubmit={signIn}>
      <Brand caption="Панель управления" />
      <div class="card-head">
        <h1>Вход администратора</h1>
        <p class="muted">Укажите ключ HomeProxy Server.</p>
      </div>
      <label>Ключ доступа <input type="password" bind:value={keyInput} placeholder="Вставьте ключ" required autocomplete="off" /></label>
      {#if error}<p class="notice error" role="alert">{error}</p>{/if}
      <button class="primary" disabled={busy}>{busy ? 'Подключение…' : 'Войти'} <ArrowRight size={16} /></button>
    </form>
  </main>
{:else if data}
  <div class="shell">
    <aside>
      <Brand caption="Панель управления" />
      <nav aria-label="Разделы">
        {#each views as item}
          <button class:current={item.id === view} aria-current={item.id === view ? 'page' : undefined} onclick={() => navigate(item.id)}>
            <item.icon size={18} />{item.label}
          </button>
        {/each}
      </nav>
      <button class="ghost exit" onclick={() => { connected = false; data = undefined; token = ''; navigate('overview') }}><LogOut size={17} /> Выход</button>
    </aside>

    <div class="workspace">
      <header class="between">
        <div class="flex"><Shield size={17} /> <span>Администрирование</span></div>
        <div class="flex">
          <span class="badge" class:ok={systemHealth === true} class:bad={systemHealth === false}>{systemHealth ? 'Сервер доступен' : 'Проверьте сервер'}</span>
          <button class="small ghost" aria-label="Обновить данные" title="Обновить данные" onclick={() => task(load)} disabled={busy}><RefreshCw size={16} /></button>
        </div>
      </header>
      <main class="content stack">
        <div class="between page-title">
          <div class="card-head"><h1>{title}</h1></div>
          {#if view === 'overview' || view === 'devices'}
            <button class="primary" disabled={!data.users.length || busy} onclick={() => open('invite')}><Link2 size={17} /> Создать ссылку</button>
          {:else if view === 'proxies'}
            <div class="flex"><button disabled={!data.users.length} onclick={() => open('routes')}>Назначить прокси</button><button class="primary" onclick={() => open('proxy')}><Plus size={17} /> Добавить прокси</button></div>
          {:else if view === 'users'}
            <button class="primary" onclick={() => open('user')}><Plus size={17} /> Добавить пользователя</button>
          {:else if view === 'rules'}
            <button class="primary" onclick={() => open('rule')}><Plus size={17} /> Добавить правило</button>
          {:else if view === 'groups'}
            <button class="primary" onclick={() => open('group')}><Plus size={17} /> Добавить группу</button>
          {:else if view === 'audit'}
            <button class="primary" disabled={busy} onclick={backup}><DatabaseBackup size={17} /> Создать копию SQLite</button>
          {/if}
        </div>
        {#if error && !modal?.open}<p class="notice error" role="alert">{error}</p>{/if}
        {#if message && !modal?.open}<p class="notice success" role="status">{message}</p>{/if}
        {#if view === 'overview'}
          <div class="metrics">
            {#each [{ icon: Monitor, label: 'Устройства онлайн', value: `${onlineCount} / ${active}` }, { icon: Router, label: 'Настроенные прокси', value: data.proxies.length }, { icon: ListFilter, label: 'Правила и группы', value: data.rules.length + data.groups.length }, { icon: Activity, label: 'Версия конфигурации', value: data.revision }] as card}
              <div class="card metric"><span class="mark"><card.icon size={19} /></span><strong>{card.value}</strong><small>{card.label}</small></div>
            {/each}
          </div>
          <section class="card stack">
            <div class="between">
              <div class="card-head"><h2>Схема маршрутизации</h2><p class="muted">В профиле AUTO клиенты подключаются к внешнему прокси напрямую с устройства.</p></div>
            </div>
            <div class="topology">
              <div class="node"><Monitor size={22} /><div><strong>Устройство</strong><small>HomeProxy Agent</small></div></div>
              <ArrowRight class="edge" size={18} />
              <div class="node"><Cable size={22} /><div><strong>Внешний прокси</strong><small>HTTP CONNECT (основной)</small></div></div>
              <ArrowRight class="edge" size={18} />
              <div class="node"><Globe2 size={22} /><div><strong>HomeProxy Server</strong><small>VLESS + REALITY (резерв)</small></div></div>
            </div>
            <span class="label">Если внешний прокси с устройства недоступен или выбран маршрут через сервер, трафик идёт через HomeProxy Server.</span>
          </section>
        {/if}

        {#if view === 'overview' || view === 'devices'}
          <section class="card stack">
            <div class="between"><h2>{view === 'overview' ? 'Недавние устройства' : 'Все устройства'}</h2>
              {#if view === 'overview'}<button class="small ghost" onclick={() => navigate('devices')}>Открыть список <ArrowRight size={15} /></button>
              {:else}<input class="search" aria-label="Поиск устройств" placeholder="Поиск устройств" bind:value={search} />{/if}
            </div>
            {#if !data.devices.length}<p class="empty">Создайте ссылку, чтобы подключить первое устройство.</p>
            {:else}<div class="table-scroll"><table>
              <thead><tr><th>Устройство</th><th>Пользователь</th><th>Статус</th><th>Версия</th><th>Последняя связь</th>{#if view === 'devices'}<th>Действия</th>{/if}</tr></thead>
              <tbody>{#each data.devices.filter(d => matches(d.label, username(d.userId))).slice(0, view === 'overview' ? 5 : undefined) as device (device.id)}
                <tr><td data-label="Устройство"><span class="flex"><Monitor size={16} />{device.label}</span></td><td data-label="Пользователь">{username(device.userId)}</td>
                  <td data-label="Статус">
                    {#if device.status === 'connected'}
                      <span class="badge" class:ok={Boolean(device.online)}>{device.online ? 'Онлайн' : 'Офлайн'}{#if (device.activeConnections ?? 0) > 0} · {device.activeConnections}{/if}</span>
                    {:else}
                      <span class="badge" class:wait={device.status === 'invited'} class:bad={device.status === 'revoked'}>{deviceStates[device.status]}</span>
                    {/if}
                  </td>
                  <td data-label="Версия" class="mono">{device.ackRevision || 'Нет данных'}</td><td data-label="Последняя связь">{stamp(device.seen)}</td>
                  {#if view === 'devices'}<td>{#if device.status !== 'revoked'}<button class="small danger" onclick={() => remove('devices/' + device.id, 'Отозвать доступ устройства?')}>Отозвать</button>{/if}</td>{/if}</tr>
              {/each}</tbody>
            </table></div>{/if}
          </section>
        {:else if view === 'proxies'}
          <section class="card stack">
            <div class="between"><h2>Исходные прокси</h2><input class="search" aria-label="Поиск прокси" placeholder="Поиск по имени или адресу" bind:value={search} /></div>
            {#if !data.proxies.length}<p class="empty">Добавьте HTTP CONNECT и назначьте его пользователю.</p>
            {:else}<div class="table-scroll"><table>
              <thead><tr><th>Имя</th><th>Адрес</th><th>Протокол</th><th>Действия</th></tr></thead>
              <tbody>{#each data.proxies.filter(p => matches(p.name, p.host)) as proxy (proxy.id)}
                <tr><td data-label="Имя">{proxy.name}</td><td data-label="Адрес" class="mono">{proxy.host}:{proxy.port}</td>
                  <td data-label="Протокол"><span class="flex">{proxy.tls ? 'HTTPS CONNECT' : 'HTTP CONNECT'}{#if proxy.headers && Object.keys(proxy.headers).length}<span class="badge">+{Object.keys(proxy.headers).length} заг.</span>{/if}</span></td>
                  <td><div class="flex"><button class="small" disabled={busy} onclick={() => probe(proxy)}>Проверить</button><button class="small" onclick={() => open('proxy', proxy)}>Изменить</button>
                    <button class="small danger" onclick={() => remove('proxies/' + proxy.id, 'Удалить прокси из всех назначений?')}>Удалить</button></div></td></tr>
              {/each}</tbody>
            </table></div>{/if}
          </section>
        {:else if view === 'users'}
          <section class="card stack">
            <div class="between"><h2>Учётные записи HomeProxy</h2><input class="search" aria-label="Поиск пользователей" placeholder="Поиск пользователей" bind:value={search} /></div>
            <p class="label">Учётная запись объединяет устройства, назначенные прокси и синхронизируемые правила.</p>
            {#if !data.users.length}<p class="empty">Добавьте пользователя, чтобы выдать ему ссылку подключения.</p>
            {:else}<div class="table-scroll"><table>
              <thead><tr><th>Имя</th><th>Назначенные прокси по приоритету</th><th>Действия</th></tr></thead>
              <tbody>{#each data.users.filter(u => matches(u.name)) as user (user.id)}
                <tr><td data-label="Имя">{user.name}</td><td data-label="Очередь прокси">{data.routes.filter(route => route.userId === user.id).map(route => data?.proxies.find(p => p.id === route.proxyId)?.name).join(', ') || 'Нет назначений'}</td>
                  <td><div class="flex"><button class="small" onclick={() => open('user', user)}>Изменить имя</button>
                    <button class="small" onclick={() => { open('routes'); selectUser(user.id) }}>Назначить прокси</button>
                    <button class="small" onclick={() => { open('invite'); selectUser(user.id) }}>Создать ссылку</button>
                    <button class="small danger" onclick={() => remove('users/' + user.id, 'Удалить пользователя и все его устройства и правила?')}>Удалить</button></div></td></tr>
              {/each}</tbody>
            </table></div>{/if}
          </section>
        {:else if view === 'rules'}
          <section class="card stack">
            <div class="between"><h2>Правила маршрутизации</h2><input class="search" aria-label="Поиск правил" placeholder="Поиск по шаблону" bind:value={search} /></div>
            {#if !data.rules.length}<p class="empty">Добавьте правило для сайта или приложения.</p>
            {:else}<div class="table-scroll"><table>
              <thead><tr><th>Шаблон</th><th>Область</th><th>Маршрут</th><th>Статус</th><th>Действия</th></tr></thead>
              <tbody>{#each data.rules.filter(r => matches(r.pattern, username(r.userId))) as rule (rule.id)}
                <tr><td data-label="Шаблон" class="mono">{rule.pattern}</td><td data-label="Область">{scopeOf(rule)}{rule.userId ? ' · ' + username(rule.userId) : ''}</td>
                  <td data-label="Маршрут">{actionNames[rule.action]}</td>
                  <td data-label="Статус"><button class="small" disabled={busy} onclick={() => toggleRule(rule)}>{rule.enabled !== false ? 'Вкл' : 'Выкл'}</button></td>
                  <td><div class="flex"><button class="small" onclick={() => open('rule', rule)}>Изменить</button>
                    <button class="small danger" onclick={() => remove('rules/' + rule.id, 'Удалить правило?')}>Удалить</button></div></td></tr>
              {/each}</tbody>
            </table></div>{/if}
          </section>
        {:else if view === 'groups'}
          <section class="card stack">
            <div class="between"><h2>Группы сервисов</h2><input class="search" aria-label="Поиск групп" placeholder="Поиск групп" bind:value={search} /></div>
            <p class="label">Объединяйте домены, IP-адреса и приложения Windows/Android в один сервис с общим маршрутом.</p>
            {#if !data.groups.length}<p class="empty">Создайте группу сервисов, например ChatGPT или Рабочие ресурсы.</p>
            {:else}<div class="table-scroll"><table>
              <thead><tr><th>Название</th><th>Область</th><th>Состав</th><th>Маршрут</th><th>Статус</th><th>Действия</th></tr></thead>
              <tbody>{#each data.groups.filter(g => matches(g.name, username(g.userId), ...g.entries.map(e => e.pattern))) as group (group.id)}
                <tr>
                  <td data-label="Название"><strong>{group.name}</strong></td>
                  <td data-label="Область">{group.locked ? 'Обязательное' : group.userId ? 'PERSONAL · ' + username(group.userId) : 'GLOBAL'}</td>
                  <td data-label="Состав"><span class="mono">{group.entries.length}</span>{#if group.entries.length} <small class="muted">{group.entries.slice(0, 2).map(e => e.pattern).join(', ')}{group.entries.length > 2 ? '…' : ''}</small>{/if}</td>
                  <td data-label="Маршрут">{actionNames[group.action]}</td>
                  <td data-label="Статус"><button class="small" disabled={busy} onclick={() => toggleGroup(group)}>{group.enabled ? 'Вкл' : 'Выкл'}</button></td>
                  <td><div class="flex"><button class="small" onclick={() => open('group', group)}>Изменить</button>
                    <button class="small danger" onclick={() => remove('groups/' + group.id, 'Удалить группу сервисов?')}>Удалить</button></div></td>
                </tr>
              {/each}</tbody>
            </table></div>{/if}
          </section>
        {:else if view === 'updates'}
          <section class="card stack">
            <h2>HomeProxy Server</h2>
            {#if serverRelease?.version}
              <p>Установленная версия <strong>{serverRelease.version}</strong></p>
              <p class="muted">API {serverRelease.api}, схема SQLite {serverRelease.dbSchema}</p>
            {:else}
              <p class="muted">Версия сервера недоступна.</p>
            {/if}
            <p><a href="https://github.com/C0dece/HomeProxy/releases/latest" target="_blank" rel="noopener noreferrer">Стабильный выпуск на GitHub</a></p>
          </section>
          <section class="card stack">
            <h2>Автоматические обновления сервера</h2>
            {#await updatePolicy}
              <p class="muted" role="status">Загрузка политики…</p>
            {:then policy}
              {#if !policy}
                <p class="notice error" role="alert">Политика обновлений недоступна.</p>
              {:else if !policy.managed}
                <p class="muted">Управление из панели отключено в конфигурации сервера.</p>
              {:else}
                <div class="between">
                  <span class="badge" class:wait={policy.paused} class:ok={!policy.paused}>{policy.paused ? 'На паузе' : 'Разрешены'}</span>
                  <button disabled={busy} onclick={() => setUpdatesPaused(!policy.paused)}>{policy.paused ? 'Возобновить' : 'Приостановить'}</button>
                </div>
              {/if}
            {/await}
          </section>
          <section class="card stack">
            <h2>Обновления Windows и Android</h2>
            {#await clientUpdatePolicy}
              <p class="muted" role="status">Загрузка политики…</p>
            {:then policy}
              {#if !policy}
                <p class="notice error" role="alert">Политика клиентов недоступна.</p>
              {:else}
                <div class="between">
                  <span class="badge" class:wait={policy.paused} class:ok={!policy.paused}>{policy.paused ? 'На паузе' : 'Разрешены'}</span>
                  <button disabled={busy} onclick={() => setClientUpdatesPaused(!policy.paused)}>{policy.paused ? 'Возобновить у клиентов' : 'Приостановить у клиентов'}</button>
                </div>
              {/if}
            {/await}
          </section>
          <section class="card stack">
            <h2>Версии клиентских устройств</h2>
            {#if !data.devices.length}
              <p class="empty">Устройств пока нет.</p>
            {:else}
              <div class="table-scroll"><table>
                <thead><tr><th>Устройство</th><th>Платформа</th><th>Установленная версия</th><th>Получен отчёт</th></tr></thead>
                <tbody>
                  {#each data.devices as device (device.id)}
                    <tr>
                      <td data-label="Устройство">{device.label}{#if device.status === 'revoked'} <span class="badge bad">Отозвано</span>{/if}</td>
                      <td data-label="Платформа">{device.platform ? releasePlatforms[device.platform] : 'Нет данных'}</td>
                      <td data-label="Установленная версия">{device.installedVersion || 'Нет данных'}</td>
                      <td data-label="Получен отчёт">{stamp(device.reportedAt ?? 0)}</td>
                    </tr>
                  {/each}
                </tbody>
              </table></div>
            {/if}
          </section>
          <section class="card stack">
            <h2>История обновлений сервера</h2>
            {#await updateHistory}
              <p class="muted" role="status">Загрузка истории…</p>
            {:then entries}
              {#if !entries}
                <p class="notice error" role="alert">История обновлений недоступна.</p>
              {:else if !entries.length}
                <p class="empty">Пока нет записей об обновлениях.</p>
              {:else}
                <div class="table-scroll"><table>
                  <thead><tr><th>Время завершения</th><th>Результат</th><th>Подробности</th></tr></thead>
                  <tbody>
                    {#each entries as entry}
                      <tr>
                        <td data-label="Время завершения">{stamp(entry.finishedAt)}</td>
                        <td data-label="Результат">
                          <span class="badge update-outcome" class:ok={entry.outcome === 'installed'} class:bad={entry.outcome === 'failed'}>{updateOutcomes[entry.outcome]}</span>
                        </td>
                        <td data-label="Подробности">
                          {#if entry.version}Версия {entry.version}
                          {:else if entry.outcome === 'failed'}{updatePhases[entry.phase]}{#if entry.exitCode !== undefined}, код {entry.exitCode}{/if}
                          {:else}Стабильный канал{/if}
                        </td>
                      </tr>
                    {/each}
                  </tbody>
                </table></div>
              {/if}
            {/await}
          </section>
        {:else if view === 'audit'}
          <section class="card stack">
            <h2>Последние изменения</h2>
            {#if !data.audit.length}<p class="empty">В журнале пока нет событий.</p>
            {:else}<div class="table-scroll"><table>
              <thead><tr><th>Версия</th><th>Событие</th><th>Время</th></tr></thead>
              <tbody>{#each data.audit as entry (entry.revision)}<tr><td data-label="Версия" class="mono">{entry.revision}</td><td data-label="Событие">{eventNames[entry.event] ?? entry.event}</td><td data-label="Время">{stamp(entry.time)}</td></tr>{/each}</tbody>
            </table></div>{/if}
          </section>
        {/if}
      </main>
    </div>
  </div>
{/if}

{#if connected && data}
  <dialog bind:this={modal} onclose={() => { error = ''; link = '' }}>
    <div class="stack">
      <div class="between"><h2>{dialog === 'user' ? (editingUser ? 'Изменить имя' : 'Добавить пользователя') : dialogNames[dialog]}</h2><button class="small ghost" aria-label="Закрыть" onclick={() => modal?.close()}><X size={19} /></button></div>
      {#if error}<p class="notice error" role="alert">{error}</p>{/if}
      {#if link}
        <div class="stack">
          <label>Одноразовая ссылка<input class="mono" value={link} readonly onclick={e => e.currentTarget.select()} /></label>
          <button class="primary" onclick={() => task(async () => { await navigator.clipboard.writeText(link); message = 'Ссылка скопирована' })}>Скопировать ссылку</button>
          {#if message}<p role="status" class="success">{message}</p>{/if}
        </div>
      {:else}
        <form class="stack" onsubmit={save}>
          {#if dialog === 'user'}
            <label>Имя<input required maxlength="100" name="name" value={editingUser?.name ?? ''} /></label>
          {:else if dialog === 'invite' || dialog === 'routes'}
            <label>Пользователь<select value={userId} onchange={e => selectUser(e.currentTarget.value)} required>{#each data.users as user}<option value={user.id}>{user.name}</option>{/each}</select></label>
            {#if dialog === 'invite'}
              <label>Название устройства<input required bind:value={label} maxlength="100" placeholder="Например, рабочий ноутбук" /></label>
              <div class="field-row">
                <label>Клиент<select bind:value={transport}><option value="agent">HomeProxy Agent</option><option value="browser">HomeProxy Browser</option></select></label>
                <label>Срок действия, минуты<input name="minutes" type="number" min="1" max="60" value="15" required /></label>
              </div>
            {:else}
              {#each selected as id, index (id)}
                <div class="between"><span class="mono">{index + 1}. {data.proxies.find(proxy => proxy.id === id)?.name}</span><div class="flex">
                  <button class="small" type="button" aria-label="Повысить приоритет" onclick={() => move(index, -1)} disabled={index === 0}>↑</button>
                  <button class="small" type="button" aria-label="Понизить приоритет" onclick={() => move(index, 1)} disabled={index === selected.length - 1}>↓</button>
                  <button class="small" type="button" onclick={() => selected = selected.filter(item => item !== id)}>Убрать</button>
                </div></div>
              {/each}
              <label>Прокси<select bind:value={candidate}><option value="">Выберите прокси</option>
                {#each data.proxies.filter(p => !selected.includes(p.id)) as proxy}<option value={proxy.id}>{proxy.name}</option>{/each}
              </select></label>
              <button type="button" disabled={!candidate} onclick={() => { selected = [...selected, candidate]; candidate = '' }}>Добавить в очередь</button>
            {/if}
          {:else if dialog === 'proxy'}
            <label>Имя<input name="name" value={editingProxy?.name ?? ''} required maxlength="100" /></label>
            <div class="field-row"><label>Адрес<input name="host" value={editingProxy?.host ?? ''} required /></label>
              <label>Порт<input name="port" type="number" min="1" max="65535" value={editingProxy?.port ?? 8080} required /></label></div>
            <div class="field-row"><label>Логин<input name="username" autocomplete="off" /></label><label>Пароль<input name="password" type="password" autocomplete="new-password" /></label></div>
            <label>HTTP-заголовки (опционально, по строке <code>Имя: Значение</code>)
              <textarea name="headers" rows="3" bind:value={proxyHeadersText} placeholder="X-Custom-Auth: token"></textarea>
            </label>
            {#if editingProxy}<small class="muted">Введите действующие учётные данные для проверки новой конфигурации.</small>{/if}
            <label class="check"><input name="tls" type="checkbox" checked={Boolean(editingProxy?.tls)} /> TLS к прокси</label>
          {:else if dialog === 'group'}
            <label>Название<input required maxlength="100" bind:value={groupName} placeholder="Например, ChatGPT" /></label>
            <div class="field-row">
              <label>Область<select bind:value={userId}><option value="">GLOBAL</option>{#each data.users as user}<option value={user.id}>PERSONAL · {user.name}</option>{/each}</select></label>
              <label>Маршрут<select bind:value={groupAction}>{#each Object.entries(actionNames) as [action, name]}<option value={action}>{name}</option>{/each}</select></label>
            </div>
            <div class="field-row">
              <label class="check"><input type="checkbox" bind:checked={groupEnabled} /> Группа включена</label>
              <label class="check"><input type="checkbox" bind:checked={groupLocked} /> Приоритет над локальными правилами</label>
            </div>
            <div class="stack entries-box">
              <span class="label">Элементы группы ({groupEntries.length})</span>
              <div class="entry-add">
                <select bind:value={newEntryKind}>
                  {#each Object.entries(entryKindNames) as [kind, label]}<option value={kind}>{label}</option>{/each}
                </select>
                <input bind:value={newEntryPattern} placeholder={newEntryKind === 'ip_cidr' ? '1.2.3.0/24' : newEntryKind === 'process' ? 'app.exe' : newEntryKind === 'package' ? 'com.example.app' : 'example.com'}
                  onkeydown={e => { if (e.key === 'Enter') { e.preventDefault(); addGroupEntry() } }} />
                <button type="button" class="small" onclick={addGroupEntry}>Добавить</button>
              </div>
              {#if groupEntries.length}
                <div class="entries-list">
                  {#each groupEntries as entry, i (entry.kind + ':' + entry.pattern)}
                    <div class="between entry-row">
                      <span><span class="badge">{entryKindNames[entry.kind]}</span> <code class="mono">{entry.pattern}</code></span>
                      <button type="button" class="small ghost" aria-label="Удалить элемент" onclick={() => groupEntries = groupEntries.filter((_, idx) => idx !== i)}><X size={14} /></button>
                    </div>
                  {/each}
                </div>
              {/if}
            </div>
          {:else}
            <label>Область<select bind:value={userId} disabled={Boolean(editingRule)}><option value="">GLOBAL</option>{#each data.users as user}<option value={user.id}>PERSONAL · {user.name}</option>{/each}</select></label>
            <div class="field-row"><label>Тип<select name="kind" bind:value={ruleKind} disabled={Boolean(editingRule)}>
              <option value="domain">Домен</option><option value="suffix">Домен и поддомены</option><option value="process">Приложение Windows</option><option value="package">Приложение Android</option>
            </select>{#if editingRule}<input type="hidden" name="kind" value={editingRule.kind} />{/if}</label>
            <label>Шаблон<input name="pattern" value={editingRule?.pattern ?? ''} readonly={Boolean(editingRule)} placeholder={ruleKind === 'package' ? 'com.example.app' : ruleKind === 'process' ? 'Имя или полный путь EXE' : 'example.com'} required /></label></div>
            <label>Маршрут<select name="action" value={editingRule?.action ?? 'PROXY'}>{#each Object.entries(actionNames) as [action, name]}<option value={action}>{name}</option>{/each}</select></label>
            <label class="check"><input name="enabled" type="checkbox" checked={editingRule?.enabled !== false} /> Правило включено</label>
            {#if ruleKind === 'domain' || ruleKind === 'suffix'}<label class="check"><input name="locked" type="checkbox" checked={Boolean(editingRule?.locked)} /> Приоритет над локальными правилами</label>{/if}
          {/if}
          <button class="primary" disabled={busy}>{busy ? 'Сохранение…' : dialog === 'invite' ? 'Создать ссылку' : 'Сохранить'}</button>
        </form>
      {/if}
    </div>
  </dialog>
{/if}

<style>
  .update-outcome { white-space: normal; }
  .login { min-height: 100vh; display: grid; place-items: center; padding: 24px; }
  .login form { width: min(100%, 430px); gap: 24px; }
  .shell { min-height: 100vh; display: grid; grid-template-columns: 224px minmax(0, 1fr); }
  aside { padding: 24px 16px; border-right: 1px solid var(--border); background: var(--sidebar); display: flex; flex-direction: column; gap: 32px; }
  nav { display: grid; gap: 5px; }
  nav button, .exit { justify-content: flex-start; background: transparent; border-color: transparent; color: var(--secondary); width: 100%; }
  nav button.current { background: #223355; border-color: #344c79; color: #b7caff; }
  .exit { margin-top: auto; }
  .workspace { min-width: 0; }
  header { min-height: 65px; padding: 12px clamp(16px, 3vw, 36px); border-bottom: 1px solid var(--border); color: var(--secondary); font-size: .84rem; }
  .content { max-width: 1440px; margin: auto; padding: 30px clamp(16px, 3vw, 36px); gap: 20px; }
  .page-title { margin-bottom: 4px; }
  .metrics { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 16px; }
  .metric { display: grid; gap: 8px; }
  .metric strong { font-size: 1.7rem; }
  .metric small, .node small { color: var(--muted); }
  .topology { display: grid; grid-template-columns: 1fr auto 1fr auto 1fr; gap: 12px; align-items: center; }
  .node { border: 1px solid var(--border); background: var(--raised); padding: 14px; border-radius: 9px; display: flex; align-items: center; gap: 12px; }
  .node div { display: grid; }
  .node :global(svg), .topology :global(.edge) { color: var(--accent); flex: none; }
  .search { width: min(100%, 240px); min-height: 36px; }
  dialog { width: min(580px, calc(100% - 24px)); max-height: calc(100% - 24px); overflow: auto; padding: 24px; background: var(--surface); color: var(--text); border: 1px solid #425168; border-radius: 12px; }
  dialog::backdrop { background: rgb(5 8 13 / .72); }
  textarea { width: 100%; background: #111720; color: var(--text); border: 1px solid #344152; border-radius: 7px; padding: 8px 11px; font: inherit; resize: vertical; }
  .entries-box { gap: 10px; border: 1px solid var(--border); padding: 12px; border-radius: 8px; background: var(--raised); }
  .entry-add { display: grid; grid-template-columns: 160px minmax(0, 1fr) auto; gap: 8px; align-items: center; }
  .entries-list { display: grid; gap: 6px; max-height: 180px; overflow: auto; }
  .entry-row { padding: 4px 0; border-bottom: 1px solid var(--border); }
  .entry-row:last-child { border-bottom: 0; }
  @media (max-width: 1100px) { .metrics { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
  @media (max-width: 800px) {
    .shell { display: block; }
    aside { gap: 12px; padding: 12px 16px; border-right: 0; border-bottom: 1px solid var(--border); }
    nav { display: flex; flex-wrap: wrap; }
    nav button, .exit { width: auto; min-height: 36px; }
    .exit { align-self: flex-start; }
    .topology { grid-template-columns: 1fr; }
    .topology :global(.edge) { transform: rotate(90deg); margin-left: 16px; }
  }
  @media (max-width: 560px) {
    .entry-add { grid-template-columns: 1fr; }
    table, tbody, tr, td { display: block; }
    thead { position: absolute; clip-path: inset(50%); width: 1px; height: 1px; overflow: hidden; }
    tr { border-top: 1px solid var(--border); padding: 10px 0; }
    td { padding: 5px 0; border-bottom: 0; }
    td[data-label] { display: grid; grid-template-columns: minmax(84px, 36%) minmax(0, 1fr); gap: 8px; }
    td[data-label]::before { content: attr(data-label); color: var(--muted); font: .78rem "Segoe UI", system-ui, sans-serif; }
  }
</style>
