import type { Action, AutoBaseRoute, RoutingMode, Rule, ServiceGroup } from '../../packages/shared/models'
import { buildPacScript, effectiveBrowserRules, matchesRule, validDomain } from './pac'
import type { ExtensionMode, StandaloneProxy, StandaloneScheme } from './pac'

export type Observed = { domain: string; failed: boolean; types: string[] }
export type SiteRoute = 'auto' | 'proxy' | 'direct' | 'block'

type BrowserState = {
  mode: ExtensionMode
  routingMode: RoutingMode
  autoBaseRoute: AutoBaseRoute
  agentPort: number
  standaloneProxy: StandaloneProxy
  origin: string
  key: string
  deviceId: string
  revision: number
  enabled: boolean
  online: boolean
  local: Rule[]
  remote: Rule[]
  groups: ServiceGroup[]
  pending: Rule[]
  error: string
}

type Incoming = {
  command: string
  link?: string
  tabId?: number
  host?: string
  enabled?: boolean
  mode?: ExtensionMode
  routingMode?: RoutingMode
  autoBaseRoute?: AutoBaseRoute
  siteRoute?: SiteRoute
  agentPort?: number
  standaloneProxy?: Partial<StandaloneProxy> & { keepPassword?: boolean }
  action?: Action
  scope?: 'LOCAL' | 'PERSONAL'
  domains?: string[]
  includeSubdomains?: boolean
  kind?: 'domain' | 'suffix'
  pattern?: string
}

const actions = new Set<Action>(['PROXY', 'AUTO', 'LOCAL_DIRECT', 'SERVER_DIRECT', 'BLOCK', 'INHERIT'])
const resourceTypes = [
  'main_frame', 'sub_frame', 'stylesheet', 'script', 'image', 'font', 'object',
  'xmlhttprequest', 'ping', 'csp_report', 'media', 'websocket', 'webtransport', 'webbundle', 'other'
] as chrome.declarativeNetRequest.ResourceType[]

const defaultStandalone: StandaloneProxy = {
  scheme: 'https',
  host: '',
  port: 8443,
  username: '',
  password: '',
  defaultDirect: true
}
const initial: BrowserState = {
  mode: 'agent',
  routingMode: 'off',
  autoBaseRoute: 'direct',
  agentPort: 17770,
  standaloneProxy: { ...defaultStandalone },
  origin: '',
  key: '',
  deviceId: '',
  revision: 0,
  enabled: false,
  online: false,
  local: [],
  remote: [],
  groups: [],
  pending: [],
  error: ''
}
const storage = chrome.storage.local
const dnr = chrome.declarativeNetRequest
let queue = Promise.resolve()
const observed = new Map<number, Map<string, Observed>>()
const retriedAuth = new Set<string>()
const RELEASE_MANIFEST_URL = 'https://github.com/C0dece/HomeProxy/releases/latest/download/release.json'
const RELEASE_PAGE_URL = 'https://github.com/C0dece/HomeProxy/releases/latest'
const UPDATE_CHECK_INTERVAL_MS = 12 * 3600 * 1000
type UpdateCache = { checkedAt: number; latestVersion: string; releaseUrl: string }

function compareVersions(a: string, b: string): number {
  const pa = a.replace(/^v/i, '').split('.').map(n => parseInt(n, 10) || 0)
  const pb = b.replace(/^v/i, '').split('.').map(n => parseInt(n, 10) || 0)
  for (let i = 0; i < 3; i++) {
    if ((pa[i] ?? 0) !== (pb[i] ?? 0)) return (pa[i] ?? 0) - (pb[i] ?? 0)
  }
  return 0
}

async function readUpdateCache(): Promise<UpdateCache | undefined> {
  return (await storage.get('updateCheck')).updateCheck as UpdateCache | undefined
}

async function checkExtensionUpdate(): Promise<void> {
  try {
    const cached = await readUpdateCache()
    if (cached && Date.now() - cached.checkedAt < UPDATE_CHECK_INTERVAL_MS) return
    const res = await fetch(RELEASE_MANIFEST_URL, {
      redirect: 'follow',
      cache: 'no-store',
      signal: AbortSignal.timeout(6000)
    })
    if (!res.ok) {
      await storage.set({
        updateCheck: {
          checkedAt: Date.now(),
          latestVersion: cached?.latestVersion ?? '',
          releaseUrl: RELEASE_PAGE_URL
        }
      })
      return
    }
    const manifest = await res.json() as { format?: number; artifacts?: Array<{ component?: string; channel?: string; version?: string }> }
    if (manifest.format !== 1 || !Array.isArray(manifest.artifacts)) return
    let newest = ''
    for (const item of manifest.artifacts) {
      if (item.component === 'browser' && item.channel === 'stable' && typeof item.version === 'string') {
        const clean = item.version.replace(/^v/i, '')
        if (!newest || compareVersions(clean, newest) > 0) newest = clean
      }
    }
    await storage.set({
      updateCheck: {
        checkedAt: Date.now(),
        latestVersion: newest,
        releaseUrl: RELEASE_PAGE_URL
      }
    })
  } catch {
    // Silent failure on offline / timeout / rate limit.
  }
}

async function detectLocalAgent(port: number): Promise<boolean> {
  if (!Number.isInteger(port) || port < 1024 || port > 65531) return false
  try {
    await fetch(`http://127.0.0.1:${port}/`, {
      method: 'GET',
      cache: 'no-store',
      signal: AbortSignal.timeout(350)
    })
    return true
  } catch {
    return false
  }
}

function token() {
  const bytes = crypto.getRandomValues(new Uint8Array(32))
  return btoa(String.fromCharCode(...bytes)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')
}

async function load(): Promise<BrowserState> {
  const stored = (await storage.get('state')).state as Partial<BrowserState> | undefined
  const standaloneProxy = { ...defaultStandalone, ...stored?.standaloneProxy }
  const enabled = Boolean(stored?.enabled)
  const routingMode: RoutingMode = stored?.routingMode ?? (enabled ? 'auto' : 'off')
  const autoBaseRoute: AutoBaseRoute = stored?.autoBaseRoute ?? (standaloneProxy.defaultDirect ? 'direct' : 'proxy')
  return {
    ...initial,
    ...stored,
    routingMode,
    autoBaseRoute,
    standaloneProxy
  }
}

async function save(state: BrowserState) {
  await storage.set({ state })
}

async function api(state: BrowserState, path: string, options: RequestInit = {}) {
  return fetch(state.origin + '/api/v1/' + path, {
    ...options,
    headers: { Authorization: 'Bearer ' + state.key, 'Content-Type': 'application/json', ...options.headers },
    redirect: 'error', cache: 'no-store', signal: AbortSignal.timeout(8000)
  })
}

function orderedForState(state: BrowserState): Rule[] {
  const remote = state.mode === 'agent' ? state.remote : []
  const groups = state.mode === 'agent' ? state.groups : []
  return effectiveBrowserRules(remote, groups, state.local)
}

async function apply(state: BrowserState) {
  const policy = orderedForState(state)
  if (!state.enabled || state.routingMode === 'off') {
    await chrome.proxy.settings.clear({ scope: 'regular' })
  } else {
    const settings = await chrome.proxy.settings.get({ incognito: false })
    if (!['controllable_by_this_extension', 'controlled_by_this_extension'].includes(settings.levelOfControl)) {
      throw new Error('Другой профиль или расширение управляет настройками прокси')
    }
    const originHost = state.origin ? new URL(state.origin).host : ''
    const script = buildPacScript({
      mode: state.mode,
      routingMode: state.routingMode,
      autoBaseRoute: state.autoBaseRoute,
      linked: Boolean(state.key && state.revision),
      rules: policy,
      agentPort: state.agentPort,
      originHost,
      standaloneProxy: state.standaloneProxy
    })
    await chrome.proxy.settings.set({ value: { mode: 'pac_script', pacScript: { data: script, mandatory: true } }, scope: 'regular' })
  }
  const existing = await dnr.getDynamicRules()
  const active = state.enabled && state.routingMode !== 'off' && policy.some(r => r.action === 'BLOCK') ? policy : []
  const addRules = active.map((rule, i): chrome.declarativeNetRequest.Rule => {
    const pattern = rule.pattern.replaceAll('.', '\\.')
    const domain = (rule.kind === 'suffix' ? '(?:[^./:]+\\.)*' : '') + pattern
    return {
      id: i + 1,
      priority: active.length - i,
      action: { type: (rule.action === 'BLOCK' ? 'block' : 'allow') as chrome.declarativeNetRequest.RuleActionType },
      condition: { regexFilter: '^(https?|wss?)://' + domain + '(?::[0-9]+)?(?:[/\\?#]|$)', resourceTypes }
    }
  })
  await dnr.updateDynamicRules({ removeRuleIds: existing.map(r => r.id), addRules })
}

async function mutate(state: BrowserState, previous: BrowserState) {
  try { await apply(state); await save(state) }
  catch (e) { await apply(previous).catch(() => {}); throw e }
}

async function sync(state: BrowserState) {
  if (state.mode !== 'agent' || !state.origin) return
  const before = structuredClone(state)
  try {
    const headers: Record<string, string> = { 'X-HomeProxy-Version': chrome.runtime.getManifest().version }
    if (state.revision) headers['If-None-Match'] = `"${state.deviceId}-${state.revision}"`
    const response = await api(state, 'config', { headers })
    if (response.status === 401) {
      const next: BrowserState = {
        ...initial,
        mode: state.mode,
        routingMode: state.routingMode,
        autoBaseRoute: state.autoBaseRoute,
        agentPort: state.agentPort,
        standaloneProxy: state.standaloneProxy,
        origin: state.origin,
        enabled: state.enabled,
        local: state.local,
        error: 'Доступ отозван. Отключите маршрут в расширении для обычного браузинга.'
      }
      if (state.enabled) await chrome.proxy.settings.set({ value: { mode: 'fixed_servers',
        rules: { singleProxy: { scheme: 'http', host: '127.0.0.1', port: 1 }, bypassList: ['<-loopback>'] } }, scope: 'regular' })
      await save(next)
      Object.assign(state, next)
      return
    }
    if (response.status !== 304) {
      if (!response.ok) throw new Error('Настройки сервера недоступны')
      const info = await response.json()
      if (info.api !== 1 || typeof info.deviceId !== 'string' || !Number.isSafeInteger(info.revision) ||
          info.revision <= state.revision || !Array.isArray(info.rules) || info.rules.length > 300 ||
          info.rules.some((r: Rule) => !r.id || !actions.has(r.action)) ||
          (state.deviceId && state.deviceId !== info.deviceId)) throw new Error('Несовместимые настройки сервера')
      const groups = Array.isArray(info.groups) ? info.groups as ServiceGroup[] : []
      Object.assign(state, { remote: info.rules, groups, revision: info.revision, deviceId: info.deviceId })
      await mutate(state, before)
    }
    state.online = true
    state.error = ''
    const ack = await api(state, 'ack', { method: 'POST', body: JSON.stringify({ revision: state.revision }) })
    if (!ack.ok) throw new Error('Сервер не подтвердил версию')
    while (state.pending.length) {
      const response = await api(state, 'personal-rules', { method: 'PUT', body: JSON.stringify(state.pending[0]) })
      if (response.status === 409) throw new Error('Конфликт персонального правила. Синхронизируйте и выберите маршрут заново.')
      if (!response.ok) throw new Error('Сервер отклонил персональное правило.')
      state.pending.shift()
      await save(state)
    }
    await save(state)
  } catch (e) {
    const persisted = await load()
    Object.assign(state, persisted, {
      online: false,
      error: e instanceof TypeError || e instanceof DOMException ? 'Сервер недоступен. Действуют сохранённые правила.' : String((e as Error).message)
    })
    await save(state)
  }
}

function validStandalone(proxy: StandaloneProxy) {
  const validSchemes = new Set<StandaloneScheme>(['http', 'https', 'socks5'])
  if (!validSchemes.has(proxy.scheme)) throw new Error('Неверный протокол прокси')
  const host = proxy.host.trim()
  if (!host || host.length > 253 || /[\s/\\@?#]/.test(host)) throw new Error('Укажите корректный адрес прокси')
  if (!Number.isInteger(proxy.port) || proxy.port < 1 || proxy.port > 65535) throw new Error('Укажите порт от 1 до 65535')
  if (proxy.password && !proxy.username.trim()) throw new Error('Укажите логин для пароля прокси')
}

function resolveSiteRoute(rule?: Rule): SiteRoute {
  if (!rule) return 'auto'
  if (rule.action === 'PROXY') return 'proxy'
  if (rule.action === 'BLOCK') return 'block'
  if (rule.action === 'LOCAL_DIRECT' || rule.action === 'SERVER_DIRECT') return 'direct'
  return 'auto'
}

async function handle(input: Incoming) {
  let state = await load()
  let agentDetected = state.mode === 'agent' ? await detectLocalAgent(state.agentPort) : false

  if (input.command === 'connect') {
    const url = new URL(input.link?.trim() ?? '')
    const loopback = url.hostname === '127.0.0.1' && url.protocol === 'http:'
    if (!(url.protocol === 'https:' || loopback) || url.pathname !== '/connect' || url.username || url.password || url.search ||
        !/^#[a-zA-Z0-9_-]{43}$/.test(url.hash)) throw new Error('Укажите персональную HTTPS-ссылку')
    const candidate: BrowserState = {
      ...initial,
      mode: 'agent',
      routingMode: state.routingMode,
      autoBaseRoute: state.autoBaseRoute,
      agentPort: state.agentPort,
      standaloneProxy: state.standaloneProxy,
      origin: url.origin,
      key: token(),
      local: state.local
    }
    const response = await api(candidate, 'connect', { method: 'POST',
      body: JSON.stringify({ token: url.hash.slice(1), deviceKey: candidate.key, transport: 'browser' }) })
    if (!response.ok) throw new Error('Ссылка просрочена, уже использована или выдана для другого клиента')
    state = candidate
    await save(state)
    await sync(state)
  } else if (input.command === 'set-mode') {
    if (input.mode !== 'agent' && input.mode !== 'standalone') throw new Error('Неверный режим')
    if (input.mode !== state.mode) {
      const previous = structuredClone(state)
      state.mode = input.mode
      state.error = ''
      agentDetected = state.mode === 'agent' ? await detectLocalAgent(state.agentPort) : false
      const ready = input.mode === 'agent'
        ? Boolean((state.key && state.revision) || agentDetected)
        : Boolean(state.standaloneProxy.host.trim() && state.standaloneProxy.port > 0)
      if (!ready) {
        state.enabled = false
        state.routingMode = 'off'
      }
      await mutate(state, previous)
    }
  } else if (input.command === 'set-routing-mode') {
    const nextRouting = input.routingMode ?? state.routingMode
    if (!['off', 'auto', 'all'].includes(nextRouting)) throw new Error('Неверный режим маршрутизации')
    const nextBase = input.autoBaseRoute ?? state.autoBaseRoute
    if (nextBase !== 'direct' && nextBase !== 'proxy') throw new Error('Неверный базовый маршрут')
    const enabling = nextRouting !== 'off'
    if (enabling) {
      if (state.mode === 'agent' && !(state.key && state.revision) && !agentDetected) {
        throw new Error('Запустите локальный ПК-агент или подключите подписку')
      }
      if (state.mode === 'standalone') {
        validStandalone(state.standaloneProxy)
      }
    }
    const previous = structuredClone(state)
    state.routingMode = nextRouting
    state.autoBaseRoute = nextBase
    state.enabled = enabling
    if (state.mode === 'standalone') {
      state.standaloneProxy.defaultDirect = nextBase === 'direct'
    }
    await mutate(state, previous)
  } else if (input.command === 'set-agent-port') {
    const port = Number(input.agentPort)
    if (!Number.isInteger(port) || port < 1024 || port > 65531) {
      throw new Error('Порт агента должен быть от 1024 до 65531')
    }
    const previous = structuredClone(state)
    state.agentPort = port
    await mutate(state, previous)
    agentDetected = state.mode === 'agent' ? await detectLocalAgent(state.agentPort) : false
  } else if (input.command === 'save-standalone') {
    const p = input.standaloneProxy
    if (!p) throw new Error('Укажите настройки прокси')
    const nextProxy: StandaloneProxy = {
      scheme: (p.scheme ?? 'https') as StandaloneScheme,
      host: String(p.host ?? '').trim(),
      port: Number(p.port ?? 0),
      username: String(p.username ?? '').trim(),
      password: p.password ? String(p.password) : (p.keepPassword ? state.standaloneProxy.password : ''),
      defaultDirect: p.defaultDirect !== undefined ? Boolean(p.defaultDirect) : state.autoBaseRoute === 'direct'
    }
    validStandalone(nextProxy)
    const previous = structuredClone(state)
    state.standaloneProxy = nextProxy
    state.autoBaseRoute = nextProxy.defaultDirect ? 'direct' : 'proxy'
    state.error = ''
    await mutate(state, previous)
  } else if (input.command === 'enable') {
    if (input.enabled) {
      if (state.mode === 'agent' && !(state.key && state.revision) && !agentDetected) {
        throw new Error('Сначала получите настройки сервера или запустите локальный агент')
      }
      if (state.mode === 'standalone') {
        validStandalone(state.standaloneProxy)
      }
    }
    const previous = structuredClone(state)
    state.enabled = Boolean(input.enabled)
    state.routingMode = state.enabled ? (state.routingMode === 'off' ? 'auto' : state.routingMode) : 'off'
    await mutate(state, previous)
  } else if (input.command === 'sync' && state.mode === 'agent' && state.key) {
    await sync(state)
  } else if (input.command === 'forget') {
    const previous = structuredClone(state)
    state = {
      ...initial,
      mode: state.mode,
      routingMode: agentDetected ? state.routingMode : 'off',
      autoBaseRoute: state.autoBaseRoute,
      enabled: agentDetected ? state.enabled : false,
      agentPort: state.agentPort,
      standaloneProxy: state.standaloneProxy,
      local: state.local
    }
    await mutate(state, previous)
  } else if (input.command === 'set-site-route') {
    const host = (input.host ?? '').toLowerCase().replace(/\.$/, '')
    if (!validDomain(host)) throw new Error('Некорректный домен')
    const routeChoice = input.siteRoute
    if (!routeChoice || !['auto', 'proxy', 'direct', 'block'].includes(routeChoice)) {
      throw new Error('Неверный маршрут сайта')
    }
    const previous = structuredClone(state)
    const mappedAction: Action = routeChoice === 'proxy' ? 'PROXY'
      : routeChoice === 'direct' ? 'LOCAL_DIRECT'
        : routeChoice === 'block' ? 'BLOCK'
          : 'INHERIT'
    state.local = state.local.filter(r => r.pattern !== host)
    if (mappedAction !== 'INHERIT') {
      state.local.push({ kind: 'domain', pattern: host, action: mappedAction, enabled: true })
    }
    await mutate(state, previous)
  } else if (input.command === 'rule') {
    const { action, scope, domains, includeSubdomains } = input
    if (!action || !actions.has(action) || !domains?.length || domains.length > 60 || domains.some(d => !validDomain(d))) {
      throw new Error('Укажите корректные домены и маршрут')
    }
    const previous = structuredClone(state)
    const effectiveScope = state.mode === 'standalone' ? 'LOCAL' : scope
    for (const pattern of domains) {
      const kind = includeSubdomains ? 'suffix' : 'domain'
      const rule: Rule = { kind, pattern, action, enabled: true }
      if (effectiveScope === 'PERSONAL') {
        if (!state.key) throw new Error('Сначала подключите подписку в настройках')
        rule.revision = state.remote.find(r => r.userId && r.pattern === pattern && r.kind === kind)?.revision ?? 0
        state.pending = state.pending.filter(r => r.pattern !== pattern || r.kind !== kind)
        state.pending.push(rule)
      } else {
        state.local = state.local.filter(r => r.pattern !== pattern || r.kind !== kind)
        if (action !== 'INHERIT') state.local.push(rule)
      }
    }
    if (state.local.length > 300 || state.pending.length > 100) throw new Error('Достигнут предел локальных правил или очереди')
    await mutate(state, previous)
    if (effectiveScope === 'PERSONAL') await sync(state)
  } else if (input.command === 'cycle-local-rule') {
    const previous = structuredClone(state)
    const rule = state.local.find(r => r.kind === input.kind && r.pattern === input.pattern)
    if (rule) {
      const order: Action[] = ['PROXY', 'LOCAL_DIRECT', 'BLOCK']
      const idx = order.indexOf(rule.action)
      rule.action = order[(idx + 1) % order.length]
      await mutate(state, previous)
    }
  } else if (input.command === 'toggle-local-rule') {
    const previous = structuredClone(state)
    const rule = state.local.find(r => r.kind === input.kind && r.pattern === input.pattern)
    if (rule) {
      rule.enabled = rule.enabled === false
      await mutate(state, previous)
    }
  } else if (input.command === 'delete-local-rule') {
    const previous = structuredClone(state)
    state.local = state.local.filter(r => !(r.kind === input.kind && r.pattern === input.pattern))
    await mutate(state, previous)
  } else if (input.command === 'status' && state.enabled && (state.mode === 'standalone' || state.key || agentDetected)) {
    const settings = await chrome.proxy.settings.get({ incognito: false })
    if (settings.levelOfControl !== 'controlled_by_this_extension') state.error = 'Прокси контролируется другим расширением или политикой браузера'
  }

  const current = orderedForState(state).find(rule => matchesRule(rule, input.host ?? ''))
  const cachedUpdate = await readUpdateCache()
  const currentVersion = chrome.runtime.getManifest().version
  const updateAvailable = cachedUpdate?.latestVersion && compareVersions(cachedUpdate.latestVersion, currentVersion) > 0
    ? { version: cachedUpdate.latestVersion, url: cachedUpdate.releaseUrl || RELEASE_PAGE_URL }
    : null
  return {
    mode: state.mode,
    routingMode: state.routingMode,
    autoBaseRoute: state.autoBaseRoute,
    agentDetected,
    agentPort: state.agentPort,
    standaloneProxy: {
      scheme: state.standaloneProxy.scheme,
      host: state.standaloneProxy.host,
      port: state.standaloneProxy.port,
      username: state.standaloneProxy.username,
      hasPassword: Boolean(state.standaloneProxy.password),
      defaultDirect: state.standaloneProxy.defaultDirect
    },
    linked: Boolean(state.key),
    enabled: state.enabled,
    online: state.online,
    revision: state.revision,
    pending: state.pending.length,
    error: state.error,
    rule: current,
    siteRoute: resolveSiteRoute(current),
    localRules: state.local,
    resources: [...(observed.get(input.tabId ?? -1)?.values() ?? [])],
    updateAvailable
  }
}

function serialize(work: () => Promise<unknown>) {
  const running = queue.then(work)
  queue = running.then(() => {}, () => {})
  return running
}

chrome.runtime.onMessage.addListener((input: Incoming, sender, respond) => {
  if (sender.id !== chrome.runtime.id || !sender.url?.startsWith(chrome.runtime.getURL('popup.html'))) return false
  void serialize(() => handle(input)).then(value => respond({ value }), e => respond({ error: e instanceof Error ? e.message : 'Ошибка расширения' }))
  return true
})
chrome.runtime.onInstalled.addListener(() => {
  void storage.setAccessLevel({ accessLevel: 'TRUSTED_CONTEXTS' })
  void chrome.alarms.create('sync', { periodInMinutes: 1 })
  void load()
  void checkExtensionUpdate()
})
chrome.runtime.onStartup.addListener(() => {
  void chrome.alarms.create('sync', { periodInMinutes: 1 })
  void load()
  void checkExtensionUpdate()
})
chrome.alarms.onAlarm.addListener(alarm => {
  if (alarm.name === 'sync') {
    void serialize(() => handle({ command: 'sync' }))
    void checkExtensionUpdate()
  }
})

function observe(info: { tabId: number; url: string; type: string }, failed: boolean) {
  if (info.tabId < 0) return
  const domain = new URL(info.url).hostname.toLowerCase().replace(/\.$/, '')
  let forTab = observed.get(info.tabId)
  if (!forTab || info.type === 'main_frame' && !failed) {
    if (observed.size >= 64) observed.delete(observed.keys().next().value!)
    forTab = new Map()
    observed.set(info.tabId, forTab)
  }
  const entry = forTab.get(domain)
  if (entry) {
    entry.failed ||= failed
    if (!entry.types.includes(info.type)) entry.types.push(info.type)
  } else if (forTab.size < 80) {
    forTab.set(domain, { domain, failed, types: [info.type] })
  }
}
const filter = { urls: ['http://*/*', 'https://*/*'] }
chrome.webRequest.onBeforeRequest.addListener(info => { observe(info, false); return undefined }, filter)
chrome.webRequest.onErrorOccurred.addListener(info => observe(info, true), filter)
chrome.webRequest.onCompleted.addListener(info => { retriedAuth.delete(info.requestId) }, filter)
chrome.webRequest.onAuthRequired.addListener(
  (details, callback) => {
    if (!details.isProxy) {
      callback?.({})
      return
    }
    void load().then(state => {
      if (!state.enabled || state.mode !== 'standalone' || !state.standaloneProxy.username || retriedAuth.has(details.requestId)) {
        callback?.({})
        return
      }
      if (retriedAuth.size > 100) retriedAuth.clear()
      retriedAuth.add(details.requestId)
      callback?.({
        authCredentials: {
          username: state.standaloneProxy.username,
          password: state.standaloneProxy.password
        }
      })
    }).catch(() => callback?.({}))
  },
  filter,
  ['asyncBlocking']
)
chrome.tabs.onRemoved.addListener(id => observed.delete(id))
