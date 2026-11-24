import type { Action, Rule } from '../../packages/shared/models'

export type Observed = { domain: string; failed: boolean; types: string[] }
type BrowserState = {
  origin: string; key: string; deviceId: string; revision: number; enabled: boolean; online: boolean;
  local: Rule[]; remote: Rule[]; pending: Rule[]; error: string;
}
type Incoming = { command: string; link?: string; tabId?: number; host?: string; enabled?: boolean; action?: Action;
  scope?: 'LOCAL' | 'PERSONAL'; domains?: string[]; includeSubdomains?: boolean }
const actions = new Set<Action>(['PROXY', 'AUTO', 'LOCAL_DIRECT', 'SERVER_DIRECT', 'BLOCK', 'INHERIT'])
const resourceTypes = [
  'main_frame', 'sub_frame', 'stylesheet', 'script', 'image', 'font', 'object',
  'xmlhttprequest', 'ping', 'csp_report', 'media', 'websocket', 'webtransport', 'webbundle', 'other'
] as chrome.declarativeNetRequest.ResourceType[]

const initial: BrowserState = { origin: '', key: '', deviceId: '', revision: 0, enabled: false,
  online: false, local: [], remote: [], pending: [], error: '' }
const storage = chrome.storage.local
const dnr = chrome.declarativeNetRequest
let queue = Promise.resolve()
const observed = new Map<number, Map<string, Observed>>()

function validDomain(value: string) {
  return value.length <= 253 && value.split('.').every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))
}
const order = (rule: Rule) => rule.locked ? 0 : !rule.id ? 1 : rule.userId ? 2 : 3
function ordered(state: BrowserState) {
  return [...state.remote, ...state.local].filter(r => r.action !== 'INHERIT' && validDomain(r.pattern) && (r.kind === 'domain' || r.kind === 'suffix'))
    .sort((a, b) => order(a) - order(b) || Number(a.kind === 'suffix') - Number(b.kind === 'suffix') || b.pattern.length - a.pattern.length)
}
const matches = (rule: Rule, domain: string) => domain === rule.pattern || rule.kind === 'suffix' && domain.endsWith('.' + rule.pattern)

function token() {
  const bytes = crypto.getRandomValues(new Uint8Array(32))
  return btoa(String.fromCharCode(...bytes)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')
}

async function load(): Promise<BrowserState> {
  const stored = (await storage.get('state')).state
  return { ...initial, ...stored as Partial<BrowserState> }
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

async function apply(state: BrowserState) {
  const policy = ordered(state)
  if (!state.enabled) {
    await chrome.proxy.settings.clear({ scope: 'regular' })
  } else {
    const settings = await chrome.proxy.settings.get({ incognito: false })
    if (!['controllable_by_this_extension', 'controlled_by_this_extension'].includes(settings.levelOfControl)) {
      throw new Error('Другой профиль или расширение управляет настройками прокси')
    }
    const values = policy.map(r => [r.pattern, r.kind === 'suffix', r.action])
    const origin = new URL(state.origin)
    const authority = origin.host
    const script = `
function FindProxyForURL(url, host) {
  host = host.toLowerCase().replace(/\\.$/, '');
  if (url.split('/')[2] === ${JSON.stringify(authority)}) return 'DIRECT';
  var rules = ${JSON.stringify(values)};
  var ports = {PROXY:17772, LOCAL_DIRECT:17773, SERVER_DIRECT:17774, AUTO:17770, BLOCK:1};
  for (var i = 0; i < rules.length; i++) {
    var rule = rules[i], suffix = '.' + rule[0];
    if (host === rule[0] || (rule[1] && host.slice(-suffix.length) === suffix))
      return 'PROXY 127.0.0.1:' + ports[rule[2]];
  }
  return 'PROXY 127.0.0.1:17770';
}`
    await chrome.proxy.settings.set({ value: { mode: 'pac_script', pacScript: { data: script, mandatory: true } }, scope: 'regular' })
  }
  const existing = await dnr.getDynamicRules()
  const active = state.enabled && policy.some(r => r.action === 'BLOCK') ? policy : []
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
  if (!state.origin) return
  // Deep copy because queued edits and refreshed policies are mutated in place.
  const before = structuredClone(state)
  try {
    const headers: Record<string, string> = { 'X-HomeProxy-Version': chrome.runtime.getManifest().version }
    if (state.revision) headers['If-None-Match'] = `"${state.deviceId}-${state.revision}"`
    const response = await api(state, 'config', { headers })
    if (response.status === 401) {
      // Keep the mandatory proxy fail-closed until the user turns it off.
      const next = { ...initial, origin: state.origin, enabled: state.enabled, local: state.local, error: 'Доступ отозван. Отключите маршрут в расширении для обычного браузинга.' }
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
      Object.assign(state, { remote: info.rules, revision: info.revision, deviceId: info.deviceId })
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

async function handle(input: Incoming) {
  let state = await load()
  if (input.command === 'connect') {
    const url = new URL(input.link?.trim() ?? '')
    const loopback = url.hostname === '127.0.0.1' && url.protocol === 'http:'
    if (!(url.protocol === 'https:' || loopback) || url.pathname !== '/connect' || url.username || url.password || url.search ||
        !/^#[a-zA-Z0-9_-]{43}$/.test(url.hash)) throw new Error('Укажите персональную HTTPS-ссылку')
    const candidate = { ...initial, origin: url.origin, key: token(), local: state.local }
    const response = await api(candidate, 'connect', { method: 'POST',
      body: JSON.stringify({ token: url.hash.slice(1), deviceKey: candidate.key, transport: 'browser' }) })
    if (!response.ok) throw new Error('Ссылка просрочена, уже использована или выдана для другого клиента')
    state = candidate
    await save(state)
    await sync(state)
  } else if (input.command === 'enable') {
    if (input.enabled && (!state.key || !state.revision)) throw new Error('Сначала получите настройки сервера')
    const previous = structuredClone(state)
    state.enabled = Boolean(input.enabled)
    await mutate(state, previous)
  } else if (input.command === 'sync' && state.key) {
    await sync(state)
  } else if (input.command === 'forget') {
    const previous = structuredClone(state)
    state = { ...initial, local: state.local }
    await mutate(state, previous)
  } else if (input.command === 'rule') {
    const { action, scope, domains, includeSubdomains } = input
    if (!action || !actions.has(action) || !domains?.length || domains.length > 20 || domains.some(d => !validDomain(d))) {
      throw new Error('Укажите корректные домены и маршрут')
    }
    const previous = structuredClone(state)
    for (const pattern of domains) {
      const kind = includeSubdomains ? 'suffix' : 'domain'
      const rule: Rule = { kind, pattern, action }
      if (scope === 'PERSONAL') {
        if (!state.key) throw new Error('Сначала подключите расширение')
        rule.revision = state.remote.find(r => r.userId && r.pattern === pattern && r.kind === kind)?.revision ?? 0
        state.pending = state.pending.filter(r => r.pattern !== pattern || r.kind !== kind)
        state.pending.push(rule)
      } else {
        state.local = state.local.filter(r => r.pattern !== pattern || r.kind !== kind)
        if (action !== 'INHERIT') state.local.push(rule)
      }
    }
    if (state.local.length > 200 || state.pending.length > 100) throw new Error('Достигнут предел локальных правил или очереди')
    await mutate(state, previous)
    if (scope === 'PERSONAL') await sync(state)
  } else if (input.command === 'status' && state.enabled && state.key) {
    const settings = await chrome.proxy.settings.get({ incognito: false })
    if (settings.levelOfControl !== 'controlled_by_this_extension') state.error = 'Прокси контролируется другим расширением или политикой браузера'
  }
  const current = ordered(state).find(rule => matches(rule, input.host ?? ''))
  return { linked: Boolean(state.key), enabled: state.enabled, online: state.online, revision: state.revision,
    pending: state.pending.length, error: state.error, rule: current, resources: [...(observed.get(input.tabId ?? -1)?.values() ?? [])] }
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
})
chrome.runtime.onStartup.addListener(() => { void chrome.alarms.create('sync', { periodInMinutes: 1 }) })
chrome.alarms.onAlarm.addListener(alarm => {
  if (alarm.name === 'sync') void serialize(() => handle({ command: 'sync' }))
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
chrome.tabs.onRemoved.addListener(id => observed.delete(id))
