import type { AutoBaseRoute, RoutingMode, Rule } from '../../packages/shared/models'
import type { Observed, SiteRoute } from './background'
import type { ExtensionMode, StandaloneScheme } from './pac'

const get = <T extends HTMLElement>(id: string) => document.getElementById(id) as T
const notice = get<HTMLParagraphElement>('notice')
const updateBanner = get<HTMLParagraphElement>('update-banner')
const link = get<HTMLInputElement>('link')
const settingsLink = get<HTMLInputElement>('settings-link')

const elements = {
  status: get('status'),
  statusText: get('status-text'),
  viewToggle: get<HTMLButtonElement>('view-toggle'),
  viewHome: get('view-home'),
  viewSettings: get('view-settings'),
  rmOff: get<HTMLButtonElement>('rm-off'),
  rmAuto: get<HTMLButtonElement>('rm-auto'),
  rmAll: get<HTMLButtonElement>('rm-all'),
  baseRouteBar: get('base-route-bar'),
  baseDirect: get<HTMLButtonElement>('base-direct'),
  baseProxy: get<HTMLButtonElement>('base-proxy'),
  connect: get<HTMLFormElement>('connect'),
  route: get('route'),
  domain: get('domain'),
  modePill: get('mode-pill'),
  srAuto: get<HTMLButtonElement>('sr-auto'),
  srProxy: get<HTMLButtonElement>('sr-proxy'),
  srDirect: get<HTMLButtonElement>('sr-direct'),
  srBlock: get<HTMLButtonElement>('sr-block'),
  quickSite: get<HTMLButtonElement>('quick-site'),
  modeAgent: get<HTMLButtonElement>('mode-agent'),
  modeStandalone: get<HTMLButtonElement>('mode-standalone'),
  agentPanel: get('agent-panel'),
  agentStateLine: get('agent-state-line'),
  agentStateText: get('agent-state-text'),
  portForm: get<HTMLFormElement>('port-form'),
  agentPort: get<HTMLInputElement>('agent-port'),
  sync: get<HTMLButtonElement>('sync'),
  forget: get<HTMLButtonElement>('forget'),
  settingsConnect: get<HTMLFormElement>('settings-connect'),
  standalonePanel: get('standalone-panel'),
  saForm: get<HTMLFormElement>('sa-form'),
  saScheme: get<HTMLSelectElement>('sa-scheme'),
  saHost: get<HTMLInputElement>('sa-host'),
  saPort: get<HTMLInputElement>('sa-port'),
  saUser: get<HTMLInputElement>('sa-user'),
  saPass: get<HTMLInputElement>('sa-pass'),
  saPassToggle: get<HTMLButtonElement>('sa-pass-toggle'),
  localCount: get('local-count'),
  localRules: get('local-rules')
}

type Status = {
  mode: ExtensionMode
  routingMode: RoutingMode
  autoBaseRoute: AutoBaseRoute
  agentDetected: boolean
  agentPort: number
  standaloneProxy: {
    scheme: StandaloneScheme
    host: string
    port: number
    username: string
    hasPassword: boolean
    defaultDirect: boolean
  }
  linked: boolean
  enabled: boolean
  online: boolean
  revision: number
  pending: number
  error: string
  rule?: Rule
  siteRoute: SiteRoute
  localRules: Rule[]
  resources: Observed[]
  updateAvailable?: { version: string; url: string } | null
}

let current: Status | undefined
let tabId: number | undefined
let host: string | undefined
let view: 'home' | 'settings' = 'home'
let showPass = false
let busy = false

function alertMsg(message: string) {
  notice.textContent = message
  notice.hidden = !message
}

function setStatusBadge(kind: 'online' | 'offline', label: string) {
  elements.status.className = 'signal-bars ' + kind
  const icon = elements.status.firstElementChild as HTMLElement
  if (kind === 'online') {
    icon.className = 'signal-bars-graph'
    icon.replaceChildren(document.createElement('span'), document.createElement('span'), document.createElement('span'))
  } else {
    icon.className = 'signal-dot'
    icon.replaceChildren()
  }
  elements.statusText.textContent = label
}

function routeBtnLabel(r: Rule): string {
  if (r.action === 'BLOCK') return 'Блок'
  if (r.action === 'LOCAL_DIRECT' || r.action === 'SERVER_DIRECT') return 'Прямой'
  return 'Прокси'
}

function render(state: Status) {
  current = state
  const isAgent = state.mode === 'agent'

  elements.viewHome.hidden = view !== 'home'
  elements.viewSettings.hidden = view !== 'settings'
  elements.viewToggle.textContent = view === 'home' ? '⚙' : '←'
  elements.viewToggle.title = view === 'home' ? 'Настройки' : 'Назад'

  if (!state.enabled || state.routingMode === 'off') {
    setStatusBadge('offline', 'Выкл')
  } else if (isAgent) {
    setStatusBadge('online', state.online ? 'Онлайн' : state.agentDetected ? 'Агент' : 'Автономно')
  } else {
    setStatusBadge('online', 'Автономно')
  }

  // Routing mode switcher
  elements.rmOff.className = state.routingMode === 'off' ? 'active-muted' : ''
  elements.rmAuto.className = state.routingMode === 'auto' ? 'active' : ''
  elements.rmAll.className = state.routingMode === 'all' ? 'active' : ''
  elements.baseRouteBar.hidden = state.routingMode !== 'auto'
  elements.baseDirect.className = state.autoBaseRoute === 'direct' ? 'active-muted' : ''
  elements.baseProxy.className = state.autoBaseRoute === 'proxy' ? 'active-soft' : ''

  const agentReady = state.linked || state.agentDetected
  const standaloneReady = Boolean(state.standaloneProxy.host)

  elements.connect.hidden = !isAgent || agentReady
  elements.route.hidden = !host || (isAgent ? !agentReady : !standaloneReady)
  if (host) elements.domain.textContent = host
  elements.modePill.textContent = isAgent ? 'Агент' : 'Автономно'

  elements.srAuto.className = state.siteRoute === 'auto' ? 'active' : ''
  elements.srProxy.className = state.siteRoute === 'proxy' ? 'active' : ''
  elements.srDirect.className = state.siteRoute === 'direct' ? 'active' : ''
  elements.srBlock.className = state.siteRoute === 'block' ? 'sr-block-active' : ''

  const subResources = state.resources.filter(item => item.domain !== host)
  elements.quickSite.textContent = `Весь сайт + внешние (${subResources.length})`

  // Settings screen
  elements.modeAgent.className = isAgent ? 'active' : ''
  elements.modeStandalone.className = !isAgent ? 'active' : ''
  elements.agentPanel.hidden = !isAgent
  elements.standalonePanel.hidden = isAgent

  elements.agentStateLine.className = 'agent-state' + (state.agentDetected || state.linked ? ' ready' : '')
  elements.agentStateText.textContent = state.agentDetected
    ? 'ПК-агент подключён автоматически'
    : state.linked
      ? `Подписка активна · v${state.revision}`
      : 'ПК-агент не обнаружен — укажите порт или ссылку'
  elements.agentPort.value = String(state.agentPort || 17770)
  elements.sync.hidden = !state.linked
  elements.forget.hidden = !state.linked
  elements.settingsConnect.hidden = state.linked

  elements.saScheme.value = state.standaloneProxy.scheme
  elements.saHost.value = state.standaloneProxy.host
  elements.saPort.value = String(state.standaloneProxy.port || 8443)
  elements.saUser.value = state.standaloneProxy.username
  elements.saPass.value = ''
  elements.saPass.type = showPass ? 'text' : 'password'
  elements.saPass.placeholder = state.standaloneProxy.hasPassword ? 'Сохранён (оставьте пустым)' : 'Пароль прокси'
  elements.saPassToggle.textContent = showPass ? '🙈' : '👁'

  elements.localCount.textContent = String(state.localRules.length)
  elements.localRules.replaceChildren(...state.localRules.map(rule => {
    const row = document.createElement('div')
    row.className = 'between local-rule-item'

    const domainEl = document.createElement('span')
    domainEl.className = 'mono rule-domain' + (rule.enabled === false ? ' off' : '')
    domainEl.textContent = (rule.kind === 'suffix' ? '*.' : '') + rule.pattern

    const actionsBox = document.createElement('div')
    actionsBox.className = 'flex'

    const routeBtn = document.createElement('button')
    routeBtn.type = 'button'
    routeBtn.className = 'route-chip'
    routeBtn.textContent = routeBtnLabel(rule)
    routeBtn.addEventListener('click', () => void send('cycle-local-rule', { kind: rule.kind, pattern: rule.pattern }))

    const toggleBtn = document.createElement('button')
    toggleBtn.type = 'button'
    toggleBtn.className = 'hp-toggle'
    toggleBtn.setAttribute('role', 'switch')
    toggleBtn.setAttribute('aria-checked', String(rule.enabled !== false))
    const thumb = document.createElement('span')
    thumb.className = 'hp-toggle-thumb'
    toggleBtn.append(thumb)
    toggleBtn.addEventListener('click', () => void send('toggle-local-rule', { kind: rule.kind, pattern: rule.pattern }))

    const delBtn = document.createElement('button')
    delBtn.type = 'button'
    delBtn.className = 'x-del'
    delBtn.textContent = '×'
    delBtn.ariaLabel = 'Удалить ' + rule.pattern
    delBtn.addEventListener('click', () => void send('delete-local-rule', { kind: rule.kind, pattern: rule.pattern }))

    actionsBox.append(routeBtn, toggleBtn, delBtn)
    row.append(domainEl, actionsBox)
    return row
  }))

  alertMsg(state.error || (isAgent && state.pending ? 'Ожидают отправки: ' + state.pending : ''))
  if (state.updateAvailable) {
    const linkEl = document.createElement('a')
    linkEl.href = state.updateAvailable.url
    linkEl.target = '_blank'
    linkEl.rel = 'noopener noreferrer'
    linkEl.textContent = 'Скачать на GitHub'
    updateBanner.replaceChildren(`Доступна новая версия v${state.updateAvailable.version} · `, linkEl)
    updateBanner.hidden = false
  } else {
    updateBanner.hidden = true
  }
}

async function send(command: string, values: Record<string, unknown> = {}) {
  if (busy) return
  busy = true
  const buttons = [...document.querySelectorAll('button')]
  buttons.forEach(button => button.disabled = true)
  try {
    const result = await chrome.runtime.sendMessage({ command, tabId, host, ...values })
    if (!result || result.error) throw new Error(result?.error ?? 'Нет ответа от расширения')
    if (command === 'connect') {
      link.value = ''
      settingsLink.value = ''
    }
    render(result.value)
  } catch (e) {
    alertMsg(e instanceof Error ? e.message : 'Ошибка расширения')
  } finally {
    busy = false
    buttons.forEach(button => button.disabled = false)
  }
}

elements.viewToggle.addEventListener('click', () => {
  view = view === 'home' ? 'settings' : 'home'
  if (current) render(current)
})

elements.rmOff.addEventListener('click', () => void send('set-routing-mode', { routingMode: 'off' }))
elements.rmAuto.addEventListener('click', () => void send('set-routing-mode', { routingMode: 'auto' }))
elements.rmAll.addEventListener('click', () => void send('set-routing-mode', { routingMode: 'all' }))
elements.baseDirect.addEventListener('click', () => void send('set-routing-mode', { routingMode: 'auto', autoBaseRoute: 'direct' }))
elements.baseProxy.addEventListener('click', () => void send('set-routing-mode', { routingMode: 'auto', autoBaseRoute: 'proxy' }))

elements.srAuto.addEventListener('click', () => void send('set-site-route', { siteRoute: 'auto' }))
elements.srProxy.addEventListener('click', () => void send('set-site-route', { siteRoute: 'proxy' }))
elements.srDirect.addEventListener('click', () => void send('set-site-route', { siteRoute: 'direct' }))
elements.srBlock.addEventListener('click', () => void send('set-site-route', { siteRoute: 'block' }))

elements.quickSite.addEventListener('click', () => {
  if (!host) return
  const all = [host, ...(current?.resources.map(r => r.domain).filter(d => d !== host) ?? [])].slice(0, 60)
  void send('rule', { action: 'PROXY', scope: 'LOCAL', domains: all, includeSubdomains: true })
})

elements.connect.addEventListener('submit', e => {
  e.preventDefault()
  void send('connect', { link: link.value })
})
elements.settingsConnect.addEventListener('submit', e => {
  e.preventDefault()
  void send('connect', { link: settingsLink.value })
})

elements.modeAgent.addEventListener('click', () => void send('set-mode', { mode: 'agent' }))
elements.modeStandalone.addEventListener('click', () => void send('set-mode', { mode: 'standalone' }))
elements.portForm.addEventListener('submit', e => {
  e.preventDefault()
  void send('set-agent-port', { agentPort: Number(elements.agentPort.value) })
})
elements.sync.addEventListener('click', () => void send('sync'))
elements.forget.addEventListener('click', () => {
  if (confirm('Отвязать подписку от расширения?')) void send('forget')
})

elements.saPassToggle.addEventListener('click', () => {
  showPass = !showPass
  elements.saPass.type = showPass ? 'text' : 'password'
  elements.saPassToggle.textContent = showPass ? '🙈' : '👁'
})

elements.saForm.addEventListener('submit', e => {
  e.preventDefault()
  void send('save-standalone', {
    standaloneProxy: {
      scheme: elements.saScheme.value,
      host: elements.saHost.value,
      port: Number(elements.saPort.value),
      username: elements.saUser.value,
      password: elements.saPass.value,
      keepPassword: Boolean(current?.standaloneProxy.hasPassword && !elements.saPass.value),
      defaultDirect: current ? current.autoBaseRoute === 'direct' : true
    }
  })
})

void chrome.tabs.query({ active: true, currentWindow: true }).then(([tab]) => {
  tabId = tab?.id
  return tab?.url
}).then(value => {
  const url = value && new URL(value)
  if (url && (url.protocol === 'http:' || url.protocol === 'https:')) host = url.hostname.toLowerCase().replace(/\.$/, '')
  return send('status')
}).catch(() => send('status'))
