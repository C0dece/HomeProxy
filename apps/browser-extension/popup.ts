import { actionNames, scopeOf } from '../../packages/shared/models'
import type { Rule } from '../../packages/shared/models'
import type { Observed } from './background'
import type { ExtensionMode, StandaloneScheme } from './pac'

const get = <T extends HTMLElement>(id: string) => document.getElementById(id) as T
const notice = get<HTMLParagraphElement>('notice')
const updateBanner = get<HTMLParagraphElement>('update-banner')
const link = get<HTMLInputElement>('link')
const elements = {
  status: get('status'),
  modeAgent: get<HTMLButtonElement>('mode-agent'),
  modeStandalone: get<HTMLButtonElement>('mode-standalone'),
  domain: get('domain'),
  revision: get('revision'),
  current: get('current'),
  quickSingle: get<HTMLButtonElement>('quick-single'),
  quickSite: get<HTMLButtonElement>('quick-site'),
  toggle: get<HTMLButtonElement>('toggle'),
  sync: get<HTMLButtonElement>('sync'),
  forget: get<HTMLButtonElement>('forget'),
  connect: get<HTMLFormElement>('connect'),
  route: get('route'),
  agent: get('agent'),
  portForm: get<HTMLFormElement>('port-form'),
  agentPort: get<HTMLInputElement>('agent-port'),
  scopeWrap: get('scope-wrap'),
  scope: get<HTMLSelectElement>('scope'),
  action: get<HTMLSelectElement>('action'),
  resources: get('resources'),
  count: get('count'),
  save: get<HTMLButtonElement>('save'),
  subdomains: get<HTMLInputElement>('subdomains'),
  standalone: get('standalone'),
  saForm: get<HTMLFormElement>('sa-form'),
  saScheme: get<HTMLSelectElement>('sa-scheme'),
  saHost: get<HTMLInputElement>('sa-host'),
  saPort: get<HTMLInputElement>('sa-port'),
  saUser: get<HTMLInputElement>('sa-user'),
  saPass: get<HTMLInputElement>('sa-pass'),
  saDefault: get<HTMLSelectElement>('sa-default'),
  saToggle: get<HTMLButtonElement>('sa-toggle'),
  localCount: get('local-count'),
  localRules: get('local-rules')
}

type Status = {
  mode: ExtensionMode
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
  localRules: Rule[]
  resources: Observed[]
  updateAvailable?: { version: string; url: string } | null
}
let current: Status | undefined
let tabId: number | undefined
let host: string | undefined
let busy = false

function alert(message: string) {
  notice.textContent = message
  notice.hidden = !message
}

function render(state: Status) {
  current = state
  const isAgent = state.mode === 'agent'
  elements.modeAgent.classList.toggle('current', isAgent)
  elements.modeStandalone.classList.toggle('current', !isAgent)

  elements.status.className = 'badge ' + (state.enabled
    ? (isAgent ? (state.online ? 'ok' : 'wait') : 'ok')
    : '')
  elements.status.textContent = state.enabled
    ? (isAgent ? (state.online ? 'Активно' : 'Автономно') : 'Автономный прокси')
    : 'Выключено'

  const standaloneReady = Boolean(state.standaloneProxy.host)
  elements.connect.hidden = !isAgent || state.linked || state.enabled
  elements.route.hidden = !host || (isAgent ? !state.linked : !standaloneReady)
  elements.agent.hidden = !isAgent || (!state.linked && !state.enabled)
  elements.standalone.hidden = isAgent
  elements.sync.hidden = !state.linked
  elements.scopeWrap.hidden = !isAgent
  if (!isAgent) elements.scope.value = 'LOCAL'

  elements.agentPort.value = String(state.agentPort || 17770)
  elements.saScheme.value = state.standaloneProxy.scheme
  elements.saHost.value = state.standaloneProxy.host
  elements.saPort.value = String(state.standaloneProxy.port || 8080)
  elements.saUser.value = state.standaloneProxy.username
  elements.saPass.value = ''
  elements.saPass.placeholder = state.standaloneProxy.hasPassword ? 'Сохранён (оставьте пустым)' : 'Опционально'
  elements.saDefault.value = state.standaloneProxy.defaultDirect ? 'direct' : 'proxy'
  elements.saToggle.textContent = state.enabled ? 'Выключить маршрутизацию' : 'Включить маршрутизацию'
  elements.saToggle.disabled = !standaloneReady && !state.enabled

  if (host) elements.domain.textContent = host
  elements.revision.textContent = isAgent && state.revision ? 'v' + state.revision : ''
  elements.current.textContent = state.rule
    ? actionNames[state.rule.action] + ' · ' + scopeOf(state.rule)
    : isAgent
      ? 'Автоматически · Профиль агента'
      : (state.standaloneProxy.defaultDirect ? 'По умолчанию · Напрямую' : 'По умолчанию · Через прокси')
  elements.toggle.textContent = state.enabled ? 'Выключить маршрутизацию' : 'Включить маршрутизацию'

  const previous = new Set([...elements.resources.querySelectorAll<HTMLInputElement>('input:checked')].map(input => input.value))
  const resources = state.resources.filter(item => item.domain !== host)
  elements.quickSite.textContent = `Весь сайт + внешние (${resources.length})`
  elements.resources.replaceChildren(...resources.map(item => {
    const label = document.createElement('label')
    label.className = 'check'
    const check = document.createElement('input')
    check.type = 'checkbox'; check.value = item.domain; check.checked = previous.has(item.domain)
    const text = document.createElement('span')
    text.textContent = item.domain + (item.failed ? ' · ошибка запроса' : '')
    label.append(check, text)
    return label
  }))
  elements.count.textContent = String(resources.length)

  elements.localCount.textContent = String(state.localRules.length)
  elements.localRules.replaceChildren(...state.localRules.map(rule => {
    const row = document.createElement('div')
    row.className = 'between local-rule-item'
    const info = document.createElement('div')
    info.className = 'card-head'
    const pat = document.createElement('span')
    pat.className = 'mono'
    pat.textContent = (rule.kind === 'suffix' ? '*.' : '') + rule.pattern
    const meta = document.createElement('small')
    meta.className = 'muted'
    meta.textContent = actionNames[rule.action] + (rule.enabled === false ? ' · выключено' : '')
    info.append(pat, meta)

    const actionsBox = document.createElement('div')
    actionsBox.className = 'flex'
    const toggleBtn = document.createElement('button')
    toggleBtn.type = 'button'
    toggleBtn.className = 'small'
    toggleBtn.textContent = rule.enabled === false ? 'Выкл' : 'Вкл'
    toggleBtn.addEventListener('click', () => void send('toggle-local-rule', { kind: rule.kind, pattern: rule.pattern }))
    const delBtn = document.createElement('button')
    delBtn.type = 'button'
    delBtn.className = 'small ghost danger'
    delBtn.textContent = '×'
    delBtn.ariaLabel = 'Удалить ' + rule.pattern
    delBtn.addEventListener('click', () => void send('delete-local-rule', { kind: rule.kind, pattern: rule.pattern }))
    actionsBox.append(toggleBtn, delBtn)
    row.append(info, actionsBox)
    return row
  }))

  alert(state.error || (isAgent && state.pending ? 'Ожидают отправки: ' + state.pending : ''))
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
    if (command === 'connect') link.value = ''
    render(result.value)
  } catch (e) {
    alert(e instanceof Error ? e.message : 'Ошибка расширения')
  } finally {
    busy = false
    buttons.forEach(button => button.disabled = false)
    if (current) {
      elements.saToggle.disabled = !current.standaloneProxy.host && !current.enabled
    }
  }
}

elements.modeAgent.addEventListener('click', () => void send('set-mode', { mode: 'agent' }))
elements.modeStandalone.addEventListener('click', () => void send('set-mode', { mode: 'standalone' }))
elements.connect.addEventListener('submit', e => { e.preventDefault(); void send('connect', { link: link.value }) })
elements.portForm.addEventListener('submit', e => { e.preventDefault(); void send('set-agent-port', { agentPort: Number(elements.agentPort.value) }) })
elements.toggle.addEventListener('click', () => void send('enable', { enabled: !current?.enabled }))
elements.sync.addEventListener('click', () => void send('sync'))
elements.forget.addEventListener('click', () => { if (confirm('Отвязать браузер и освободить его настройки прокси?')) void send('forget') })

elements.quickSingle.addEventListener('click', () => {
  if (!host) return
  const scope = current?.mode === 'standalone' ? 'LOCAL' : elements.scope.value
  void send('rule', { action: 'PROXY', scope, domains: [host], includeSubdomains: false })
})
elements.quickSite.addEventListener('click', () => {
  if (!host) return
  const scope = current?.mode === 'standalone' ? 'LOCAL' : elements.scope.value
  const all = [host, ...(current?.resources.map(r => r.domain).filter(d => d !== host) ?? [])].slice(0, 60)
  void send('rule', { action: 'PROXY', scope, domains: all, includeSubdomains: true })
})
elements.save.addEventListener('click', () => {
  const domains = [host, ...[...elements.resources.querySelectorAll<HTMLInputElement>('input:checked')].map(input => input.value)]
  const scope = current?.mode === 'standalone' ? 'LOCAL' : elements.scope.value
  void send('rule', { action: elements.action.value, scope, domains, includeSubdomains: elements.subdomains.checked })
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
      defaultDirect: elements.saDefault.value === 'direct'
    }
  })
})
elements.saToggle.addEventListener('click', () => void send('enable', { enabled: !current?.enabled }))

void chrome.tabs.query({ active: true, currentWindow: true }).then(([tab]) => {
  tabId = tab?.id
  return tab?.url
}).then(value => {
  const url = value && new URL(value)
  if (url && (url.protocol === 'http:' || url.protocol === 'https:')) host = url.hostname.toLowerCase().replace(/\.$/, '')
  return send('status')
}).catch(() => send('status'))
