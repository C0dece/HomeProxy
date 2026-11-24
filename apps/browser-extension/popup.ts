import { actionNames, scopeOf } from '../../packages/shared/models'
import type { Rule } from '../../packages/shared/models'
import type { Observed } from './background'

const get = <T extends HTMLElement>(id: string) => document.getElementById(id) as T
const notice = get<HTMLParagraphElement>('notice')
const link = get<HTMLInputElement>('link')
const elements = {
  status: get('status'), domain: get('domain'), revision: get('revision'), current: get('current'),
  toggle: get<HTMLButtonElement>('toggle'), sync: get<HTMLButtonElement>('sync'), forget: get<HTMLButtonElement>('forget'),
  connect: get<HTMLFormElement>('connect'), route: get('route'), agent: get('agent'),
  scope: get<HTMLSelectElement>('scope'), action: get<HTMLSelectElement>('action'),
  resources: get('resources'), count: get('count'), save: get<HTMLButtonElement>('save'),
  subdomains: get<HTMLInputElement>('subdomains')
}

type Status = { linked: boolean; enabled: boolean; online: boolean; revision: number;
  pending: number; error: string; rule?: Rule; resources: Observed[] }
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
  elements.status.className = 'badge ' + (state.enabled ? state.online ? 'ok' : 'wait' : '')
  elements.status.textContent = state.enabled ? state.online ? 'Активно' : 'Автономно' : 'Выключено'
  elements.connect.hidden = state.linked || state.enabled
  elements.route.hidden = !state.linked || !host
  elements.agent.hidden = !state.linked && !state.enabled
  elements.sync.hidden = !state.linked
  if (host) elements.domain.textContent = host
  elements.revision.textContent = state.revision ? 'v' + state.revision : ''
  elements.current.textContent = state.rule ? actionNames[state.rule.action] + ' · ' + scopeOf(state.rule) : 'Автоматически · Профиль агента'
  elements.toggle.textContent = state.enabled ? 'Выключить маршрутизацию' : 'Включить маршрутизацию'
  const previous = new Set([...elements.resources.querySelectorAll<HTMLInputElement>('input:checked')].map(input => input.value))
  const resources = state.resources.filter(item => item.domain !== host)
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
  alert(state.error || (state.pending ? 'Ожидают отправки: ' + state.pending : ''))
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
  }
}

elements.connect.addEventListener('submit', e => { e.preventDefault(); void send('connect', { link: link.value }) })
elements.toggle.addEventListener('click', () => void send('enable', { enabled: !current?.enabled }))
elements.sync.addEventListener('click', () => void send('sync'))
elements.forget.addEventListener('click', () => { if (confirm('Отвязать браузер и освободить его настройки прокси?')) void send('forget') })
elements.save.addEventListener('click', () => {
  const domains = [host, ...[...elements.resources.querySelectorAll<HTMLInputElement>('input:checked')].map(input => input.value)]
  void send('rule', { action: elements.action.value, scope: elements.scope.value, domains, includeSubdomains: elements.subdomains.checked })
})

void chrome.tabs.query({ active: true, currentWindow: true }).then(([tab]) => {
  tabId = tab?.id
  return tab?.url
}).then(value => {
  const url = value && new URL(value)
  if (url && (url.protocol === 'http:' || url.protocol === 'https:')) host = url.hostname.toLowerCase().replace(/\.$/, '')
  return send('status')
}).catch(() => send('status'))
