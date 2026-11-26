import { readFileSync } from 'node:fs'

const port = Number(process.argv[2])
const input = JSON.parse(readFileSync(0, 'utf8'))
const pages = await (await fetch('http://127.0.0.1:' + port + '/json/list')).json()
const app = pages.find(page => page.type === 'page' && page.webSocketDebuggerUrl)
if (!app) throw new Error('HomeProxy WebView is not visible')

function invoke({ command, data }) {
  if (command === 'ui-connect') {
    const field = document.querySelector('input[type=password]')
    if (!(field instanceof HTMLInputElement) || !field.form) throw new Error('Pairing screen is missing')
    field.value = data.link
    field.dispatchEvent(new Event('input', { bubbles: true }))
    field.form.requestSubmit()
    return true
  }
  if (command === 'ui-text') return document.body.innerText
  if (command === 'ui-updates') {
    const button = [...document.querySelectorAll('button')].find(item => item.textContent.trim() === 'Обновления')
    if (!button || button.disabled) return false
    button.click()
    return true
  }
  if (command === 'ui-vpn-policy') {
    const heading = [...document.querySelectorAll('h2')].find(item => item.textContent === 'Политика VPN Android')
    const section = heading?.closest('section')
    if (!section) return false
    section.scrollIntoView({ block: 'center' })
    return section.innerText
  }
  if (command === 'ui-vpn-settings') {
    const button = [...document.querySelectorAll('button')].find(item => item.textContent.trim() === 'Настройки VPN Android')
    if (!button || button.disabled) return false
    button.click()
    return true
  }
  if (command === 'ui-apps') {
    const tab = [...document.querySelectorAll('nav button')].find(item => item.textContent.trim() === 'Приложения')
    if (!tab) return false
    tab.click()
    return true
  }
  if (command === 'ui-package') {
    const items = document.querySelectorAll('.app-choice')
    const item = [...items].find(button => button.querySelector('.mono')?.textContent === data.package)
    if (!item?.querySelector('img')?.naturalWidth) return false
    const bounds = item.getBoundingClientRect()
    const text = item.querySelector('.card-head').getBoundingClientRect()
    if (text.top < bounds.top || text.bottom > bounds.bottom) throw new Error('Android package row text overlaps')
    item.click()
    return item.innerText
  }
  if (command === 'ui-app-search') {
    const field = document.querySelector('input[type=search]')
    if (!field) return false
    field.value = data.query
    field.dispatchEvent(new Event('input', { bubbles: true }))
    return true
  }
  if (command === 'ui-exclusions') {
    const section = document.querySelector('[aria-label="Исключения из VPN"]')
    if (!section) {
      const tab = [...document.querySelectorAll('nav button')].find(item => item.textContent.trim() === 'Исключения')
      tab?.click()
      return ''
    }
    section.scrollIntoView({ block: 'center' })
    return section.innerText
  }
  if (command === 'ui-exclusion-change') {
    const list = document.querySelector(data.excluded ? '[aria-label="Добавить исключение"]' : '[aria-label="Исключения из VPN"]')
    const field = list?.querySelector('input[type=search]')
    if (field && field.value !== data.package) {
      field.value = data.package
      field.dispatchEvent(new Event('input', { bubbles: true }))
      return false
    }
    const button = [...(list?.querySelectorAll('button[data-package]') ?? [])].find(item => item.dataset.package === data.package)
    if (!button || button.disabled) return false
    button.click()
    return true
  }
  if (command === 'ui-package-save') {
    const field = document.querySelector('input[placeholder="com.example.app"]')
    const form = field?.form
    const button = form?.querySelector('button.primary')
    if (!form || !button || button.disabled || field.value !== data.package) return false
    const [scope, route] = form.querySelectorAll('select')
    for (const [select, value] of [[scope, data.scope], [route, data.action]]) {
      select.value = value
      select.dispatchEvent(new Event('change', { bubbles: true }))
    }
    form.requestSubmit()
    return true
  }
  if (command === 'ui-vpn') {
    const label = data.enabled ? 'Запустить VPN' : 'Остановить VPN'
    const button = [...document.querySelectorAll('button')].find(item => item.textContent.trim() === label)
    if (!button || button.disabled) return false
    button.click()
    return true
  }
  return window.__TAURI_INTERNALS__.invoke('agent_command', { command, data })
}
const socket = new WebSocket(app.webSocketDebuggerUrl)
const result = new Promise((resolve, reject) => {
  socket.addEventListener('open', () => socket.send(JSON.stringify({
    id: 1,
    method: 'Runtime.evaluate',
    params: { expression: '(' + invoke.toString() + ')(' + JSON.stringify(input) + ')', awaitPromise: true, returnByValue: true }
  })), { once: true })
  socket.addEventListener('error', () => reject(new Error('WebView debug connection failed')), { once: true })
  socket.addEventListener('message', ({ data }) => {
    const reply = JSON.parse(data)
    if (reply.id !== 1) return
    const failure = reply.result?.exceptionDetails
    if (reply.error || failure) {
      reject(new Error(failure?.exception?.description ?? failure?.exception?.value ?? reply.error?.message ?? 'Android command failed'))
    }
    else resolve(reply.result.result.value)
  })
})
const timer = setTimeout(() => socket.close(), input.command === 'update-install' ? 195000 : 25000)
try { process.stdout.write(JSON.stringify(await result)) }
finally { clearTimeout(timer); socket.close() }
