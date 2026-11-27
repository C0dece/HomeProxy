import { readFileSync } from 'node:fs'

const port = Number(process.argv[2])
const input = JSON.parse(readFileSync(0, 'utf8'))
const pages = await (await fetch('http://127.0.0.1:' + port + '/json/list')).json()
const app = pages.find(page => page.type === 'page' && page.webSocketDebuggerUrl)
if (!app) throw new Error('HomeProxy WebView is not visible')

function invoke({ command, data }) {
  if (command === 'ui-connect') {
    let field = document.querySelector('input[type=password]')
    if (!field) {
      const subBtn = [...document.querySelectorAll('button')].find(item => item.textContent.includes('По подписке'))
      subBtn?.click()
      field = document.querySelector('input[type=password]')
    }
    if (!(field instanceof HTMLInputElement) || !field.form) throw new Error('Pairing screen is missing')
    field.value = data.link
    field.dispatchEvent(new Event('input', { bubbles: true }))
    field.form.requestSubmit()
    return true
  }
  if (command === 'ui-text') return document.body.innerText
  if (command === 'ui-updates') {
    const tab = [...document.querySelectorAll('nav button')].find(item => item.textContent.includes('Настройки'))
    if (!tab || tab.disabled) return false
    tab.click()
    return true
  }
  if (command === 'ui-vpn-policy') {
    const tab = [...document.querySelectorAll('nav button')].find(item => item.textContent.includes('Настройки'))
    tab?.click()
    return document.body.innerText
  }
  if (command === 'ui-vpn-settings') {
    const tab = [...document.querySelectorAll('nav button')].find(item => item.textContent.includes('Настройки'))
    tab?.click()
    const button = [...document.querySelectorAll('button')].find(item => item.textContent.includes('Настройки VPN'))
    if (!button || button.disabled) return false
    button.click()
    return true
  }
  if (command === 'ui-apps') {
    const tab = [...document.querySelectorAll('nav button')].find(item => item.textContent.includes('Ресурсы'))
    if (!tab) return false
    tab.click()
    const addBtn = [...document.querySelectorAll('button')].find(item => item.textContent.includes('Добавить ресурс'))
    addBtn?.click()
    return true
  }
  if (command === 'ui-package') {
    const items = document.querySelectorAll('.app-pick')
    const item = [...items].find(button => button.querySelector('.app-path')?.textContent === data.package)
    if (!item?.querySelector('img')?.naturalWidth) return false
    item.click()
    return item.innerText
  }
  if (command === 'ui-app-search') {
    const field = document.querySelector('dialog input[type=search]')
    if (!field) return false
    field.value = data.query
    field.dispatchEvent(new Event('input', { bubbles: true }))
    return true
  }
  if (command === 'ui-exclusions') {
    const tab = [...document.querySelectorAll('nav button')].find(item => item.textContent.includes('Настройки'))
    tab?.click()
    const details = [...document.querySelectorAll('details')].find(d => d.textContent.includes('Исключения из VPN'))
    if (!details) return ''
    if (!details.open) details.open = true
    return details.innerText
  }
  if (command === 'ui-exclusion-change') {
    const details = [...document.querySelectorAll('details')].find(d => d.textContent.includes('Исключения из VPN'))
    if (details && !details.open) details.open = true
    const button = [...(details?.querySelectorAll('button') ?? [])].find(item =>
      item.textContent.trim() === (data.excluded ? 'Исключить' : 'Вернуть') &&
      item.parentElement?.innerText.includes(data.package)
    )
    if (!button || button.disabled) return false
    button.click()
    return true
  }
  if (command === 'ui-vpn') {
    const label = data.enabled ? 'Включить' : 'Выключить'
    const button = document.querySelector(`button[aria-label="${label}"]`)
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
