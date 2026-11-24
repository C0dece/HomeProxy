import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { createServer } from 'node:http'
import { mkdir, mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
import { promisify } from 'node:util'

const env = process.env
const { chromium } = await import(env.HOMEPROXY_PLAYWRIGHT ? pathToFileURL(env.HOMEPROXY_PLAYWRIGHT).href : 'playwright')
const screenshots = resolve('dist/qa')
const extension = resolve('dist/browser')
const profile = await mkdtemp(join(tmpdir(), 'HomeProxyBrowser-'))
const run = promisify(execFile)
const target = `http://app.homeproxy.test:${env.HOMEPROXY_QA_ORIGIN_PORT}/browser-fixture`
const localhost = env.HOMEPROXY_QA_API
await mkdir(screenshots, { recursive: true })
const context = await chromium.launchPersistentContext(profile, {
  channel: 'chromium',
  executablePath: env.HOMEPROXY_CHROMIUM,
  headless: true,
  viewport: { width: 1360, height: 880 },
  args: [`--disable-extensions-except=${extension}`, `--load-extension=${extension}`, '--disable-background-networking']
})
let web
try {
  const worker = context.serviceWorkers()[0] ?? await context.waitForEvent('serviceworker')
  const extensionId = new URL(worker.url()).hostname
  const popupURL = `chrome-extension://${extensionId}/popup.html`
  const admin = context.pages()[0] ?? await context.newPage()
  await admin.goto(localhost)
  await admin.getByLabel('Ключ доступа').fill(env.HOMEPROXY_ADMIN_TOKEN)
  await admin.getByRole('button', { name: 'Войти' }).click()
  await admin.getByRole('heading', { name: 'Обзор' }).waitFor()
  await admin.screenshot({ path: join(screenshots, 'admin-desktop.png') })
  const health = await admin.request.get(new URL('/healthz', localhost).href)
  assert.ok(health.ok())
  const running = await health.json()
  await admin.getByRole('button', { name: 'Обновления', exact: true }).click()
  await admin.getByRole('heading', { name: 'Обновления', exact: true }).waitFor()
  await admin.getByText(running.version, { exact: true }).waitFor()
  assert.equal(await admin.getByRole('heading', { name: 'Последние изменения' }).count(), 0)
  await admin.getByText('Версия 1.2.3', { exact: true }).waitFor()
  await admin.getByText('Восстановление, код 7', { exact: true }).waitFor()
  await admin.getByText('Нет совместимого обновления', { exact: true }).waitFor()
  await admin.getByText('Пропущено по политике', { exact: true }).waitFor()
  const windowsDevice = admin.getByRole('row').filter({ hasText: 'Agent QA' })
  await windowsDevice.getByText('Windows', { exact: true }).waitFor()
  await windowsDevice.getByText(/^\d+\.\d+\.\d+$/).waitFor()
  await admin.getByRole('button', { name: 'Приостановить', exact: true }).click()
  await admin.getByText('На паузе', { exact: true }).waitFor()
  const [policyAfterRefresh] = await Promise.all([
    admin.waitForResponse(response => response.url().endsWith('/api/v1/admin/update-policy') && response.request().method() === 'GET'),
    admin.getByRole('button', { name: 'Обновить данные' }).click()
  ])
  assert.deepEqual(await policyAfterRefresh.json(), { managed: true, paused: true })
  await admin.getByText('На паузе', { exact: true }).waitFor()
  await admin.getByRole('button', { name: 'Возобновить', exact: true }).click()
  await admin.getByText('Разрешены', { exact: true }).waitFor()
  await admin.screenshot({ path: join(screenshots, 'admin-updates-desktop.png') })
  await admin.getByRole('button', { name: 'Пользователи', exact: true }).click()
  await admin.getByRole('button', { name: 'Добавить пользователя' }).click()
  await admin.getByLabel('Имя', { exact: true }).fill('UI QA')
  await admin.getByRole('button', { name: 'Сохранить', exact: true }).click()
  await admin.getByText('UI QA', { exact: true }).waitFor()
  await admin.setViewportSize({ width: 390, height: 840 })
  await admin.getByRole('button', { name: 'Обновления', exact: true }).click()
  await admin.getByText('Нет совместимого обновления', { exact: true }).waitFor()
  assert.equal(await admin.evaluate(() => document.documentElement.scrollWidth), 390)
  await admin.screenshot({ path: join(screenshots, 'admin-updates-narrow.png'), fullPage: true })
  await admin.getByRole('button', { name: 'Прокси', exact: true }).click()
  await admin.getByRole('heading', { name: 'Исходные прокси' }).waitFor()
  assert.equal(await admin.evaluate(() => document.documentElement.scrollWidth), 390)
  await admin.screenshot({ path: join(screenshots, 'admin-narrow.png') })
  await admin.getByRole('button', { name: 'Правила', exact: true }).click()
  await admin.getByRole('button', { name: 'Добавить правило' }).click()
  await admin.getByRole('dialog').locator('select[name="kind"]').selectOption('process')
  await admin.getByLabel('Шаблон').fill('qa-admin.exe')
  await admin.getByRole('button', { name: 'Сохранить', exact: true }).click()
  await admin.getByText('qa-admin.exe', { exact: true }).waitFor()
  await admin.getByRole('button', { name: 'Добавить правило' }).click()
  await admin.getByRole('dialog').locator('select[name="kind"]').selectOption('package')
  await admin.getByLabel('Шаблон').fill('app.homeproxy.qa')
  assert.equal(await admin.evaluate(() => document.documentElement.scrollWidth), 390)
  await admin.screenshot({ path: join(screenshots, 'admin-android-rule.png') })
  await admin.getByRole('button', { name: 'Сохранить', exact: true }).click()
  await admin.getByText('app.homeproxy.qa', { exact: true }).waitFor()

  async function controller(command, data = null) {
    const { stdout } = await run(env.HOMEPROXY_QA_AGENT,
      ['ctl', '--data', env.HOMEPROXY_QA_STATE, '--port', env.HOMEPROXY_QA_CTL, '--command', command, '--json', JSON.stringify(data)],
      { windowsHide: true, timeout: 20000 })
    return JSON.parse(stdout)
  }
  const site = await context.newPage()
  await site.goto(`http://127.0.0.1:${env.HOMEPROXY_QA_ORIGIN_PORT}/probe`)
  await site.bringToFront()
  const session = await context.newCDPSession(site)
  async function openPopup() {
    const popupEvent = context.waitForEvent('page')
    await session.send('Target.createTarget', { url: popupURL, background: true })
    return await popupEvent
  }
  let popup = await openPopup()
  await popup.locator('#link').fill(env.HOMEPROXY_QA_INVITE)
  await popup.getByRole('button', { name: 'Подключить', exact: true }).click()
  await popup.getByRole('button', { name: 'Включить маршрутизацию' }).click()
  await popup.getByRole('button', { name: 'Выключить маршрутизацию' }).waitFor()
  await popup.close()
  const synced = await controller('sync')
  assert.ok(synced.linked && synced.online && !synced.error, 'Agent did not synchronize browser test rules')

  await site.goto(target)
  await site.getByRole('heading', { name: 'HomeProxy QA' }).waitFor()
  await site.bringToFront()
  popup = await openPopup()
  await popup.getByText('app.homeproxy.test', { exact: true }).waitFor()
  await popup.getByText('Ресурсы вкладки').click()
  await popup.getByText('asset.homeproxy.test', { exact: true }).waitFor()
  await popup.screenshot({ path: join(screenshots, 'browser-popup.png'), clip: { x: 0, y: 0, width: 390, height: 720 } })
  await popup.locator('#action').selectOption('BLOCK')
  await popup.getByRole('button', { name: 'Сохранить правило' }).click()
  await popup.getByText('Блокировать · LOCAL', { exact: true }).waitFor()
  await assert.rejects(site.goto(target + '?blocked=1'), /ERR_BLOCKED_BY_CLIENT|ERR_UNSAFE_PORT|ERR_PROXY_CONNECTION_FAILED/)
  await popup.locator('#action').selectOption('PROXY')
  await popup.getByRole('button', { name: 'Сохранить правило' }).click()
  await popup.getByText('Через прокси · LOCAL', { exact: true }).waitFor()
  // Chromium may still use the previous PAC result while the network service applies the new configuration.
  for (let attempt = 0; ; attempt++) {
    try {
      await site.goto(target + '?proxy=' + attempt, { timeout: 5000 })
      break
    } catch (error) {
      if (attempt >= 4 || !/ERR_PROXY_CONNECTION_FAILED|ERR_HTTP_RESPONSE_CODE_FAILURE|ERR_BLOCKED_BY_CLIENT|ERR_UNSAFE_PORT/.test(String(error))) throw error
      await new Promise(resolve => setTimeout(resolve, 350))
    }
  }
  await site.getByRole('heading', { name: 'HomeProxy QA' }).waitFor()
  await popup.getByRole('button', { name: 'Выключить маршрутизацию' }).click()
  await popup.getByRole('button', { name: 'Включить маршрутизацию' }).waitFor()
  await popup.close()
  console.log('PASS Chromium extension enrollment, live PAC proxy, resource discovery and BLOCK')

  await admin.getByRole('button', { name: 'Обновления', exact: true }).click()
  await admin.getByRole('button', { name: 'Обновить данные' }).click()
  const browserDevice = admin.getByRole('row').filter({ hasText: 'Chromium QA' })
  await browserDevice.getByText('Расширение', { exact: true }).waitFor()
  await browserDevice.getByText(/^\d+\.\d+\.\d+$/).waitFor()

  web = createServer(async (req, res) => {
    const path = req.url === '/' ? 'index.html' : req.url?.slice(1)
    if (!path || !/^(index\.html|assets\/[a-zA-Z0-9_-]+\.(js|css))$/.test(path)) { res.writeHead(404).end(); return }
    const body = await readFile(resolve('dist/agent', path))
    res.writeHead(200, { 'Content-Type': path.endsWith('.css') ? 'text/css' : path.endsWith('.js') ? 'text/javascript' : 'text/html' }).end(body)
  }).listen(0, '127.0.0.1')
  await new Promise(resolve => web.once('listening', resolve))
  const agent = await context.newPage()
  await agent.setViewportSize({ width: 820, height: 760 })
  await agent.exposeFunction('agentQA', controller)
  await agent.addInitScript(() => {
    window.__TAURI_INTERNALS__ = { invoke: (_, { command, data }) => window.agentQA(command, data) }
  })
  await agent.goto(`http://127.0.0.1:${web.address().port}/`)
  await agent.getByRole('heading', { name: 'Маршрутизация' }).waitFor()
  await agent.screenshot({ path: join(screenshots, 'agent-desktop.png') })
  await agent.setViewportSize({ width: 360, height: 820 })
  await agent.getByRole('button', { name: 'Сайты', exact: true }).click()
  await agent.getByLabel('Домен', { exact: true }).fill('qa-ui.homeproxy.test')
  await agent.getByRole('button', { name: 'Сохранить правило' }).click()
  await agent.getByText('qa-ui.homeproxy.test', { exact: true }).waitFor()
  assert.equal(await agent.evaluate(() => document.documentElement.scrollWidth), 360)
  await agent.screenshot({ path: join(screenshots, 'agent-narrow.png') })
  await agent.getByRole('button', { name: 'Приложения', exact: true }).click()
  await agent.getByLabel('Запущенное приложение').locator('option').nth(1).waitFor({ state: 'attached' })
  await agent.getByLabel('Имя или путь EXE', { exact: true }).fill('qa-ui.exe')
  await agent.getByLabel('Маршрут').selectOption('BLOCK')
  await agent.getByRole('button', { name: 'Сохранить правило' }).click()
  await agent.getByText('qa-ui.exe', { exact: true }).waitFor()
  assert.equal(await agent.evaluate(() => document.documentElement.scrollWidth), 360)
  await agent.screenshot({ path: join(screenshots, 'agent-apps-narrow.png'), fullPage: true })
  await agent.setViewportSize({ width: 820, height: 760 })
  await agent.screenshot({ path: join(screenshots, 'agent-apps-desktop.png'), fullPage: true })
  console.log('PASS Admin and Agent frontend actions at desktop and narrow sizes')
} finally {
  web?.close()
  await context.close()
  await rm(profile, { recursive: true, force: true, maxRetries: 4 })
}
