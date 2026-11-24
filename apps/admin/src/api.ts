import type { Rule } from '../../../packages/shared/models'

export type User = { id: string; name: string }
export type Proxy = User & { host: string; port: number; tls: number }
export type Device = { id: string; userId: string; label: string; transport: string; ackRevision: number; status: string; seen: number; expires: number }
export type Event = { revision: number; event: string; time: number }
export type State = {
  revision: number
  users: User[]
  devices: Device[]
  proxies: Proxy[]
  routes: { userId: string; proxyId: string; priority: number }[]
  rules: Rule[]
  audit: Event[]
}

const errors: Record<string, string> = {
  unauthorized: 'Проверьте ключ администратора.',
  name_taken: 'Это имя уже используется.',
  proxy_unreachable: 'Контрольный запрос через прокси не прошёл. Проверьте адрес и учётные данные.',
  invalid_proxy: 'Проверьте адрес, порт и учётные данные.',
  invalid_rule: 'Проверьте шаблон и действие правила.',
  invalid_invite: 'Проверьте название устройства и срок действия ссылки.',
  invalid_name: 'Укажите имя пользователя.',
  rule_conflict: 'Пока вы редактировали правило, оно изменилось. Обновите панель.',
  not_found: 'Запись не найдена. Обновите панель.'
}

export async function admin<T>(token: string, path: string, method = 'GET', body?: object): Promise<T> {
  const res = await fetch('/api/v1/admin/' + path, {
    method,
    headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' },
    ...(body ? { body: JSON.stringify(body) } : {}),
    redirect: 'error',
    signal: AbortSignal.timeout(25_000)
  })
  if (res.status === 204) return undefined as T
  const data = await res.json()
  if (!res.ok) throw new Error(errors[data.error] ?? 'Операция не завершилась. Проверьте сервер.')
  return data
}
