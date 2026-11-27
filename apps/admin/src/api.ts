import type { Rule, ServiceGroup } from '../../../packages/shared/models'

export type User = { id: string; name: string; canEditGlobal?: boolean }
export type Proxy = { id: string; name: string; host: string; port: number; tls: number; headers?: Record<string, string> }
export type Device = {
  id: string; userId: string; label: string; transport: string; ackRevision: number; status: string; seen: number; expires: number
  linkType?: 'permanent' | 'temp'
  linkDurationSec?: number
  accessExpires?: number
  accessEnabled?: boolean
  expired?: boolean
  closedReason?: string
  closedAt?: number
  canEditGlobal?: boolean
  universal?: boolean
  subUrl?: string
  subActive?: boolean
  platform?: 'windows' | 'android' | 'browser' | 'ios' | ''
  installedVersion?: string
  reportedAt?: number
  online?: boolean
  activeConnections?: number
}
export type Event = { revision: number; event: string; time: number }
export type UpdatePolicy = { managed: boolean; paused: boolean }
export type UpdateEntry = {
  startedAt: number
  finishedAt: number
  outcome: 'installed' | 'no-update' | 'completed' | 'failed' | 'paused'
  phase: 'prerequisites' | 'recovery' | 'apply' | 'policy'
  version?: string
  exitCode?: number
}
export type State = {
  revision: number
  users: User[]
  devices: Device[]
  proxies: Proxy[]
  routes: { userId: string; proxyId: string; priority: number }[]
  rules: Rule[]
  groups: ServiceGroup[]
  audit: Event[]
}

const errors: Record<string, string> = {
  update_policy_disabled: 'Управление автообновлением на сервере отключено.',
  update_policy_unavailable: 'Не удалось сохранить политику обновлений.',
  unauthorized: 'Проверьте ключ администратора.',
  name_taken: 'Это имя уже используется.',
  proxy_unreachable: 'Контрольный запрос через прокси не прошёл. Проверьте адрес, учётные данные и заголовки.',
  invalid_proxy: 'Проверьте адрес, порт, учётные данные и заголовки.',
  invalid_rule: 'Проверьте шаблон и действие правила.',
  invalid_group: 'Проверьте название группы, маршрут и записи.',
  invalid_invite: 'Проверьте название устройства и срок действия ссылки.',
  invalid_name: 'Укажите имя пользователя.',
  rule_conflict: 'Пока вы редактировали правило, оно изменилось. Обновите панель.',
  group_conflict: 'Пока вы редактировали группу, она изменилась. Обновите панель.',
  forbidden_group: 'Недостаточно прав для изменения общих ресурсов.',
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
