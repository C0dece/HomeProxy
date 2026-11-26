export type Action = 'PROXY' | 'AUTO' | 'LOCAL_DIRECT' | 'SERVER_DIRECT' | 'BLOCK' | 'INHERIT'
export type Profile = 'AUTO' | 'HOME_SERVER' | 'DIRECT_HTTP' | 'DIRECT_INTERNET' | 'CUSTOM'
export type RuleKind = 'domain' | 'suffix' | 'ip_cidr' | 'process' | 'package'
export type Rule = {
  id?: string
  userId?: string
  pattern: string
  kind: RuleKind
  action: Action
  enabled?: boolean
  locked?: boolean
  revision?: number
}
export type ServiceGroupEntry = {
  id?: string
  kind: RuleKind
  pattern: string
}
export type ServiceGroup = {
  id?: string
  name: string
  userId?: string
  action: Action
  enabled: boolean
  locked?: boolean
  revision?: number
  entries: ServiceGroupEntry[]
}

export const actionNames: Record<Action, string> = {
  PROXY: 'Через прокси',
  AUTO: 'Автоматически',
  LOCAL_DIRECT: 'Напрямую с устройства',
  SERVER_DIRECT: 'Напрямую с сервера',
  BLOCK: 'Блокировать',
  INHERIT: 'Наследовать'
}

export const profileNames: Record<Profile, string> = {
  AUTO: 'Автоматически',
  HOME_SERVER: 'Только через сервер',
  DIRECT_HTTP: 'Сразу к прокси провайдера',
  DIRECT_INTERNET: 'Интернет устройства',
  CUSTOM: 'Выбрать маршрут вручную'
}

export function scopeOf(rule: Rule): string {
  return rule.locked ? 'Обязательное' : !rule.id ? 'LOCAL' : rule.userId ? 'PERSONAL' : 'GLOBAL'
}
