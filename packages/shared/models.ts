export type Action = 'PROXY' | 'AUTO' | 'LOCAL_DIRECT' | 'SERVER_DIRECT' | 'BLOCK' | 'INHERIT'
export type Profile = 'AUTO' | 'HOME_SERVER' | 'DIRECT_HTTP' | 'DIRECT_INTERNET' | 'CUSTOM'
export type Rule = {
  id?: string
  userId?: string
  pattern: string
  kind: 'domain' | 'suffix' | 'process' | 'package'
  action: Action
  locked?: boolean
  revision?: number
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
  AUTO: 'AUTO',
  HOME_SERVER: 'HOME SERVER',
  DIRECT_HTTP: 'DIRECT HTTP',
  DIRECT_INTERNET: 'DIRECT INTERNET',
  CUSTOM: 'CUSTOM'
}

export function scopeOf(rule: Rule): string {
  return rule.locked ? 'Обязательное' : !rule.id ? 'LOCAL' : rule.userId ? 'PERSONAL' : 'GLOBAL'
}
