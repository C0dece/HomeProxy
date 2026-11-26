import type { Action, Rule, ServiceGroup } from '../../packages/shared/models'

export type ExtensionMode = 'agent' | 'standalone'
export type StandaloneScheme = 'http' | 'https' | 'socks5'
export type StandaloneProxy = {
  scheme: StandaloneScheme
  host: string
  port: number
  username: string
  password: string
  defaultDirect: boolean
}

export function validDomain(value: string): boolean {
  return Boolean(value) && value.length <= 253 &&
    value.split('.').every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))
}

function scopeOrder(rule: Rule): number {
  return rule.locked ? 0 : !rule.id ? 1 : rule.userId ? 2 : 3
}

export function effectiveBrowserRules(remote: Rule[], groups: ServiceGroup[], local: Rule[]): Rule[] {
  const expanded: Rule[] = []
  for (const group of groups) {
    if (group.enabled === false || group.action === 'INHERIT') continue
    for (const entry of group.entries) {
      if (entry.kind !== 'domain' && entry.kind !== 'suffix') continue
      expanded.push({
        id: group.id,
        userId: group.userId,
        kind: entry.kind,
        pattern: entry.pattern,
        action: group.action,
        enabled: true,
        locked: group.locked,
        revision: group.revision
      })
    }
  }
  return [...remote, ...expanded, ...local]
    .filter(r => r.enabled !== false && r.action !== 'INHERIT' && validDomain(r.pattern) && (r.kind === 'domain' || r.kind === 'suffix'))
    .sort((a, b) => scopeOrder(a) - scopeOrder(b) || Number(a.kind === 'suffix') - Number(b.kind === 'suffix') || b.pattern.length - a.pattern.length)
}

export function matchesRule(rule: Rule, domain: string): boolean {
  return domain === rule.pattern || (rule.kind === 'suffix' && domain.endsWith('.' + rule.pattern))
}

function formatPacHost(host: string): string {
  const trimmed = host.trim()
  if (trimmed.includes(':') && !trimmed.startsWith('[')) return `[${trimmed}]`
  return trimmed
}

export function buildPacScript(params: {
  mode: ExtensionMode
  rules: Rule[]
  agentPort: number
  originHost?: string
  standaloneProxy?: StandaloneProxy
}): string {
  const values = params.rules.map(r => [r.pattern, r.kind === 'suffix', r.action] as [string, boolean, Action])
  if (params.mode === 'standalone') {
    const proxy = params.standaloneProxy
    if (!proxy || !proxy.host.trim() || !Number.isInteger(proxy.port) || proxy.port < 1 || proxy.port > 65535) {
      throw new Error('Укажите адрес и порт прокси для автономного режима')
    }
    const keyword = proxy.scheme === 'https' ? 'HTTPS' : proxy.scheme === 'socks5' ? 'SOCKS5' : 'PROXY'
    const target = `${keyword} ${formatPacHost(proxy.host)}:${proxy.port}`
    const fallback = proxy.defaultDirect ? 'DIRECT' : target
    return `
function FindProxyForURL(url, host) {
  host = host.toLowerCase().replace(/\\.$/, '');
  if (host === 'localhost' || host === '127.0.0.1' || host === '::1') return 'DIRECT';
  var rules = ${JSON.stringify(values)};
  var proxyTarget = ${JSON.stringify(target)};
  for (var i = 0; i < rules.length; i++) {
    var rule = rules[i], suffix = '.' + rule[0];
    if (host === rule[0] || (rule[1] && host.slice(-suffix.length) === suffix)) {
      var act = rule[2];
      if (act === 'BLOCK') return 'PROXY 127.0.0.1:1';
      if (act === 'LOCAL_DIRECT' || act === 'SERVER_DIRECT') return 'DIRECT';
      return proxyTarget;
    }
  }
  return ${JSON.stringify(fallback)};
}`
  }

  const base = params.agentPort
  const authority = params.originHost ?? ''
  return `
function FindProxyForURL(url, host) {
  host = host.toLowerCase().replace(/\\.$/, '');
  if (${JSON.stringify(authority)} && url.split('/')[2] === ${JSON.stringify(authority)}) return 'DIRECT';
  var rules = ${JSON.stringify(values)};
  var ports = {PROXY:${base + 2}, LOCAL_DIRECT:${base + 3}, SERVER_DIRECT:${base + 4}, AUTO:${base}, BLOCK:1};
  for (var i = 0; i < rules.length; i++) {
    var rule = rules[i], suffix = '.' + rule[0];
    if (host === rule[0] || (rule[1] && host.slice(-suffix.length) === suffix))
      return 'PROXY 127.0.0.1:' + ports[rule[2]];
  }
  return 'PROXY 127.0.0.1:${base}';
}`
}
