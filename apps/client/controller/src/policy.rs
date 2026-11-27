use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::net::IpAddr;

fn default_true() -> bool {
    true
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Action {
    Proxy,
    Auto,
    LocalDirect,
    ServerDirect,
    Block,
    Inherit,
}

#[derive(Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Profile {
    #[default]
    Auto,
    HomeServer,
    DirectHttp,
    DirectInternet,
    Custom,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Rule {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub user_id: String,
    pub kind: String,
    pub pattern: String,
    pub action: Action,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub locked: bool,
    #[serde(default)]
    pub revision: u64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceGroupEntry {
    #[serde(default)]
    pub id: String,
    pub kind: String,
    pub pattern: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceGroup {
    #[serde(default)]
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub user_id: String,
    pub action: Action,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub locked: bool,
    #[serde(default)]
    pub revision: u64,
    #[serde(default)]
    pub entries: Vec<ServiceGroupEntry>,
}

impl ServiceGroup {
    pub fn validate(&mut self) -> Result<(), String> {
        self.name = self.name.trim().to_string();
        if self.name.is_empty() || self.name.len() > 100 {
            return Err("Укажите название ресурса".into());
        }
        if self.locked && self.action == Action::Inherit {
            return Err("Некорректный маршрут для обязательного ресурса".into());
        }
        if self.entries.len() > 256 {
            return Err("Слишком много записей в ресурсе".into());
        }
        let mut seen = std::collections::HashSet::with_capacity(self.entries.len());
        for entry in &mut self.entries {
            entry.normalize()?;
            let key = format!("{}\x00{}", entry.kind, entry.pattern);
            if !seen.insert(key) {
                return Err("В ресурсе есть дублирующиеся записи".into());
            }
        }
        Ok(())
    }
}

fn domain(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

fn normalize_cidr(raw: &str) -> Option<String> {
    if let Some((addr_part, prefix_part)) = raw.split_once('/') {
        let addr: IpAddr = addr_part.parse().ok()?;
        let prefix: u8 = prefix_part.parse().ok()?;
        let max_prefix = if addr.is_ipv4() { 32 } else { 128 };
        if prefix > max_prefix {
            return None;
        }
        Some(format!("{addr}/{prefix}"))
    } else {
        let addr: IpAddr = raw.parse().ok()?;
        let prefix = if addr.is_ipv4() { 32 } else { 128 };
        Some(format!("{addr}/{prefix}"))
    }
}

fn normalize_pattern(kind: &str, pattern: &mut String) -> Result<(), String> {
    *pattern = if kind == "package" {
        pattern.trim().to_owned()
    } else {
        pattern.trim().to_lowercase()
    };
    let valid = match kind {
        "domain" | "suffix" => {
            pattern.truncate(pattern.trim_end_matches('.').len());
            domain(pattern)
        }
        "ip_cidr" => {
            if let Some(normalized) = normalize_cidr(pattern) {
                *pattern = normalized;
                true
            } else {
                false
            }
        }
        "process" => {
            *pattern = pattern.replace('/', "\\");
            pattern.ends_with(".exe")
                && pattern.len() > 4
                && pattern.len() <= 1024
                && !pattern.contains(['\r', '\n', '\0'])
        }
        "package" => {
            pattern.len() <= 255
                && pattern.contains('.')
                && pattern.split('.').all(|part| {
                    part.starts_with(|c: char| c.is_ascii_alphabetic())
                        && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                })
        }
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err("Недопустимое значение правила".into())
    }
}

impl Rule {
    pub fn normalize(&mut self) -> Result<(), String> {
        normalize_pattern(&self.kind, &mut self.pattern)
    }

    pub fn same_target(&self, other: &Rule) -> bool {
        self.kind == other.kind && self.pattern == other.pattern
    }
}

impl ServiceGroupEntry {
    pub fn normalize(&mut self) -> Result<(), String> {
        normalize_pattern(&self.kind, &mut self.pattern)
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ServerEndpoint {
    pub host: String,
    pub port: u16,
    pub id: String,
    pub direct_id: String,
    pub server_name: String,
    pub public_key: String,
    pub short_id: String,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Proxy {
    pub id: String,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub tls: bool,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Configuration {
    #[serde(default)]
    pub client_updates_paused: bool,
    #[serde(default)]
    pub can_edit_global: bool,
    pub api: u32,
    pub device_id: String,
    pub revision: u64,
    pub rules: Vec<Rule>,
    #[serde(default)]
    pub groups: Vec<ServiceGroup>,
    pub home: ServerEndpoint,
    pub proxies: Vec<Proxy>,
    pub probe_url: String,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, rename_all = "camelCase")]
pub struct CustomProxy {
    pub protocol: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub tls: bool,
    pub server_name: String,
}

impl Default for CustomProxy {
    fn default() -> Self {
        Self {
            protocol: "HTTP".into(),
            host: String::new(),
            port: 8080,
            username: String::new(),
            password: String::new(),
            tls: false,
            server_name: String::new(),
        }
    }
}

impl CustomProxy {
    pub fn validate(&mut self) -> Result<(), String> {
        self.protocol = self.protocol.trim().to_uppercase();
        if !matches!(self.protocol.as_str(), "HTTP" | "SOCKS5" | "VLESS") {
            return Err("Выберите протокол HTTP, SOCKS5 или VLESS".into());
        }
        self.host = self.host.trim().to_string();
        if self.host.is_empty()
            || self.host.len() > 253
            || self
                .host
                .contains([' ', '\t', '\r', '\n', '/', '\\', '@', '?', '#'])
        {
            return Err("Укажите корректный адрес сервера".into());
        }
        if self.port == 0 {
            return Err("Укажите корректный порт (1-65535)".into());
        }
        self.username = self.username.trim().to_string();
        self.server_name = self.server_name.trim().to_string();
        if self.protocol == "VLESS" {
            if self.username.is_empty() {
                return Err("Для VLESS укажите UUID в поле логина".into());
            }
        } else if !self.password.is_empty() && self.username.is_empty() {
            return Err("Укажите логин для пароля прокси".into());
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct Candidate {
    pub tag: String,
    pub name: String,
}

pub struct Generated {
    pub config: Value,
    pub candidates: Vec<Candidate>,
}

pub fn parse_web(value: &str, allow_http: bool) -> Result<reqwest::Url, String> {
    let url = reqwest::Url::parse(value.trim()).map_err(|_| "Неверный URL")?;
    let local = url.host_str() == Some("127.0.0.1");
    if url.host().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || !(url.scheme() == "https" || allow_http && local && url.scheme() == "http")
    {
        return Err("Укажите HTTPS URL без учётных данных".into());
    }
    Ok(url)
}

fn route(action: Action, default: Action) -> Value {
    match if action == Action::Auto {
        default
    } else {
        action
    } {
        Action::Block | Action::Inherit => json!({"action": "reject"}),
        Action::LocalDirect => json!({"action": "route", "outbound": "local-direct"}),
        Action::ServerDirect => json!({"action": "route", "outbound": "server-direct"}),
        Action::Proxy | Action::Auto => json!({"action": "route", "outbound": "selected-proxy"}),
    }
}

pub(crate) fn tun_dns(profile: Profile, custom: Action) -> Value {
    let dns_route = match (profile, custom) {
        (Profile::DirectInternet, _) | (Profile::Custom, Action::LocalDirect) => None,
        (Profile::Custom, Action::ServerDirect) => Some("server-direct"),
        (Profile::Custom, Action::Block) => Some("unavailable"),
        _ => Some("selected-proxy"),
    };
    let mut https = json!({
        "type": "https", "tag": "routed-dns", "server": "9.9.9.9", "path": "/dns-query",
        "tls": {"enabled": true, "server_name": "dns.quad9.net"}
    });
    if let Some(detour) = dns_route {
        https["detour"] = json!(detour);
    }
    json!({
        "servers": [
            {"type": "local", "tag": "system"},
            {"type": "fakeip", "tag": "fake", "inet4_range": "198.18.0.0/15", "inet6_range": "fc00::/18"},
            https
        ],
        "rules": [{"query_type": ["A", "AAAA"], "action": "route", "server": "fake", "rewrite_ttl": 60}],
        "final": "routed-dns"
    })
}

pub fn effective_rules(
    synced: &[Rule],
    groups: &[ServiceGroup],
    local_groups: &[ServiceGroup],
    local: &[Rule],
) -> Vec<Rule> {
    let mut rules: Vec<Rule> = synced
        .iter()
        .chain(local)
        .filter(|r| r.enabled && r.action != Action::Inherit)
        .cloned()
        .collect();
    for group in groups {
        if !group.enabled || group.action == Action::Inherit {
            continue;
        }
        for entry in &group.entries {
            if !entry.enabled {
                continue;
            }
            rules.push(Rule {
                id: group.id.clone(),
                user_id: group.user_id.clone(),
                kind: entry.kind.clone(),
                pattern: entry.pattern.clone(),
                action: group.action,
                enabled: true,
                locked: group.locked,
                revision: group.revision,
            });
        }
    }
    for group in local_groups {
        if !group.enabled || group.action == Action::Inherit {
            continue;
        }
        for entry in &group.entries {
            if !entry.enabled {
                continue;
            }
            rules.push(Rule {
                id: String::new(),
                user_id: String::new(),
                kind: entry.kind.clone(),
                pattern: entry.pattern.clone(),
                action: group.action,
                enabled: true,
                locked: false,
                revision: 0,
            });
        }
    }
    rules.sort_by_key(|r| {
        let scope = if r.locked {
            0
        } else if r.id.is_empty() {
            1
        } else if !r.user_id.is_empty() {
            2
        } else {
            3
        };
        (
            scope,
            !matches!(r.kind.as_str(), "process" | "package"),
            r.kind == "process" && !r.pattern.contains('\\'),
            r.kind == "suffix",
            std::cmp::Reverse(r.pattern.len()),
        )
    });
    rules
}

pub fn ordered_rules<'a>(synced: &'a [Rule], local: &'a [Rule]) -> Vec<&'a Rule> {
    let mut rules: Vec<_> = synced
        .iter()
        .chain(local)
        .filter(|r| r.enabled && r.action != Action::Inherit)
        .collect();
    rules.sort_by_key(|r| {
        let scope = if r.locked {
            0
        } else if r.id.is_empty() {
            1
        } else if !r.user_id.is_empty() {
            2
        } else {
            3
        };
        (
            scope,
            !matches!(r.kind.as_str(), "process" | "package"),
            r.kind == "process" && !r.pattern.contains('\\'),
            r.kind == "suffix",
            std::cmp::Reverse(r.pattern.len()),
        )
    });
    rules
}

pub(crate) fn process_pattern(pattern: &str) -> String {
    let mut expression = if pattern.contains('\\') {
        "(?i)^"
    } else {
        r"(?i)(?:^|[\\/])"
    }
    .to_string();
    for c in pattern.chars() {
        if matches!(
            c,
            '\\' | '.' | '+' | '*' | '?' | '(' | ')' | '|' | '[' | ']' | '{' | '}' | '^' | '$'
        ) {
            expression.push('\\');
        }
        expression.push(c);
    }
    expression.push('$');
    expression
}

fn home_outbound(home: &ServerEndpoint, tag: &str, id: &str) -> Value {
    json!({"type": "vless", "tag": tag, "server": home.host, "server_port": home.port,
        "uuid": id, "flow": "xtls-rprx-vision", "network": "tcp",
        "tls": {"enabled": true, "server_name": home.server_name,
            "utls": {"enabled": true, "fingerprint": "chrome"},
            "reality": {"enabled": true, "public_key": home.public_key, "short_id": home.short_id}}})
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, rename_all = "camelCase")]
pub struct ProxyListen {
    pub bind: String,
    pub port: u16,
    pub username: String,
    pub password: String,
}

impl Default for ProxyListen {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1".into(),
            port: 17770,
            username: String::new(),
            password: String::new(),
        }
    }
}

impl ProxyListen {
    pub fn validate(&mut self) -> Result<(), String> {
        self.bind = self.bind.trim().to_owned();
        if self.bind != "127.0.0.1" && self.bind != "0.0.0.0" {
            return Err("Допустимы только адреса 127.0.0.1 и 0.0.0.0".into());
        }
        if !(1024..=65531).contains(&self.port) {
            return Err("Укажите порт от 1024 до 65531".into());
        }
        self.username = self.username.trim().to_owned();
        if self.username.len() > 128 || self.username.contains([':', '\r', '\n', '\0']) {
            return Err("Недопустимый логин прокси".into());
        }
        if self.password.len() > 512 || self.password.contains(['\r', '\n', '\0']) {
            return Err("Недопустимый пароль прокси".into());
        }
        if self.username.is_empty() && !self.password.is_empty() {
            return Err("Укажите логин для пароля прокси".into());
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct Ports {
    pub proxy: u16,
    pub probe: u16,
    pub control: u16,
    pub listen: ProxyListen,
}

#[allow(clippy::too_many_arguments)]
fn assemble_config(
    mut outbounds: Vec<Value>,
    candidates: Vec<Candidate>,
    has_server_direct: bool,
    ordered: Vec<Rule>,
    profile: Profile,
    custom: Action,
    ports: &Ports,
    secret: &str,
) -> Generated {
    let mut tags: Vec<_> = candidates.iter().map(|c| c.tag.as_str()).collect();
    tags.push("unavailable");
    outbounds.push(
        json!({"type": "selector", "tag": "selected-proxy", "outbounds": tags,
        "default": "unavailable", "interrupt_exist_connections": true}),
    );
    let mut users: Vec<_> = candidates
        .iter()
        .map(|c| json!({"username": c.tag, "password": secret}))
        .collect();
    if has_server_direct {
        users.push(json!({"username": "server-direct", "password": secret}));
    }
    let mut apps_inbound = json!({
        "type": "mixed",
        "tag": "apps",
        "listen": ports.listen.bind,
        "listen_port": ports.listen.port
    });
    if !ports.listen.username.is_empty() {
        apps_inbound["users"] = json!([{
            "username": ports.listen.username,
            "password": ports.listen.password
        }]);
    }
    let inbounds = [
        apps_inbound,
        json!({"type": "mixed", "tag": "browser-proxy", "listen": "127.0.0.1", "listen_port": ports.proxy + 2}),
        json!({"type": "mixed", "tag": "browser-direct", "listen": "127.0.0.1", "listen_port": ports.proxy + 3}),
        json!({"type": "mixed", "tag": "browser-server", "listen": "127.0.0.1", "listen_port": ports.proxy + 4}),
        json!({"type": "mixed", "tag": "probe", "listen": "127.0.0.1", "listen_port": ports.probe, "users": users}),
    ];
    let mut rules = vec![json!({"network": "udp", "action": "reject"})];
    rules.extend(candidates.iter().map(
        |c| json!({"inbound": "probe", "auth_user": c.tag, "action": "route", "outbound": c.tag}),
    ));
    if has_server_direct {
        rules.push(json!({"inbound": "probe", "auth_user": "server-direct", "action": "route", "outbound": "server-direct"}));
    }
    rules.push(json!({"inbound": "probe", "action": "reject"}));
    rules.push(json!({"action": "sniff", "timeout": "300ms"}));
    let default = match profile {
        Profile::DirectInternet => Action::LocalDirect,
        Profile::Custom => custom,
        _ => Action::Proxy,
    };
    let route_rule = |rule: &Rule| {
        let mut entry = route(rule.action, default);
        match rule.kind.as_str() {
            "domain" => entry["domain"] = json!([rule.pattern]),
            "suffix" => entry["domain_suffix"] = json!([rule.pattern]),
            "ip_cidr" => entry["ip_cidr"] = json!([rule.pattern]),
            "process" => entry["process_path_regex"] = json!([process_pattern(&rule.pattern)]),
            "package" => entry["package_name"] = json!([rule.pattern]),
            _ => return None,
        }
        Some(entry)
    };
    rules.extend(ordered.iter().filter(|r| r.locked).filter_map(route_rule));
    for (inbound, action) in [
        ("browser-proxy", Action::Proxy),
        ("browser-direct", Action::LocalDirect),
        (
            "browser-server",
            if has_server_direct {
                Action::ServerDirect
            } else {
                Action::LocalDirect
            },
        ),
    ] {
        let mut entry = route(action, default);
        entry["inbound"] = json!(inbound);
        rules.push(entry);
    }
    rules.extend(ordered.iter().filter(|r| !r.locked).filter_map(route_rule));
    rules.push(route(default, Action::Proxy));
    let config = json!({
        "log": {"disabled": true},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "dns": {"servers": [{"type": "local", "tag": "system"}]},
        "route": {"rules": rules, "default_domain_resolver": "system"},
        "experimental": {"clash_api": {"external_controller": format!("127.0.0.1:{}", ports.control), "secret": secret}}
    });
    Generated { config, candidates }
}

pub fn generate(
    remote: &Configuration,
    local_groups: &[ServiceGroup],
    local: &[Rule],
    profile: Profile,
    custom: Action,
    ports: &Ports,
    secret: &str,
) -> Generated {
    let mut outbounds = vec![
        json!({"type": "direct", "tag": "local-direct"}),
        home_outbound(&remote.home, "server-direct", &remote.home.direct_id),
        json!({"type": "block", "tag": "unavailable"}),
    ];
    let mut candidates = Vec::new();
    if profile != Profile::HomeServer {
        for (index, proxy) in remote.proxies.iter().enumerate() {
            let tag = format!("direct-{index}");
            let mut out = json!({"type": "http", "tag": tag, "server": proxy.host, "server_port": proxy.port,
                "username": proxy.username, "password": proxy.password});
            if proxy.tls {
                out["tls"] = json!({"enabled": true, "server_name": proxy.host});
            }
            if !proxy.headers.is_empty() {
                out["headers"] = json!(proxy.headers);
            }
            outbounds.push(out);
            candidates.push(Candidate {
                tag,
                name: proxy.name.clone(),
            });
        }
    }
    if profile != Profile::DirectHttp {
        outbounds.push(home_outbound(&remote.home, "home", &remote.home.id));
        candidates.push(Candidate {
            tag: "home".into(),
            name: "HomeProxy Server".into(),
        });
    }
    let ordered = effective_rules(&remote.rules, &remote.groups, local_groups, local);
    assemble_config(
        outbounds, candidates, true, ordered, profile, custom, ports, secret,
    )
}

pub fn generate_custom(
    custom_proxy: &CustomProxy,
    local_groups: &[ServiceGroup],
    local: &[Rule],
    profile: Profile,
    custom: Action,
    ports: &Ports,
    secret: &str,
) -> Generated {
    let tag = "custom-0".to_string();
    let proto = custom_proxy.protocol.to_uppercase();
    let mut outbound = match proto.as_str() {
        "SOCKS5" => {
            let mut obj = json!({
                "type": "socks",
                "tag": tag,
                "server": custom_proxy.host,
                "server_port": custom_proxy.port,
                "version": "5"
            });
            if !custom_proxy.username.is_empty() {
                obj["username"] = json!(custom_proxy.username);
                obj["password"] = json!(custom_proxy.password);
            }
            obj
        }
        "VLESS" => {
            let mut obj = json!({
                "type": "vless",
                "tag": tag,
                "server": custom_proxy.host,
                "server_port": custom_proxy.port,
                "uuid": custom_proxy.username
            });
            if custom_proxy.tls || !custom_proxy.server_name.is_empty() {
                let sni = if custom_proxy.server_name.is_empty() {
                    &custom_proxy.host
                } else {
                    &custom_proxy.server_name
                };
                obj["tls"] = json!({"enabled": true, "server_name": sni});
            }
            obj
        }
        _ => {
            let mut obj = json!({
                "type": "http",
                "tag": tag,
                "server": custom_proxy.host,
                "server_port": custom_proxy.port
            });
            if !custom_proxy.username.is_empty() {
                obj["username"] = json!(custom_proxy.username);
                obj["password"] = json!(custom_proxy.password);
            }
            if custom_proxy.tls {
                let sni = if custom_proxy.server_name.is_empty() {
                    &custom_proxy.host
                } else {
                    &custom_proxy.server_name
                };
                obj["tls"] = json!({"enabled": true, "server_name": sni});
            }
            obj
        }
    };
    let _ = &mut outbound;
    let outbounds = vec![
        json!({"type": "direct", "tag": "local-direct"}),
        json!({"type": "block", "tag": "unavailable"}),
        outbound,
    ];
    let candidates = vec![Candidate {
        tag,
        name: format!("{}:{} ({})", custom_proxy.host, custom_proxy.port, proto),
    }];
    let ordered = effective_rules(&[], &[], local_groups, local);
    assemble_config(
        outbounds, candidates, false, ordered, profile, custom, ports, secret,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::Path;
    use std::process::{Command, Stdio};

    #[test]
    fn auto_prefers_direct_proxy_with_headers_and_expands_service_groups() {
        let mut headers = BTreeMap::new();
        headers.insert("X-Proxy-Auth".into(), "secret".into());
        let remote = Configuration {
            client_updates_paused: false,
            can_edit_global: false,
            api: 1,
            device_id: "dev1".into(),
            revision: 1,
            rules: vec![Rule {
                id: "r1".into(),
                user_id: String::new(),
                kind: "domain".into(),
                pattern: "disabled.example".into(),
                action: Action::Block,
                enabled: false,
                locked: false,
                revision: 1,
            }],
            groups: vec![
                ServiceGroup {
                    id: "g1".into(),
                    name: "ChatGPT".into(),
                    user_id: String::new(),
                    action: Action::Proxy,
                    enabled: true,
                    locked: false,
                    revision: 1,
                    entries: vec![
                        ServiceGroupEntry {
                            id: "e1".into(),
                            kind: "domain".into(),
                            pattern: "chatgpt.com".into(),
                            enabled: true,
                        },
                        ServiceGroupEntry {
                            id: "e2".into(),
                            kind: "ip_cidr".into(),
                            pattern: "104.18.0.0/16".into(),
                            enabled: true,
                        },
                        ServiceGroupEntry {
                            id: "e3".into(),
                            kind: "process".into(),
                            pattern: "chatgpt.exe".into(),
                            enabled: true,
                        },
                        ServiceGroupEntry {
                            id: "e3b".into(),
                            kind: "domain".into(),
                            pattern: "entry-off.example".into(),
                            enabled: false,
                        },
                    ],
                },
                ServiceGroup {
                    id: "g2".into(),
                    name: "DisabledGroup".into(),
                    user_id: String::new(),
                    action: Action::Block,
                    enabled: false,
                    locked: false,
                    revision: 1,
                    entries: vec![ServiceGroupEntry {
                        id: "e4".into(),
                        kind: "domain".into(),
                        pattern: "ignored.example".into(),
                        enabled: true,
                    }],
                },
            ],
            home: ServerEndpoint {
                host: "127.0.0.1".into(),
                port: 8444,
                id: "11111111-1111-1111-1111-111111111111".into(),
                direct_id: "22222222-2222-2222-2222-222222222222".into(),
                server_name: "localhost".into(),
                public_key: "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0".into(),
                short_id: "0123456789abcdef".into(),
            },
            proxies: vec![Proxy {
                id: "p1".into(),
                name: "External HTTP".into(),
                host: "127.0.0.1".into(),
                port: 3128,
                tls: false,
                username: "u".into(),
                password: "p".into(),
                headers,
            }],
            probe_url: "http://127.0.0.1:80/probe".into(),
        };
        let generated = generate(
            &remote,
            &[],
            &[],
            Profile::Auto,
            Action::Proxy,
            &Ports {
                proxy: 17770,
                probe: 17775,
                control: 17776,
                listen: ProxyListen::default(),
            },
            "secret",
        );
        assert_eq!(
            generated
                .candidates
                .iter()
                .map(|c| c.tag.as_str())
                .collect::<Vec<_>>(),
            vec!["direct-0", "home"]
        );
        let direct_out = generated.config["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["tag"] == "direct-0")
            .unwrap();
        assert_eq!(direct_out["headers"]["X-Proxy-Auth"], "secret");

        let route_rules = generated.config["route"]["rules"].as_array().unwrap();
        assert!(route_rules
            .iter()
            .any(|r| r["domain"] == json!(["chatgpt.com"])));
        assert!(route_rules
            .iter()
            .any(|r| r["ip_cidr"] == json!(["104.18.0.0/16"])));
        assert!(route_rules
            .iter()
            .any(|r| r.get("process_path_regex").is_some()));
        assert!(!route_rules
            .iter()
            .any(|r| r["domain"] == json!(["disabled.example"])
                || r["domain"] == json!(["ignored.example"])
                || r["domain"] == json!(["entry-off.example"])));

        let binary = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../.tools/sing-box-1.14.4-windows-amd64/sing-box.exe");
        if cfg!(windows) && binary.exists() {
            let mut child = Command::new(&binary)
                .args(["check", "-c", "stdin"])
                .stdin(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            child
                .stdin
                .take()
                .unwrap()
                .write_all(generated.config.to_string().as_bytes())
                .unwrap();
            let result = child.wait_with_output().unwrap();
            assert!(
                result.status.success(),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
        }
    }

    #[test]
    fn mixed_inbound_supports_lan_bind_and_auth() {
        let mut listen = ProxyListen {
            bind: "0.0.0.0".into(),
            port: 18080,
            username: "alice".into(),
            password: "secret".into(),
        };
        listen.validate().unwrap();
        let remote = Configuration {
            client_updates_paused: false,
            can_edit_global: false,
            api: 1,
            device_id: "dev1".into(),
            revision: 1,
            rules: vec![],
            groups: vec![],
            home: ServerEndpoint {
                host: "127.0.0.1".into(),
                port: 8444,
                id: "11111111-1111-1111-1111-111111111111".into(),
                direct_id: "22222222-2222-2222-2222-222222222222".into(),
                server_name: "localhost".into(),
                public_key: "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0".into(),
                short_id: "0123456789abcdef".into(),
            },
            proxies: vec![],
            probe_url: "http://127.0.0.1:80/probe".into(),
        };
        let generated = generate(
            &remote,
            &[],
            &[],
            Profile::Auto,
            Action::Proxy,
            &Ports {
                proxy: 18080,
                probe: 18085,
                control: 18086,
                listen,
            },
            "secret",
        );
        let apps = &generated.config["inbounds"][0];
        assert_eq!(apps["listen"], "0.0.0.0");
        assert_eq!(apps["listen_port"], 18080);
        assert_eq!(apps["users"][0]["username"], "alice");
        assert_eq!(apps["users"][0]["password"], "secret");

        let binary = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../.tools/sing-box-1.14.4-windows-amd64/sing-box.exe");
        if cfg!(windows) && binary.exists() {
            let mut child = Command::new(&binary)
                .args(["check", "-c", "stdin"])
                .stdin(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            child
                .stdin
                .take()
                .unwrap()
                .write_all(generated.config.to_string().as_bytes())
                .unwrap();
            let result = child.wait_with_output().unwrap();
            assert!(
                result.status.success(),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
        }
    }

    #[test]
    fn custom_proxy_supports_http_socks5_vless_and_local_groups() {
        let local_group = ServiceGroup {
            id: "lg1".into(),
            name: "LocalApp".into(),
            user_id: String::new(),
            action: Action::Proxy,
            enabled: true,
            locked: false,
            revision: 0,
            entries: vec![ServiceGroupEntry {
                id: "le1".into(),
                kind: "domain".into(),
                pattern: "local-group.example".into(),
                enabled: true,
            }],
        };
        let ports = Ports {
            proxy: 17770,
            probe: 17775,
            control: 17776,
            listen: ProxyListen::default(),
        };
        let binary = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../.tools/sing-box-1.14.4-windows-amd64/sing-box.exe");
        for (proto, user, tls) in [
            ("HTTP", "alice", false),
            ("SOCKS5", "alice", false),
            ("VLESS", "11111111-1111-1111-1111-111111111111", true),
        ] {
            let mut cp = CustomProxy {
                protocol: proto.into(),
                host: "proxy.example.com".into(),
                port: 8443,
                username: user.into(),
                password: "secret".into(),
                tls,
                server_name: String::new(),
            };
            cp.validate().unwrap();
            let generated = generate_custom(
                &cp,
                std::slice::from_ref(&local_group),
                &[],
                Profile::DirectInternet,
                Action::Proxy,
                &ports,
                "secret",
            );
            assert_eq!(generated.candidates.len(), 1);
            assert_eq!(generated.candidates[0].tag, "custom-0");
            let route_rules = generated.config["route"]["rules"].as_array().unwrap();
            assert!(route_rules
                .iter()
                .any(|r| r["domain"] == json!(["local-group.example"])));
            if cfg!(windows) && binary.exists() {
                let mut child = Command::new(&binary)
                    .args(["check", "-c", "stdin"])
                    .stdin(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .unwrap();
                child
                    .stdin
                    .take()
                    .unwrap()
                    .write_all(generated.config.to_string().as_bytes())
                    .unwrap();
                let result = child.wait_with_output().unwrap();
                assert!(
                    result.status.success(),
                    "{proto}: {}",
                    String::from_utf8_lossy(&result.stderr)
                );
            }
        }
    }
}
