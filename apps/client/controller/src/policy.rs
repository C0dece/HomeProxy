use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

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
    #[serde(default)]
    pub locked: bool,
    #[serde(default)]
    pub revision: u64,
}

fn domain(value: &str) -> bool {
    value.len() <= 253
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

impl Rule {
    pub fn normalize(&mut self) -> Result<(), String> {
        self.pattern = if self.kind == "package" {
            self.pattern.trim().to_owned()
        } else {
            self.pattern.trim().to_lowercase()
        };
        let valid = match self.kind.as_str() {
            "domain" | "suffix" => {
                self.pattern
                    .truncate(self.pattern.trim_end_matches('.').len());
                domain(&self.pattern)
            }
            "process" => {
                self.pattern = self.pattern.replace('/', "\\");
                self.pattern.ends_with(".exe")
                    && self.pattern.len() > 4
                    && self.pattern.len() <= 1024
                    && !self.pattern.contains(['\r', '\n', '\0'])
            }
            "package" => {
                self.pattern.len() <= 255
                    && self.pattern.contains('.')
                    && self.pattern.split('.').all(|part| {
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

    pub fn same_target(&self, other: &Rule) -> bool {
        self.kind == other.kind && self.pattern == other.pattern
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
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Configuration {
    pub api: u32,
    pub device_id: String,
    pub revision: u64,
    pub rules: Vec<Rule>,
    pub home: ServerEndpoint,
    pub proxies: Vec<Proxy>,
    pub probe_url: String,
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

pub fn ordered_rules<'a>(synced: &'a [Rule], local: &'a [Rule]) -> Vec<&'a Rule> {
    let mut rules: Vec<_> = synced
        .iter()
        .chain(local)
        .filter(|r| r.action != Action::Inherit)
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

pub struct Ports {
    pub proxy: u16,
    pub probe: u16,
    pub control: u16,
}

pub fn generate(
    remote: &Configuration,
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
    if profile != Profile::DirectHttp {
        outbounds.push(home_outbound(&remote.home, "home", &remote.home.id));
        candidates.push(Candidate {
            tag: "home".into(),
            name: "HomeProxy Server".into(),
        });
    }
    if profile != Profile::HomeServer {
        for (index, proxy) in remote.proxies.iter().enumerate() {
            let tag = format!("backup-{index}");
            let mut out = json!({"type": "http", "tag": tag, "server": proxy.host, "server_port": proxy.port,
                "username": proxy.username, "password": proxy.password});
            if proxy.tls {
                out["tls"] = json!({"enabled": true, "server_name": proxy.host});
            }
            outbounds.push(out);
            candidates.push(Candidate {
                tag,
                name: proxy.name.clone(),
            });
        }
    }
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
    users.push(json!({"username": "server-direct", "password": secret}));
    let inbounds = [
        json!({"type": "mixed", "tag": "apps", "listen": "127.0.0.1", "listen_port": ports.proxy}),
        json!({"type": "mixed", "tag": "browser-proxy", "listen": "127.0.0.1", "listen_port": ports.proxy + 2}),
        json!({"type": "mixed", "tag": "browser-direct", "listen": "127.0.0.1", "listen_port": ports.proxy + 3}),
        json!({"type": "mixed", "tag": "browser-server", "listen": "127.0.0.1", "listen_port": ports.proxy + 4}),
        json!({"type": "mixed", "tag": "probe", "listen": "127.0.0.1", "listen_port": ports.probe, "users": users}),
    ];
    let mut rules = vec![json!({"network": "udp", "action": "reject"})];
    rules.extend(candidates.iter().map(
        |c| json!({"inbound": "probe", "auth_user": c.tag, "action": "route", "outbound": c.tag}),
    ));
    rules.push(json!({"inbound": "probe", "auth_user": "server-direct", "action": "route", "outbound": "server-direct"}));
    rules.push(json!({"inbound": "probe", "action": "reject"}));
    rules.push(json!({"action": "sniff", "timeout": "300ms"}));
    let default = match profile {
        Profile::DirectInternet => Action::LocalDirect,
        Profile::Custom => custom,
        _ => Action::Proxy,
    };
    let ordered = ordered_rules(&remote.rules, local);
    let route_rule = |rule: &Rule| {
        let mut entry = route(rule.action, default);
        match rule.kind.as_str() {
            "domain" => entry["domain"] = json!([rule.pattern]),
            "suffix" => entry["domain_suffix"] = json!([rule.pattern]),
            "process" => entry["process_path_regex"] = json!([process_pattern(&rule.pattern)]),
            "package" => entry["package_name"] = json!([rule.pattern]),
            _ => return None,
        }
        Some(entry)
    };
    rules.extend(
        ordered
            .iter()
            .filter(|r| r.locked)
            .filter_map(|r| route_rule(r)),
    );
    for (inbound, action) in [
        ("browser-proxy", Action::Proxy),
        ("browser-direct", Action::LocalDirect),
        ("browser-server", Action::ServerDirect),
    ] {
        let mut entry = route(action, default);
        entry["inbound"] = json!(inbound);
        rules.push(entry);
    }
    rules.extend(
        ordered
            .iter()
            .filter(|r| !r.locked)
            .filter_map(|r| route_rule(r)),
    );
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
