use std::{
    io::{ErrorKind, Read},
    net::TcpListener,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use reqwest::{
    blocking::{Client, Response},
    header::IF_NONE_MATCH,
    StatusCode, Url,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tiny_http::{Header, Request, Server};

use crate::{
    engine::Engine,
    policy::{generate, ordered_rules, parse_web, Action, Configuration, Ports, Profile, Rule},
    random_token, secure, windows_tun,
};

pub struct Options {
    pub directory: PathBuf,
    pub binary: PathBuf,
    pub port: u16,
    pub proxy_port: u16,
    pub allow_loopback_http: bool,
    pub probe_seconds: u64,
    pub tun: bool,
    pub strict: bool,
}

#[derive(Clone, Serialize, Deserialize)]
struct Enrollment {
    url: Url,
    key: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
struct Stored {
    enrollment: Option<Enrollment>,
    remote: Option<Configuration>,
    previous_ack: u64,
    local: Vec<Rule>,
    queue: Vec<Rule>,
    profile: Profile,
    custom: Action,
    enabled: bool,
}

pub fn updates_paused(directory: &Path) -> Result<bool, String> {
    let data = match secure::load(&directory.join("state.dpapi")) {
        Ok(data) => data,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(false),
        Err(_) => return Err("Не удалось прочитать политику обновлений".into()),
    };
    let state: Stored =
        serde_json::from_slice(&data).map_err(|_| "Не удалось прочитать политику обновлений")?;
    Ok(state
        .remote
        .is_some_and(|config| config.client_updates_paused))
}

impl Default for Stored {
    fn default() -> Self {
        Self {
            enrollment: None,
            remote: None,
            previous_ack: 0,
            local: Vec::new(),
            queue: Vec::new(),
            profile: Profile::Auto,
            custom: Action::Proxy,
            enabled: true,
        }
    }
}

struct Controller {
    options: Options,
    ports: Ports,
    state: Stored,
    state_path: PathBuf,
    http: Client,
    engine: Engine,
    engine_token: String,
    online: bool,
    last_error: Option<String>,
    next_sync: Instant,
    sync_delay: Duration,
    stopping: bool,
}

fn free_port(excluded: &[u16]) -> Result<u16, String> {
    for _ in 0..16 {
        let port = TcpListener::bind(("127.0.0.1", 0))
            .and_then(|listener| listener.local_addr())
            .map_err(|_| "Не удалось выделить локальный порт")?
            .port();
        if !excluded.contains(&port) {
            return Ok(port);
        }
    }
    Err("Не удалось выделить отдельный порт ядра".into())
}

fn exact(value: &str, expected: &str) -> bool {
    if value.len() != expected.len() {
        return false;
    }
    value
        .bytes()
        .zip(expected.bytes())
        .fold(0, |r, (a, b)| r | (a ^ b))
        == 0
}

pub fn serve(options: Options) -> Result<(), String> {
    if options.tun {
        windows_tun::check_elevation()?;
    }
    if options.proxy_port > 65531
        || options.port == options.proxy_port
        || (2..=4).any(|offset| options.port == options.proxy_port + offset)
    {
        return Err("Порты прокси и управления пересекаются".into());
    }
    let mut access = String::new();
    let server = Server::http(("127.0.0.1", options.port))
        .map_err(|_| "Локальный контроллер уже работает или порт занят")?;
    std::fs::create_dir_all(&options.directory).map_err(|_| "Не удалось создать каталог агента")?;
    let control_path = options.directory.join("control.dpapi");
    let key = match secure::load(&control_path) {
        Ok(bytes) => String::from_utf8(bytes).map_err(|_| "Ключ управления повреждён")?,
        Err(e) if e.kind() == ErrorKind::NotFound => {
            let key = random_token()?;
            secure::save(&control_path, key.as_bytes())
                .map_err(|_| "Не удалось сохранить ключ управления")?;
            key
        }
        Err(_) => return Err("Не удалось прочитать ключ управления".into()),
    };
    access.push_str("Bearer ");
    access.push_str(&key);
    let state_path = options.directory.join("state.dpapi");
    let state = match secure::load(&state_path) {
        Ok(data) => {
            serde_json::from_slice(&data).map_err(|_| "Сохранённая конфигурация повреждена")?
        }
        Err(e) if e.kind() == ErrorKind::NotFound => Stored::default(),
        Err(_) => return Err("Не удалось открыть сохранённую конфигурацию".into()),
    };
    let base = options.proxy_port;
    let mut reserved = [options.port, base, base + 2, base + 3, base + 4, 0];
    let probe = free_port(&reserved)?;
    reserved[5] = probe;
    let ports = Ports {
        proxy: base,
        probe,
        control: free_port(&reserved)?,
    };
    let engine_token = random_token()?;
    let engine = Engine::new(
        options.binary.clone(),
        Ports { ..ports },
        engine_token.clone(),
        options.tun,
        options.strict,
    )?;
    let http = Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(8));
    #[cfg(windows)]
    let http = if options.strict {
        let resolver = crate::bootstrap_dns::BootstrapDns::new()
            .map_err(|_| "Не удалось подготовить защищённый DNS для STRICT")?;
        http.dns_resolver(std::sync::Arc::new(resolver))
    } else {
        http
    };
    let http = http
        .build()
        .map_err(|_| "Не удалось создать защищённое подключение")?;
    let mut ctl = Controller {
        options,
        ports,
        state,
        state_path,
        http,
        engine,
        engine_token,
        online: false,
        last_error: None,
        next_sync: Instant::now(),
        sync_delay: Duration::from_secs(5),
        stopping: false,
    };
    if let Err(err) = ctl.apply(&ctl.state.clone(), false) {
        ctl.last_error = Some(err);
    }
    let mut next_probe = Instant::now() + Duration::from_secs(ctl.options.probe_seconds);
    loop {
        if let Some(mut request) = server
            .recv_timeout(Duration::from_millis(250))
            .map_err(|_| "Ошибка локального контроллера")?
        {
            let allowed = request
                .headers()
                .iter()
                .any(|h| h.field.equiv("Authorization") && exact(h.value.as_str(), &access));
            if !allowed || request.method().as_str() != "POST" || request.url() != "/command" {
                reply(request, 401, json!({"error": "Нет доступа"}));
                continue;
            }
            let mut bytes = Vec::new();
            let read = request.as_reader().take(32769).read_to_end(&mut bytes);
            let data = if read.is_ok() && bytes.len() <= 32768 {
                serde_json::from_slice::<Value>(&bytes).ok()
            } else {
                None
            };
            let result = data
                .as_ref()
                .ok_or_else(|| "Неверный запрос".into())
                .and_then(|body| {
                    ctl.command(body["command"].as_str().unwrap_or(""), &body["data"])
                });
            match result {
                Ok(body) => reply(request, 200, body),
                Err(err) => reply(request, 422, json!({"error": err})),
            }
            if ctl.stopping {
                return Ok(());
            }
        }
        if Instant::now() >= next_probe {
            if ctl.state.enabled {
                if let Some(config) = &ctl.state.remote {
                    let result = if ctl.engine.alive() {
                        ctl.engine.probe(&config.probe_url)
                    } else {
                        ctl.apply(&ctl.state.clone(), false)
                    };
                    if let Err(error) = result {
                        ctl.last_error = Some(error);
                    }
                }
            }
            next_probe = Instant::now() + Duration::from_secs(ctl.options.probe_seconds);
        }
        if ctl.state.enrollment.is_some() && Instant::now() >= ctl.next_sync {
            ctl.sync_now();
        }
    }
}

fn reply(request: Request, status: u16, value: Value) {
    let response = tiny_http::Response::from_string(value.to_string())
        .with_status_code(status)
        .with_header(Header::from_bytes("Content-Type", "application/json").unwrap())
        .with_header(Header::from_bytes("Cache-Control", "no-store").unwrap());
    let _ = request.respond(response);
}

fn response_json<T: serde::de::DeserializeOwned>(response: Response) -> Result<T, String> {
    let mut bytes = Vec::new();
    response
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "Не удалось получить ответ сервера")?;
    if bytes.len() > 1024 * 1024 {
        return Err("Ответ сервера превышает допустимый размер".into());
    }
    serde_json::from_slice(&bytes).map_err(|_| "Несовместимый ответ сервера".into())
}

impl Controller {
    fn save(&self, state: &Stored) -> Result<(), String> {
        let data = serde_json::to_vec(state).map_err(|_| "Невозможно сохранить конфигурацию")?;
        secure::save(&self.state_path, &data)
            .map_err(|_| "Не удалось записать защищённую конфигурацию".into())
    }

    fn apply(&mut self, state: &Stored, verify: bool) -> Result<(), String> {
        if let Some(remote) = state.remote.as_ref().filter(|_| state.enabled) {
            let mut generated = generate(
                remote,
                &state.local,
                state.profile,
                state.custom,
                &self.ports,
                &self.engine_token,
            );
            if self.options.tun {
                let origin = &state
                    .enrollment
                    .as_ref()
                    .ok_or("Отсутствует адрес сервера")?
                    .url;
                let executable = std::env::current_exe()
                    .map_err(|_| "Не удалось определить путь контроллера")?;
                windows_tun::configure(
                    &mut generated.config,
                    state.profile,
                    state.custom,
                    origin,
                    &executable,
                    self.options.strict,
                )?;
            }
            self.engine.replace(generated, &remote.probe_url, verify)?;
        } else {
            self.engine.clear();
        }
        Ok(())
    }

    fn commit(&mut self, state: Stored, verify: bool) -> Result<(), String> {
        self.apply(&state, verify)?;
        if let Err(error) = self.save(&state) {
            let _ = self.apply(&self.state.clone(), false);
            return Err(error);
        }
        self.state = state;
        Ok(())
    }

    fn parse_link(&self, value: &str) -> Result<(Url, String), String> {
        let mut url = parse_web(value, self.options.allow_loopback_http)?;
        let token = url
            .fragment()
            .ok_or("В ссылке отсутствует ключ подключения")?
            .to_string();
        if url.path() != "/connect"
            || url.query().is_some()
            || token.len() != 43
            || !token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return Err("Неверная персональная ссылка".into());
        }
        url.set_fragment(None);
        url.set_path("/");
        Ok((url, token))
    }

    fn endpoint(e: &Enrollment, endpoint: &str) -> Result<Url, String> {
        e.url
            .join(&format!("api/v1/{endpoint}"))
            .map_err(|_| "Неверный адрес сервера".into())
    }

    fn connect(&mut self, link: &str) -> Result<(), String> {
        if self.state.enrollment.is_some() {
            return Err("Сначала отключите текущую учётную запись".into());
        }
        let (url, token) = self.parse_link(link)?;
        let enrollment = Enrollment {
            url,
            key: random_token()?,
        };
        let response = self
            .http
            .post(Self::endpoint(&enrollment, "connect")?)
            .json(&json!({"token": token, "deviceKey": enrollment.key, "transport": "agent"}))
            .send();
        if std::env::var_os("HOMEPROXY_DIAGNOSTIC_CORE_STDERR").is_some() {
            if let Err(error) = &response {
                let source = std::error::Error::source(error);
                eprintln!(
                    "Agent connection failed: {}",
                    source.map_or_else(|| error.to_string(), |cause| format!("{cause:?}"))
                );
            }
        }
        match response {
            Ok(response) if response.status() == StatusCode::CREATED => (),
            Ok(response) if response.status().is_client_error() => {
                return Err("Ссылка недействительна, просрочена или использована".into())
            }
            _ => {
                let retry = self
                    .http
                    .get(Self::endpoint(&enrollment, "config")?)
                    .bearer_auth(&enrollment.key)
                    .send();
                if !retry.is_ok_and(|r| r.status().is_success()) {
                    return Err("Сервер подключения недоступен".into());
                }
            }
        }
        let mut next = self.state.clone();
        next.enrollment = Some(enrollment);
        self.commit(next, false)?;
        self.sync_now();
        Ok(())
    }

    fn sync_now(&mut self) {
        match self.sync() {
            Ok(()) => {
                self.last_error = None;
                self.sync_delay = Duration::from_secs(10);
            }
            Err(error) => {
                self.last_error = Some(error);
                self.sync_delay = (self.sync_delay * 2).min(Duration::from_secs(120));
            }
        }
        self.next_sync = Instant::now() + self.sync_delay;
    }

    fn sync(&mut self) -> Result<(), String> {
        let Some(e) = self.state.enrollment.clone() else {
            return Ok(());
        };
        let mut request = self
            .http
            .get(Self::endpoint(&e, "config")?)
            .bearer_auth(&e.key)
            .header(
                "X-HomeProxy-Version",
                option_env!("HOMEPROXY_RELEASE_VERSION").unwrap_or(env!("CARGO_PKG_VERSION")),
            );
        if let Some(current) = &self.state.remote {
            request = request.header(
                IF_NONE_MATCH,
                format!("\"{}-{}\"", current.device_id, current.revision),
            );
        }
        self.online = false;
        let response = request
            .send()
            .map_err(|_| "Сервер недоступен. Используется сохранённая конфигурация")?;
        self.online = true;
        match response.status() {
            StatusCode::UNAUTHORIZED => {
                self.engine.clear();
                let next = Stored {
                    local: self.state.local.clone(),
                    ..Stored::default()
                };
                // If a disk write fails, keep the revoked credentials in memory
                // for another cleanup attempt while the engine remains stopped.
                self.save(&next)?;
                self.state = next;
                return Err("Сервер отозвал доступ устройства".into());
            }
            StatusCode::NOT_MODIFIED => (),
            StatusCode::OK => {
                let mut config: Configuration = response_json(response)?;
                parse_web(&config.probe_url, self.options.allow_loopback_http)?;
                if config.api != 1
                    || config.revision == 0
                    || config.proxies.len() > 16
                    || config.rules.len() > 4096
                    || self.state.remote.as_ref().is_some_and(|old| {
                        old.device_id != config.device_id || old.revision >= config.revision
                    })
                {
                    return Err("Версия конфигурации несовместима".into());
                }
                for rule in &mut config.rules {
                    rule.normalize()?;
                }
                let verify = self.state.remote.as_ref().is_some_and(|old| {
                    let removed = old.proxies.iter().any(|known| {
                        !config
                            .proxies
                            .iter()
                            .any(|candidate| candidate.id == known.id)
                    });
                    !removed && (old.home != config.home || old.proxies != config.proxies)
                });
                let mut next = self.state.clone();
                next.remote = Some(config);
                self.commit(next, verify)?;
            }
            _ => return Err("Сервер временно не может выдать настройки".into()),
        }
        if let Some(revision) = self
            .state
            .remote
            .as_ref()
            .map(|c| c.revision)
            .filter(|&rev| rev > self.state.previous_ack)
        {
            if !self.state.enabled || self.engine.alive() {
                let result = self
                    .http
                    .post(Self::endpoint(&e, "ack")?)
                    .bearer_auth(&e.key)
                    .json(&json!({"revision": revision}))
                    .send();
                if !result.is_ok_and(|r| r.status().is_success()) {
                    return Err("Сервер не подтвердил получение версии".into());
                }
                let mut next = self.state.clone();
                next.previous_ack = revision;
                self.save(&next)?;
                self.state = next;
            }
        }
        while let Some(rule) = self.state.queue.first().cloned() {
            let response = self
                .http
                .put(Self::endpoint(&e, "personal-rules")?)
                .bearer_auth(&e.key)
                .json(&rule)
                .send()
                .map_err(|_| "Изменение сохранено для отправки")?;
            if response.status() == StatusCode::CONFLICT {
                return Err(
                    "Конфликт персонального правила. Откройте правила и проверьте текущую версию"
                        .into(),
                );
            }
            if !response.status().is_success() {
                return Err("Сервер не принял персональное правило".into());
            }
            let mut next = self.state.clone();
            next.queue.remove(0);
            self.save(&next)?;
            self.state = next;
            self.sync_delay = Duration::from_secs(1);
        }
        Ok(())
    }

    fn status(&self) -> Value {
        let remote = self.state.remote.as_ref();
        json!({
            "linked": self.state.enrollment.is_some(),
            "online": self.online,
            "enabled": self.state.enabled,
            "tun": self.options.tun,
            "strict": self.options.strict,
            "revision": remote.map(|r| r.revision),
            "clientUpdatesPaused": remote.is_some_and(|r| r.client_updates_paused),
            "ack": self.state.previous_ack,
            "proxyPort": self.ports.proxy,
            "profile": self.state.profile,
            "custom": self.state.custom,
            "error": self.last_error,
            "rules": self.state.local,
            "remoteRules": remote.map(|r| &r.rules),
            "pending": self.state.queue,
            "route": self.engine.status()
        })
    }

    fn command(&mut self, name: &str, data: &Value) -> Result<Value, String> {
        let mut next = self.state.clone();
        match name {
            "status" => (),
            "shutdown" => {
                self.engine.clear();
                self.stopping = true;
            }
            "connect" => self.connect(data["link"].as_str().unwrap_or_default())?,
            "disconnect" => {
                next = Stored {
                    local: next.local,
                    ..Stored::default()
                };
                self.commit(next, false)?;
                self.online = false;
                self.last_error = None;
            }
            "sync" => self.sync_now(),
            "probe" => {
                if let Some(c) = &self.state.remote {
                    self.engine.probe(&c.probe_url)?;
                }
            }
            "enable" => {
                next.enabled = data["enabled"].as_bool().ok_or("Укажите состояние")?;
                self.commit(next, false)?;
            }
            "profile" => {
                next.profile = serde_json::from_value(data["profile"].clone())
                    .map_err(|_| "Неверный профиль")?;
                if next.profile == Profile::Custom {
                    next.custom = serde_json::from_value(data["action"].clone())
                        .map_err(|_| "Выберите маршрут")?;
                    if matches!(next.custom, Action::Auto | Action::Inherit) {
                        return Err("Выберите явный маршрут".into());
                    }
                }
                self.commit(next, false)?;
            }
            "local-rule" | "personal-rule" => {
                let mut rule: Rule =
                    serde_json::from_value(data.clone()).map_err(|_| "Неверное правило")?;
                if rule.kind == "package" {
                    return Err("Правила по имени пакета доступны на Android".into());
                }
                rule.normalize()?;
                rule.locked = false;
                rule.id.clear();
                rule.user_id.clear();
                if name == "local-rule" {
                    rule.revision = 0;
                    next.local.retain(|existing| !existing.same_target(&rule));
                    if rule.action != Action::Inherit {
                        next.local.push(rule);
                    }
                } else {
                    if next.enrollment.is_none() {
                        return Err("Сначала подключите учётную запись".into());
                    }
                    next.queue.retain(|existing| !existing.same_target(&rule));
                    next.queue.push(rule);
                    self.next_sync = Instant::now();
                }
                self.commit(next, false)?;
            }
            "discard-pending" => {
                let pattern = data["pattern"].as_str().unwrap_or_default();
                let kind = data["kind"].as_str().unwrap_or_default();
                next.queue
                    .retain(|r| r.pattern != pattern || r.kind != kind);
                self.commit(next, false)?;
                self.next_sync = Instant::now();
            }
            "list-apps" => return Ok(json!(crate::processes::running()?)),
            "explain" => {
                let host = data["host"]
                    .as_str()
                    .unwrap_or_default()
                    .trim_end_matches('.')
                    .to_lowercase();
                let executable = data["exe"]
                    .as_str()
                    .unwrap_or_default()
                    .trim()
                    .replace('/', "\\")
                    .to_lowercase();
                let app_name = executable.rsplit('\\').next().unwrap_or("");
                let remote = self
                    .state
                    .remote
                    .as_ref()
                    .map(|cfg| cfg.rules.as_slice())
                    .unwrap_or(&[]);
                let rule = ordered_rules(remote, &self.state.local)
                    .into_iter()
                    .find(|r| match r.kind.as_str() {
                        "process" => {
                            r.pattern == executable
                                || (!r.pattern.contains('\\') && r.pattern == app_name)
                        }
                        "domain" => r.pattern == host,
                        "suffix" => {
                            r.pattern == host
                                || host
                                    .strip_suffix(&r.pattern)
                                    .is_some_and(|prefix| prefix.ends_with('.'))
                        }
                        _ => false,
                    });
                let mut action = rule.map(|r| r.action).unwrap_or(Action::Auto);
                if action == Action::Auto {
                    action = match self.state.profile {
                        Profile::DirectInternet => Action::LocalDirect,
                        Profile::Custom => self.state.custom,
                        _ => Action::Proxy,
                    };
                }
                let scope = rule
                    .map(|r| {
                        if r.locked {
                            "LOCKED"
                        } else if r.id.is_empty() {
                            "LOCAL"
                        } else if r.user_id.is_empty() {
                            "GLOBAL"
                        } else {
                            "PERSONAL"
                        }
                    })
                    .unwrap_or("DEFAULT");
                return Ok(
                    json!({"action": action, "scope": scope, "rule": rule, "route": self.engine.status()}),
                );
            }
            _ => return Err("Неизвестная команда".into()),
        }
        Ok(self.status())
    }
}
