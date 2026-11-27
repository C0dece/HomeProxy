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
    policy::{
        effective_rules, generate, generate_custom, parse_web, Action, Configuration, CustomProxy,
        Ports, Profile, ProxyListen, Rule, ServiceGroup,
    },
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
    pub handoff: bool,
}

#[derive(Clone, Serialize, Deserialize)]
struct Enrollment {
    url: Url,
    key: String,
}

fn default_config_mode() -> String {
    "subscription".into()
}

fn default_base_route() -> String {
    "direct".into()
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
struct Stored {
    enrollment: Option<Enrollment>,
    remote: Option<Configuration>,
    previous_ack: u64,
    local: Vec<Rule>,
    local_groups: Vec<ServiceGroup>,
    queue: Vec<Rule>,
    delete_queue: Vec<String>,
    profile: Profile,
    custom: Action,
    enabled: bool,
    proxy_listen: ProxyListen,
    #[serde(default = "default_config_mode")]
    config_mode: String,
    custom_proxy: Option<CustomProxy>,
    routing_mode: String,
    #[serde(default = "default_base_route")]
    auto_base_route: String,
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
            local_groups: Vec::new(),
            queue: Vec::new(),
            delete_queue: Vec::new(),
            profile: Profile::Auto,
            custom: Action::Proxy,
            enabled: true,
            proxy_listen: ProxyListen::default(),
            config_mode: default_config_mode(),
            custom_proxy: None,
            routing_mode: String::new(),
            auto_base_route: default_base_route(),
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
    if options.handoff {
        prepare_tun_handoff(&options)?;
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
    let mut state: Stored = match secure::load(&state_path) {
        Ok(data) => {
            serde_json::from_slice(&data).map_err(|_| "Сохранённая конфигурация повреждена")?
        }
        Err(e) if e.kind() == ErrorKind::NotFound => Stored::default(),
        Err(_) => return Err("Не удалось открыть сохранённую конфигурацию".into()),
    };
    if state.proxy_listen.validate().is_err() {
        state.proxy_listen = ProxyListen::default();
    }
    let base = if options.proxy_port != crate::PROXY_PORT {
        state.proxy_listen.port = options.proxy_port;
        options.proxy_port
    } else {
        state.proxy_listen.port
    };
    if options.port == base || (2..=4).any(|offset| options.port == base + offset) {
        return Err("Порты прокси и управления пересекаются".into());
    }
    let mut listen = state.proxy_listen.clone();
    listen.port = base;
    let mut reserved = [options.port, base, base + 2, base + 3, base + 4, 0];
    let probe = free_port(&reserved)?;
    reserved[5] = probe;
    let ports = Ports {
        proxy: base,
        probe,
        control: free_port(&reserved)?,
        listen,
    };
    let engine_token = random_token()?;
    let engine = Engine::new(
        options.binary.clone(),
        ports.clone(),
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
        if ctl.options.handoff {
            return Err(err);
        }
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
                if let Some(probe_url) = ctl.active_probe_url() {
                    let result = if ctl.engine.alive() {
                        ctl.engine.probe(&probe_url)
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

fn prepare_tun_handoff(options: &Options) -> Result<(), String> {
    if !options.tun || options.strict {
        return Err("Переключение поддерживается только для обычного TUN".into());
    }
    let request = |command| crate::control(&options.directory, options.port, command, &Value::Null);
    let status = request("status")?;
    if status["tun"] != false
        || (status["linked"] != true && status["configMode"] != "custom")
        || (status["linked"] == true && status["revision"].is_null())
    {
        return Err(
            "Для запуска TUN подключите локальный Agent и дождитесь получения настроек".into(),
        );
    }
    request("shutdown")?;
    let address = std::net::SocketAddr::from(([127, 0, 0, 1], options.port));
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if std::net::TcpStream::connect_timeout(&address, Duration::from_millis(100)).is_err() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err("Контроллер не освободил локальный порт".into())
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

    fn active_probe_url(&self) -> Option<String> {
        if self.state.config_mode == "custom" {
            self.state.custom_proxy.as_ref().map(|_| {
                self.state
                    .remote
                    .as_ref()
                    .map(|r| r.probe_url.clone())
                    .unwrap_or_else(|| "https://cp.cloudflare.com/generate_204".into())
            })
        } else {
            self.state.remote.as_ref().map(|r| r.probe_url.clone())
        }
    }

    fn apply(&mut self, state: &Stored, verify: bool) -> Result<(), String> {
        let mut ports = self.ports.clone();
        ports.listen = state.proxy_listen.clone();
        ports.proxy = ports.listen.port;
        if state.enabled && state.config_mode == "custom" {
            if let Some(cp) = &state.custom_proxy {
                let mut generated = generate_custom(
                    cp,
                    &state.local_groups,
                    &state.local,
                    state.profile,
                    state.custom,
                    &ports,
                    &self.engine_token,
                );
                if self.options.tun {
                    let scheme = if cp.tls { "https" } else { "http" };
                    let origin = Url::parse(&format!("{scheme}://{}:{}", cp.host, cp.port))
                        .map_err(|_| "Неверный адрес прокси для TUN")?;
                    let executable = std::env::current_exe()
                        .map_err(|_| "Не удалось определить путь контроллера")?;
                    windows_tun::configure(
                        &mut generated.config,
                        state.profile,
                        state.custom,
                        &origin,
                        &executable,
                        self.options.strict,
                    )?;
                }
                let probe_url = state
                    .remote
                    .as_ref()
                    .map(|r| r.probe_url.as_str())
                    .unwrap_or("https://cp.cloudflare.com/generate_204");
                self.engine.replace(generated, probe_url, verify)?;
            } else {
                self.engine.clear();
            }
        } else if let Some(remote) = state.remote.as_ref().filter(|_| state.enabled) {
            let mut generated = generate(
                remote,
                &state.local_groups,
                &state.local,
                state.profile,
                state.custom,
                &ports,
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
        self.ports = ports;
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
        next.config_mode = "subscription".into();
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
        self.online = matches!(response.status(), StatusCode::OK | StatusCode::NOT_MODIFIED);
        match response.status() {
            StatusCode::UNAUTHORIZED => {
                self.engine.clear();
                let next = Stored {
                    local: self.state.local.clone(),
                    proxy_listen: self.state.proxy_listen.clone(),
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
                if config.groups.len() > 256 {
                    return Err("Версия конфигурации несовместима".into());
                }
                for group in &mut config.groups {
                    if group.entries.len() > 256 {
                        return Err("Версия конфигурации несовместима".into());
                    }
                    for entry in &mut group.entries {
                        entry.normalize()?;
                    }
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
        while let Some(rule_id) = self.state.delete_queue.first().cloned() {
            let response = self
                .http
                .delete(Self::endpoint(&e, &format!("personal-rules/{rule_id}"))?)
                .bearer_auth(&e.key)
                .send()
                .map_err(|_| "Удаление правила сохранено для отправки")?;
            if !response.status().is_success() && response.status() != StatusCode::NOT_FOUND {
                return Err("Сервер не принял удаление персонального правила".into());
            }
            let mut next = self.state.clone();
            next.delete_queue.remove(0);
            self.save(&next)?;
            self.state = next;
            self.sync_delay = Duration::from_secs(1);
        }
        Ok(())
    }

    fn status(&mut self) -> Value {
        let remote = self.state.remote.as_ref();
        let routing_mode = if !self.state.enabled {
            "off"
        } else if self.state.routing_mode == "auto" || self.state.routing_mode == "all" {
            self.state.routing_mode.as_str()
        } else if self.state.profile == Profile::DirectInternet
            || (self.state.profile == Profile::Custom && self.state.custom == Action::LocalDirect)
        {
            "auto"
        } else {
            "all"
        };
        let auto_base_route = if self.state.auto_base_route == "proxy" {
            "proxy"
        } else {
            "direct"
        };
        let config_mode = if self.state.config_mode == "custom" {
            "custom"
        } else {
            "subscription"
        };
        json!({
            "linked": self.state.enrollment.is_some(),
            "online": self.online,
            "enabled": self.state.enabled,
            "tun": self.options.tun,
            "windows": cfg!(windows),
            "strict": self.options.strict,
            "routingActive": self.engine.alive(),
            "revision": remote.map(|r| r.revision),
            "clientUpdatesPaused": remote.is_some_and(|r| r.client_updates_paused),
            "canEditGlobal": remote.is_some_and(|r| r.can_edit_global),
            "configMode": config_mode,
            "customProxy": self.state.custom_proxy.as_ref().map(|cp| json!({
                "protocol": cp.protocol,
                "host": cp.host,
                "port": cp.port,
                "username": cp.username,
                "hasPassword": !cp.password.is_empty(),
                "tls": cp.tls,
                "serverName": cp.server_name,
            })),
            "routingMode": routing_mode,
            "autoBaseRoute": auto_base_route,
            "ack": self.state.previous_ack,
            "proxyPort": self.ports.proxy,
            "proxyListen": {
                "bind": self.state.proxy_listen.bind,
                "port": self.ports.proxy,
                "username": self.state.proxy_listen.username,
                "hasPassword": !self.state.proxy_listen.password.is_empty(),
            },
            "profile": self.state.profile,
            "custom": self.state.custom,
            "error": self.last_error,
            "rules": self.state.local,
            "localGroups": self.state.local_groups,
            "remoteRules": remote.map(|r| &r.rules),
            "remoteGroups": remote.map(|r| &r.groups),
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
                    local_groups: next.local_groups,
                    proxy_listen: next.proxy_listen,
                    custom_proxy: next.custom_proxy,
                    ..Stored::default()
                };
                self.commit(next, false)?;
                self.online = false;
                self.last_error = None;
            }
            "sync" => self.sync_now(),
            "probe" => {
                if let Some(url) = self.active_probe_url() {
                    self.engine.probe(&url)?;
                }
            }
            "enable" => {
                next.enabled = data["enabled"].as_bool().ok_or("Укажите состояние")?;
                if next.enabled && next.routing_mode == "off" {
                    next.routing_mode = "auto".into();
                }
                self.commit(next, false)?;
            }
            "quick-mode" => {
                if let Some(base) = data["baseRoute"].as_str() {
                    if base != "direct" && base != "proxy" {
                        return Err("Неверный базовый маршрут".into());
                    }
                    next.auto_base_route = base.into();
                }
                match data["mode"].as_str().unwrap_or_default() {
                    "off" => {
                        next.enabled = false;
                        next.routing_mode = "off".into();
                    }
                    "rules" | "auto" => {
                        next.enabled = true;
                        next.routing_mode = "auto".into();
                        next.profile = if next.auto_base_route == "proxy" {
                            Profile::Auto
                        } else {
                            Profile::DirectInternet
                        };
                    }
                    "all" => {
                        next.enabled = true;
                        next.routing_mode = "all".into();
                        next.profile = Profile::Auto;
                    }
                    _ => return Err("Неверный быстрый режим".into()),
                }
                self.commit(next, false)?;
            }
            "set-config-mode" => {
                let mode = data["mode"].as_str().unwrap_or_default();
                if mode != "subscription" && mode != "custom" {
                    return Err("Неверный источник конфигурации".into());
                }
                next.config_mode = mode.into();
                self.commit(next, false)?;
            }
            "save-custom-proxy" => {
                let keep_password = data["keepPassword"].as_bool().unwrap_or(false);
                let mut cp: CustomProxy = serde_json::from_value(data.clone())
                    .map_err(|_| "Неверные параметры прокси")?;
                if keep_password && cp.password.is_empty() {
                    if let Some(prev) = &self.state.custom_proxy {
                        cp.password = prev.password.clone();
                    }
                }
                cp.validate()?;
                next.custom_proxy = Some(cp);
                next.config_mode = "custom".into();
                self.commit(next, false)?;
            }
            "select-proxy" => {
                let tag = data["tag"]
                    .as_str()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .ok_or("Укажите выходной узел")?;
                self.engine.select_candidate(tag)?;
            }
            "save-local-group" => {
                let mut group: ServiceGroup =
                    serde_json::from_value(data.clone()).map_err(|_| "Неверная группа ресурсов")?;
                group.validate()?;
                group.locked = false;
                group.user_id.clear();
                group.revision = 0;
                if group.id.is_empty() {
                    group.id = random_token()?;
                }
                if let Some(pos) = next.local_groups.iter().position(|g| g.id == group.id) {
                    next.local_groups[pos] = group;
                } else {
                    next.local_groups
                        .retain(|g| !g.name.eq_ignore_ascii_case(&group.name));
                    next.local_groups.insert(0, group);
                }
                self.commit(next, false)?;
            }
            "delete-local-group" => {
                let id = data["id"]
                    .as_str()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .ok_or("Укажите идентификатор группы")?;
                next.local_groups.retain(|g| g.id != id);
                self.commit(next, false)?;
            }
            "save-shared-group" => {
                let Some(e) = next.enrollment.clone() else {
                    return Err("Сначала подключите подписку".into());
                };
                let mut group: ServiceGroup =
                    serde_json::from_value(data.clone()).map_err(|_| "Неверная группа ресурсов")?;
                group.validate()?;
                group.locked = false;
                let response = self
                    .http
                    .put(Self::endpoint(&e, "shared-groups")?)
                    .bearer_auth(&e.key)
                    .json(&group)
                    .send()
                    .map_err(|_| "Сервер недоступен. Общие ресурсы сейчас нельзя изменить")?;
                if response.status() == StatusCode::FORBIDDEN {
                    return Err("Нет прав на изменение общих ресурсов".into());
                }
                if response.status() == StatusCode::CONFLICT {
                    return Err("Конфликт версии ресурса. Обновите конфигурацию с сервера".into());
                }
                if !response.status().is_success() {
                    return Err("Сервер отклонил сохранение общего ресурса".into());
                }
                self.sync_now();
                if let Some(err) = &self.last_error {
                    return Err(err.clone());
                }
            }
            "delete-shared-group" => {
                let Some(e) = next.enrollment.clone() else {
                    return Err("Сначала подключите подписку".into());
                };
                let id = data["id"]
                    .as_str()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .ok_or("Укажите идентификатор группы")?;
                let response = self
                    .http
                    .delete(Self::endpoint(&e, &format!("shared-groups/{id}"))?)
                    .bearer_auth(&e.key)
                    .send()
                    .map_err(|_| "Сервер недоступен. Общие ресурсы сейчас нельзя изменить")?;
                if response.status() == StatusCode::FORBIDDEN {
                    return Err("Нет прав на изменение общих ресурсов".into());
                }
                if !response.status().is_success() && response.status() != StatusCode::NOT_FOUND {
                    return Err("Сервер отклонил удаление общего ресурса".into());
                }
                self.sync_now();
                if let Some(err) = &self.last_error {
                    return Err(err.clone());
                }
            }
            "proxy-settings" => {
                let bind = data["bind"]
                    .as_str()
                    .unwrap_or(&next.proxy_listen.bind)
                    .to_string();
                let port = data["port"]
                    .as_u64()
                    .and_then(|v| u16::try_from(v).ok())
                    .unwrap_or(next.proxy_listen.port);
                let username = data["username"]
                    .as_str()
                    .unwrap_or(&next.proxy_listen.username)
                    .to_string();
                let keep_password = data["keepPassword"].as_bool().unwrap_or(false);
                let password = match data["password"].as_str() {
                    Some(pw) if !pw.is_empty() || !keep_password => pw.to_string(),
                    _ => next.proxy_listen.password.clone(),
                };
                let mut listen = ProxyListen {
                    bind,
                    port,
                    username,
                    password,
                };
                listen.validate()?;
                if listen.username.is_empty() {
                    listen.password.clear();
                }
                let occupied = [self.options.port, self.ports.probe, self.ports.control];
                if occupied.contains(&listen.port)
                    || (2..=4).any(|off| occupied.contains(&(listen.port + off)))
                {
                    return Err("Выбранный порт пересекается со служебными портами агента".into());
                }
                next.proxy_listen = listen;
                self.commit(next, false)?;
            }
            "delete-personal-rule" => {
                let id = data["id"]
                    .as_str()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .ok_or("Укажите идентификатор правила")?;
                if next.enrollment.is_none() {
                    return Err("Сначала подключите учётную запись".into());
                }
                if let Some(remote) = next.remote.as_mut() {
                    remote
                        .rules
                        .retain(|r| r.id != id || r.locked || r.user_id.is_empty());
                }
                if !next.delete_queue.iter().any(|existing| existing == id) {
                    next.delete_queue.push(id.to_string());
                }
                self.next_sync = Instant::now();
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
                let remote = if self.state.config_mode == "custom" {
                    &[]
                } else {
                    self.state
                        .remote
                        .as_ref()
                        .map(|cfg| cfg.rules.as_slice())
                        .unwrap_or(&[])
                };
                let remote_groups = if self.state.config_mode == "custom" {
                    &[]
                } else {
                    self.state
                        .remote
                        .as_ref()
                        .map(|cfg| cfg.groups.as_slice())
                        .unwrap_or(&[])
                };
                let host_ip = host.parse::<std::net::IpAddr>().ok();
                let rule = effective_rules(
                    remote,
                    remote_groups,
                    &self.state.local_groups,
                    &self.state.local,
                )
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
                    "ip_cidr" => host_ip.is_some_and(|ip| cidr_contains(&r.pattern, ip)),
                    _ => false,
                });
                let mut action = rule.as_ref().map(|r| r.action).unwrap_or(Action::Auto);
                if action == Action::Auto {
                    action = match self.state.profile {
                        Profile::DirectInternet => Action::LocalDirect,
                        Profile::Custom => self.state.custom,
                        _ => Action::Proxy,
                    };
                }
                let group_name = rule.as_ref().and_then(|matched| {
                    if !matched.id.is_empty() {
                        remote_groups
                            .iter()
                            .find(|g| g.id == matched.id)
                            .map(|g| g.name.clone())
                    } else {
                        self.state
                            .local_groups
                            .iter()
                            .find(|g| {
                                g.enabled
                                    && g.action == matched.action
                                    && g.entries.iter().any(|e| {
                                        e.enabled
                                            && e.kind == matched.kind
                                            && e.pattern == matched.pattern
                                    })
                            })
                            .map(|g| g.name.clone())
                    }
                });
                let scope = rule
                    .as_ref()
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
                return Ok(json!({
                    "action": action,
                    "scope": scope,
                    "rule": rule,
                    "groupName": group_name,
                    "route": self.engine.status()
                }));
            }
            _ => return Err("Неизвестная команда".into()),
        }
        Ok(self.status())
    }
}

fn cidr_contains(cidr: &str, ip: std::net::IpAddr) -> bool {
    let Some((net_str, prefix_str)) = cidr.split_once('/') else {
        return false;
    };
    let (Ok(net_ip), Ok(prefix)) = (
        net_str.parse::<std::net::IpAddr>(),
        prefix_str.parse::<u32>(),
    ) else {
        return false;
    };
    match (net_ip, ip) {
        (std::net::IpAddr::V4(a), std::net::IpAddr::V4(b)) if prefix <= 32 => {
            let mask = if prefix == 0 {
                0
            } else {
                !0u32 << (32 - prefix)
            };
            (u32::from(a) & mask) == (u32::from(b) & mask)
        }
        (std::net::IpAddr::V6(a), std::net::IpAddr::V6(b)) if prefix <= 128 => {
            let mask = if prefix == 0 {
                0
            } else {
                !0u128 << (128 - prefix)
            };
            (u128::from(a) & mask) == (u128::from(b) & mask)
        }
        _ => false,
    }
}
