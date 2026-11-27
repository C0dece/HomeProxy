use std::{
    collections::HashMap,
    io::Write,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use reqwest::blocking::Client;
use serde_json::{json, Value};

use crate::policy::{Candidate, Generated, Ports};

pub struct Engine {
    path: PathBuf,
    ports: Ports,
    token: String,
    client: Client,
    tun: bool,
    child: Option<Child>,
    installed: Option<Generated>,
    selected: Option<String>,
    manual_selected: Option<String>,
    health: HashMap<String, u8>,
    latencies: HashMap<String, u32>,
    direct_available: bool,
    #[cfg(windows)]
    job: windows_sys::Win32::Foundation::HANDLE,
    #[cfg(windows)]
    interface_permit: Option<crate::windows_firewall::Session>,
    #[cfg(windows)]
    strict: Option<crate::windows_firewall::StrictGuard>,
}

impl Engine {
    pub fn new(
        path: PathBuf,
        ports: Ports,
        token: String,
        tun: bool,
        strict: bool,
    ) -> Result<Self, String> {
        let client = Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_millis(750))
            .build()
            .map_err(|_| "Не удалось создать локальный HTTP-клиент")?;
        #[cfg(windows)]
        let guard = if strict {
            let agent =
                std::env::current_exe().map_err(|_| "Не удалось определить путь контроллера")?;
            let core =
                std::path::absolute(&path).map_err(|_| "Не удалось определить путь sing-box")?;
            Some(crate::windows_firewall::StrictGuard::arm(&agent, &core)?)
        } else {
            None
        };
        #[cfg(not(windows))]
        if strict {
            return Err("Windows STRICT доступен только на Windows".into());
        }
        Ok(Self {
            path,
            ports,
            token,
            client,
            tun,
            child: None,
            installed: None,
            selected: None,
            manual_selected: None,
            health: HashMap::new(),
            latencies: HashMap::new(),
            direct_available: false,
            #[cfg(windows)]
            job: create_job().map_err(|_| "Не удалось подготовить Windows Job Object")?,
            #[cfg(windows)]
            interface_permit: None,
            #[cfg(windows)]
            strict: guard,
        })
    }

    fn command(path: &Path, action: &str) -> Command {
        let mut command = Command::new(path);
        command
            .args([action, "--disable-color", "-c", "stdin"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null());
        if std::env::var_os("HOMEPROXY_DIAGNOSTIC_CORE_STDERR").is_none() {
            command.stderr(Stdio::null());
        }
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x08000000);
        }
        command
    }

    fn spawn(&self, config: &Value, action: &str) -> Result<Child, String> {
        let mut diagnostic_config;
        let config = if std::env::var_os("HOMEPROXY_DIAGNOSTIC_CORE_STDERR").is_some() {
            diagnostic_config = config.clone();
            diagnostic_config["log"] = json!({"level": "info"});
            &diagnostic_config
        } else {
            config
        };
        let bytes = serde_json::to_vec(config).map_err(|_| "Неверная конфигурация")?;
        let mut child = Self::command(&self.path, action)
            .spawn()
            .map_err(|_| "Не удалось запустить sing-box")?;
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            use windows_sys::Win32::System::JobObjects::AssignProcessToJobObject;
            if unsafe { AssignProcessToJobObject(self.job, child.as_raw_handle().cast()) } == 0 {
                let _ = child.kill();
                let _ = child.wait();
                return Err("Не удалось взять процесс sing-box под управление".into());
            }
        }
        if child
            .stdin
            .take()
            .ok_or("stdin недоступен")?
            .write_all(&bytes)
            .is_err()
        {
            let _ = child.kill();
            let _ = child.wait();
            return Err("sing-box завершился при получении конфигурации".into());
        }
        Ok(child)
    }

    fn validate(&self, cfg: &Value) -> Result<(), String> {
        let mut child = self.spawn(cfg, "check")?;
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = child.try_wait().map_err(|_| "Сбой проверки sing-box")?
            {
                return if status.success() {
                    Ok(())
                } else {
                    Err("sing-box отклонил конфигурацию".into())
                };
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err("Истекло время проверки sing-box".into());
            }
            std::thread::sleep(Duration::from_millis(40));
        }
    }

    fn launch(&mut self, cfg: &Value) -> Result<(), String> {
        let runtime_config;
        let cfg = if self.tun {
            runtime_config = crate::windows_tun::with_fresh_interface(cfg)?;
            &runtime_config
        } else {
            cfg
        };
        self.child = Some(self.spawn(cfg, "run")?);
        let deadline = Instant::now() + Duration::from_secs(if self.tun { 15 } else { 4 });
        while Instant::now() < deadline {
            let child = self.child.as_mut().expect("started sing-box child");
            match child.try_wait() {
                Ok(Some(status)) => {
                    self.stop();
                    return Err(format!("sing-box завершился при запуске ({status})"));
                }
                Err(_) => {
                    self.stop();
                    return Err("Не удалось проверить состояние sing-box".into());
                }
                Ok(None) => (),
            }
            if self
                .client
                .get(self.url("version"))
                .bearer_auth(&self.token)
                .send()
                .is_ok_and(|r| r.status().is_success())
            {
                #[cfg(windows)]
                if self.strict.is_some() {
                    let alias = cfg["inbounds"]
                        .as_array()
                        .and_then(|inbounds| {
                            inbounds
                                .iter()
                                .find(|inbound| inbound["tag"] == "windows-tun")
                        })
                        .and_then(|inbound| inbound["interface_name"].as_str());
                    let permit = alias
                        .ok_or_else(|| "Отсутствует имя адаптера Windows TUN".into())
                        .and_then(crate::windows_firewall::Session::permit_interface);
                    match permit {
                        Ok(permit) => self.interface_permit = Some(permit),
                        Err(error) => {
                            self.stop();
                            return Err(error);
                        }
                    }
                }
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(60));
        }
        self.stop();
        Err("Истекло время ожидания запуска sing-box".into())
    }

    fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}/{}", self.ports.control, path)
    }

    fn select(&mut self, tag: &str) -> Result<(), String> {
        self.client
            .put(self.url("proxies/selected-proxy"))
            .bearer_auth(&self.token)
            .json(&json!({"name": tag}))
            .send()
            .ok()
            .filter(|r| r.status().is_success())
            .ok_or("Не удалось переключить маршрут")?;
        self.selected = (tag != "unavailable").then(|| tag.to_string());
        Ok(())
    }

    pub fn select_candidate(&mut self, tag: &str) -> Result<(), String> {
        let valid = self
            .installed
            .as_ref()
            .is_some_and(|g| g.candidates.iter().any(|c| c.tag == tag));
        if !valid {
            return Err("Выходной узел не найден".into());
        }
        self.select(tag)?;
        self.manual_selected = Some(tag.to_string());
        Ok(())
    }

    pub fn replace(
        &mut self,
        generated: Generated,
        probe_url: &str,
        require_route: bool,
    ) -> Result<(), String> {
        if self.alive()
            && self
                .installed
                .as_ref()
                .is_some_and(|current| current.config == generated.config)
        {
            return Ok(());
        }
        self.validate(&generated.config)?;
        let old = self.installed.take();
        let old_route = self.selected.clone();
        self.stop();
        let result = self.launch(&generated.config).and_then(|()| {
            self.installed = Some(generated);
            self.probe(probe_url)?;
            if require_route
                && self.selected.is_none()
                && self
                    .installed
                    .as_ref()
                    .is_some_and(|g| !g.candidates.is_empty())
            {
                return Err(
                    "Проверка новых прокси не прошла. Сохранена предыдущая конфигурация".into(),
                );
            }
            Ok(())
        });
        if result.is_err() {
            self.stop();
            if let Some(previous) = old {
                if self.launch(&previous.config).is_ok() {
                    if let Some(tag) = old_route {
                        let _ = self.select(&tag);
                    }
                }
                self.installed = Some(previous);
            } else {
                self.installed = None;
            }
        }
        result
    }

    pub fn alive(&mut self) -> bool {
        self.child
            .as_mut()
            .is_some_and(|child| matches!(child.try_wait(), Ok(None)))
    }

    pub fn stop(&mut self) {
        #[cfg(windows)]
        self.interface_permit.take();
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.selected = None;
        self.health.clear();
        self.latencies.clear();
        self.direct_available = false;
    }

    pub fn clear(&mut self) {
        self.stop();
        self.installed = None;
        self.manual_selected = None;
    }

    pub fn probe(&mut self, url: &str) -> Result<(), String> {
        let Some(generated) = &self.installed else {
            return Ok(());
        };
        let candidates = generated.candidates.clone();
        let has_server_direct = generated.config["outbounds"]
            .as_array()
            .is_some_and(|outs| outs.iter().any(|o| o["tag"] == "server-direct"));
        let mut tags: Vec<_> = candidates.iter().map(|c| c.tag.as_str()).collect();
        if has_server_direct {
            tags.push("server-direct");
        }
        let endpoint = format!("http://127.0.0.1:{}", self.ports.probe);
        let test = |tag: &str| {
            let Ok(proxy) = reqwest::Proxy::all(&endpoint) else {
                return (false, None);
            };
            let started = Instant::now();
            let ok = Client::builder()
                .proxy(proxy.basic_auth(tag, &self.token))
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(4))
                .build()
                .and_then(|client| client.head(url).send())
                .is_ok_and(|r| r.status().is_success());
            let latency = ok.then(|| started.elapsed().as_millis().max(1) as u32);
            (ok, latency)
        };
        let results = std::thread::scope(|scope| {
            let tasks: Vec<_> = tags
                .iter()
                .map(|&tag| (tag, scope.spawn(|| test(tag))))
                .collect();
            tasks
                .into_iter()
                .map(|(tag, job)| (tag, job.join().unwrap_or((false, None))))
                .collect::<Vec<_>>()
        });
        for (tag, (available, latency)) in results {
            let count = self.health.entry(tag.to_string()).or_default();
            *count = if available {
                count.saturating_add(1)
            } else {
                0
            };
            if let Some(ms) = latency {
                self.latencies.insert(tag.to_string(), ms);
            } else {
                self.latencies.remove(tag);
            }
        }
        self.direct_available = self.health.get("server-direct").copied().unwrap_or(0) > 0;
        let selected = self.selected.as_deref();
        let still_healthy =
            selected.is_some_and(|tag| self.health.get(tag).copied().unwrap_or(0) > 0);
        let minimum = if still_healthy { 2 } else { 1 };
        let manual_best = self.manual_selected.as_deref().and_then(|manual| {
            candidates
                .iter()
                .find(|c| c.tag == manual && self.health.get(&c.tag).copied().unwrap_or(0) > 0)
                .map(|c| c.tag.as_str())
        });
        let best = manual_best.or_else(|| {
            candidates
                .iter()
                .find(|c| {
                    Some(c.tag.as_str()) == selected && still_healthy
                        || self.health.get(&c.tag).copied().unwrap_or(0) >= minimum
                })
                .map(|c| c.tag.as_str())
        });
        if best != selected {
            self.select(best.unwrap_or("unavailable"))?;
        }
        Ok(())
    }

    pub fn status(&self) -> Value {
        let candidates: &[Candidate] = self
            .installed
            .as_ref()
            .map(|g| g.candidates.as_slice())
            .unwrap_or(&[]);
        let primary = candidates.first().map(|c| c.tag.as_str());
        let fallback = self
            .selected
            .as_deref()
            .is_some_and(|tag| primary.is_some_and(|first| first != tag));
        json!({
            "selected": self.selected,
            "fallback": fallback,
            "serverDirectAvailable": self.direct_available,
            "candidates": candidates.iter().map(|c| json!({
                "tag": c.tag,
                "name": c.name,
                "available": self.health.get(&c.tag).copied().unwrap_or(0) > 0,
                "latencyMs": self.latencies.get(&c.tag),
            })).collect::<Vec<_>>()
        })
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        self.stop();
        #[cfg(windows)]
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.job);
        }
    }
}

#[cfg(windows)]
fn create_job() -> std::io::Result<windows_sys::Win32::Foundation::HANDLE> {
    use windows_sys::Win32::{
        Foundation::CloseHandle,
        System::JobObjects::{
            CreateJobObjectW, JobObjectExtendedLimitInformation, SetInformationJobObject,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        },
    };
    unsafe {
        let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
        if job.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            std::mem::size_of_val(&limits) as u32,
        ) == 0
        {
            let error = std::io::Error::last_os_error();
            CloseHandle(job);
            return Err(error);
        }
        Ok(job)
    }
}
