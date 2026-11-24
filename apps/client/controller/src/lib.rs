pub mod android_policy;
#[cfg(windows)]
mod bootstrap_dns;
pub mod controller;
mod engine;
pub mod policy;
mod processes;
pub mod secure;
#[cfg(windows)]
pub mod windows_firewall;
mod windows_tun;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use std::path::PathBuf;

pub const CONTROL_PORT: u16 = 17771;
pub const PROXY_PORT: u16 = 17770;

pub fn default_dir() -> Result<PathBuf, String> {
    std::env::var_os("LOCALAPPDATA")
        .map(|value| PathBuf::from(value).join("HomeProxy"))
        .ok_or_else(|| "Windows LocalAppData is unavailable".into())
}

pub fn random_token() -> Result<String, String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| "system random generator unavailable")?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

pub fn control(
    dir: &std::path::Path,
    port: u16,
    command: &str,
    data: &serde_json::Value,
) -> Result<serde_json::Value, String> {
    let token =
        secure::load(&dir.join("control.dpapi")).map_err(|_| "Запустите HomeProxy Agent")?;
    let token = String::from_utf8(token).map_err(|_| "Ключ управления повреждён")?;
    let response = reqwest::blocking::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(45))
        .build()
        .map_err(|_| "Не удалось создать локальное подключение")?
        .post(format!("http://127.0.0.1:{port}/command"))
        .bearer_auth(token)
        .json(&serde_json::json!({"command": command, "data": data}))
        .send()
        .map_err(|_| "HomeProxy Agent недоступен")?;
    let status = response.status();
    let result: serde_json::Value = response.json().map_err(|_| "Неверный ответ агента")?;
    if status.is_success() {
        Ok(result)
    } else {
        Err(result["error"]
            .as_str()
            .unwrap_or("Ошибка агента")
            .to_string())
    }
}
