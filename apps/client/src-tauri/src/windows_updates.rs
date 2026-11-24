use homeproxy_agent::{control, default_dir, CONTROL_PORT};
use serde_json::{json, Value};
use std::{
    fs,
    net::{Ipv4Addr, SocketAddr, TcpStream},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use tauri::{async_runtime::Mutex, AppHandle, Manager};
use tauri_plugin_updater::{Update, UpdaterExt};
use url::Url;

const ENDPOINT: Option<&str> = option_env!("HOMEPROXY_WINDOWS_UPDATE_ENDPOINT");
const PUBLIC_KEY: Option<&str> = option_env!("HOMEPROXY_WINDOWS_UPDATE_KEY");

struct Offer {
    channel: String,
    update: Update,
    staged: Option<Vec<u8>>,
}

#[derive(Default)]
pub(crate) struct WindowsUpdates {
    offer: Mutex<Option<Offer>>,
}

pub(crate) fn on_startup(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        let _ = resume_controller().await;
        if ENDPOINT.is_none() || PUBLIC_KEY.is_none() {
            return;
        }
        let checked = command(&app, "update-check", &json!({"channel":"stable"})).await;
        if let Ok(result) = checked {
            if let Some(version) = result["offer"]["version"].as_str() {
                let _ = command(
                    &app,
                    "update-install",
                    &json!({"channel":"stable","version":version}),
                )
                .await;
            }
        }
    });
}

pub(crate) async fn command<R: tauri::Runtime>(
    app: &AppHandle<R>,
    command: &str,
    data: &Value,
) -> Result<Value, String> {
    let state = app.state::<WindowsUpdates>();
    let mut offer = state.offer.lock().await;
    let mut notice = None;
    match command {
        "update-status" => {}
        "update-check" => {
            let channel = data["channel"].as_str().ok_or("Укажите канал")?;
            if !matches!(channel, "dev" | "beta" | "stable") {
                return Err("Неизвестный канал обновлений".into());
            }
            let (Some(endpoint), Some(key)) = (ENDPOINT, PUBLIC_KEY) else {
                return Err("Источник обновлений не задан в сборке".into());
            };
            if offer
                .as_ref()
                .is_some_and(|current| current.staged.is_some())
            {
                return Err("Сначала отмените подготовленное обновление".into());
            }
            *offer = None;
            let url = Url::parse(&endpoint.replace("{channel}", channel))
                .map_err(|_| "Некорректный адрес обновлений")?;
            if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some() {
                return Err("Источник обновлений должен использовать HTTPS".into());
            }
            let update = app
                .updater_builder()
                .pubkey(key)
                .endpoints(vec![url])
                .and_then(|builder| builder.timeout(Duration::from_secs(90)).build())
                .map_err(|_| "Не удалось настроить обновления Windows")?
                .check()
                .await
                .map_err(|_| "Не удалось получить выпуск Windows")?;
            if let Some(update) = update {
                let min = update.raw_json["apiMin"].as_u64();
                let max = update.raw_json["apiMax"].as_u64();
                if min != Some(1) || !max.is_some_and(|version| version >= 1) {
                    return Err("Выпуск несовместим с API HomeProxy 1".into());
                }
                if update.download_url.scheme() != "https"
                    || !update.download_url.username().is_empty()
                    || update.download_url.password().is_some()
                {
                    return Err("Загрузка выпуска Windows требует HTTPS".into());
                }
                *offer = Some(Offer {
                    channel: channel.to_owned(),
                    update,
                    staged: None,
                });
            } else {
                notice = Some("Совместимых обновлений нет");
            }
        }
        "update-install" => {
            let selected = offer
                .as_mut()
                .filter(|entry| {
                    data["channel"] == entry.channel && data["version"] == entry.update.version
                })
                .ok_or("Сначала проверьте выбранный канал")?;
            let bytes = selected
                .update
                .download(|_, _| {}, || {})
                .await
                .map_err(|_| "Пакет не загрузился или подпись не совпадает")?;
            selected.staged = Some(bytes);
        }
        "update-confirm" => {
            let selected = offer.as_ref().ok_or("Подготовьте обновление")?;
            let bytes = selected.staged.as_deref().ok_or("Подготовьте обновление")?;
            let stopped = tauri::async_runtime::spawn_blocking(stop_controller)
                .await
                .map_err(|_| "Не удалось остановить контроллер")??;
            if selected.update.install(bytes).is_err() {
                if stopped {
                    resume_controller().await?;
                }
                return Err("Установщик Windows не запустился".into());
            }
        }
        "update-cancel" => {
            if let Some(entry) = offer.as_mut() {
                entry.staged = None;
            }
            notice = Some("Подготовка обновления отменена");
        }
        _ => return Err("Неизвестное действие обновления".into()),
    }
    let active = offer.as_ref().is_some_and(|entry| entry.staged.is_some());
    Ok(json!({
        "configured": ENDPOINT.is_some() && PUBLIC_KEY.is_some(),
        "installed": app.package_info().version.to_string(),
        "allowed": true,
        "active": active, "confirm": active,
        "notice": notice.or(active.then_some("Пакет проверен и готов к установке")),
        "offer": offer.as_ref().map(|entry| json!({
            "channel": entry.channel,
            "version": entry.update.version,
            "size": entry.update.raw_json["size"].as_u64(),
            "notes": entry.update.body,
        }))
    }))
}

fn resume_marker(directory: &Path) -> PathBuf {
    directory.join("resume-after-windows-update")
}

async fn resume_controller() -> Result<(), String> {
    let marker = resume_marker(&default_dir()?);
    if !marker
        .try_exists()
        .map_err(|_| "Не удалось проверить состояние обновления")?
    {
        return Ok(());
    }
    super::start_agent().await?;
    match fs::remove_file(marker) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err("Не удалось очистить состояние обновления".into()),
    }
}

fn stop_controller() -> Result<bool, String> {
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, CONTROL_PORT));
    if TcpStream::connect_timeout(&address, Duration::from_millis(200)).is_err() {
        return Ok(false);
    }
    let directory = default_dir()?;
    let status = control(&directory, CONTROL_PORT, "status", &Value::Null)?;
    if status["tun"] == true {
        return Err("Остановите системный режим TUN перед обновлением Windows".into());
    }
    fs::write(resume_marker(&directory), [])
        .map_err(|_| "Не удалось сохранить запуск контроллера после обновления")?;
    control(&directory, CONTROL_PORT, "shutdown", &Value::Null)?;
    let wait = Instant::now() + Duration::from_secs(4);
    while Instant::now() < wait {
        if TcpStream::connect_timeout(&address, Duration::from_millis(200)).is_err() {
            return Ok(true);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err("Контроллер ещё работает. Установка отложена".into())
}
