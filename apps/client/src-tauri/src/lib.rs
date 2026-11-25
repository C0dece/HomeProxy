#[cfg(not(target_os = "android"))]
use homeproxy_agent::{control, default_dir, CONTROL_PORT};
#[cfg(not(target_os = "android"))]
use serde_json::Value;

#[cfg(target_os = "android")]
mod mobile;
#[cfg(windows)]
mod windows_mode;
#[cfg(windows)]
mod windows_updates;

#[cfg(not(target_os = "android"))]
#[tauri::command]
async fn agent_command(
    app: tauri::AppHandle,
    command: String,
    data: Value,
) -> Result<Value, String> {
    #[cfg(windows)]
    if command.starts_with("update-") {
        return windows_updates::command(&app, &command, &data).await;
    }
    #[cfg(windows)]
    if command == "windows-tun" {
        let tun = data["tun"].as_bool().ok_or("Выберите режим Windows")?;
        return tauri::async_runtime::spawn_blocking(move || windows_mode::switch(tun))
            .await
            .map_err(|_| "Переключение режима прервано")?;
    }
    #[cfg(not(windows))]
    let _ = app;
    tauri::async_runtime::spawn_blocking(move || {
        control(&default_dir()?, CONTROL_PORT, &command, &data)
    })
    .await
    .map_err(|_| "Локальная команда прервана")?
}

#[cfg(not(target_os = "android"))]
#[tauri::command]
async fn start_agent() -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(start_local_agent)
        .await
        .map_err(|_| "Запуск прерван")?
}

#[cfg(not(target_os = "android"))]
fn agent_binary() -> Result<std::path::PathBuf, String> {
    Ok(std::env::current_exe()
        .map_err(|_| "Не удалось определить папку приложения")?
        .with_file_name("homeproxy-agent.exe"))
}

#[cfg(not(target_os = "android"))]
fn start_local_agent() -> Result<(), String> {
    let dir = default_dir()?;
    if control(&dir, CONTROL_PORT, "status", &Value::Null).is_ok() {
        return Ok(());
    }
    let binary = agent_binary()?;
    let mut process = std::process::Command::new(binary);
    process
        .arg("serve")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        process.creation_flags(0x08000000);
    }
    let mut child = process
        .spawn()
        .map_err(|_| "Поместите homeproxy-agent.exe и sing-box.exe рядом с приложением")?;
    for _ in 0..40 {
        if control(&dir, CONTROL_PORT, "status", &Value::Null).is_ok() {
            return Ok(());
        }
        if child.try_wait().ok().flatten().is_some() {
            return Err("Агент завершился. Проверьте файлы и локальные порты".into());
        }
        std::thread::sleep(std::time::Duration::from_millis(125));
    }
    Err("Агент не ответил при запуске".into())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let builder = tauri::Builder::default();
    #[cfg(windows)]
    let builder = builder
        .plugin(tauri_plugin_updater::Builder::new().build())
        .manage(windows_updates::WindowsUpdates::default())
        .setup(|app| {
            windows_updates::on_startup(app.handle().clone());
            Ok(())
        });
    #[cfg(target_os = "android")]
    let builder = builder
        .plugin(mobile::plugin())
        .invoke_handler(tauri::generate_handler![
            mobile::agent_command,
            mobile::start_agent
        ]);
    #[cfg(not(target_os = "android"))]
    let builder = builder.invoke_handler(tauri::generate_handler![agent_command, start_agent]);
    builder
        .run(tauri::generate_context!())
        .expect("HomeProxy startup failed");
}
