#[cfg(not(target_os = "android"))]
use homeproxy_agent::{control, default_dir, CONTROL_PORT};
#[cfg(not(target_os = "android"))]
use serde_json::{json, Value};
#[cfg(not(target_os = "android"))]
use tauri::{Emitter, Manager};

#[cfg(target_os = "android")]
mod mobile;
#[cfg(windows)]
mod windows_autostart;
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
    #[cfg(windows)]
    if command == "install-tun-task" {
        return tauri::async_runtime::spawn_blocking(|| {
            windows_mode::install_tun_task()?;
            Ok(json!({ "tunTaskInstalled": windows_mode::tun_task_installed() }))
        })
        .await
        .map_err(|_| "Настройка задачи TUN прервана")?;
    }
    #[cfg(windows)]
    if command == "desktop-settings-get" {
        return tauri::async_runtime::spawn_blocking(|| {
            let stored = windows_autostart::load_settings();
            Ok(json!({
                "autostart": windows_autostart::is_autostart_enabled(),
                "autoConnect": stored.auto_connect,
                "tunTaskInstalled": windows_mode::tun_task_installed(),
            }))
        })
        .await
        .map_err(|_| "Чтение настроек прервано")?;
    }
    #[cfg(windows)]
    if command == "desktop-settings-set" {
        return tauri::async_runtime::spawn_blocking(move || {
            if let Some(autostart) = data["autostart"].as_bool() {
                windows_autostart::set_autostart(autostart)?;
            }
            let mut stored = windows_autostart::load_settings();
            if let Some(auto_connect) = data["autoConnect"].as_bool() {
                stored.auto_connect = auto_connect;
                windows_autostart::save_settings(&stored)?;
            }
            Ok(json!({
                "autostart": windows_autostart::is_autostart_enabled(),
                "autoConnect": stored.auto_connect,
                "tunTaskInstalled": windows_mode::tun_task_installed(),
            }))
        })
        .await
        .map_err(|_| "Сохранение настроек прервано")?;
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

#[cfg(not(target_os = "android"))]
fn show_main_window(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

#[cfg(not(target_os = "android"))]
fn tray_quick_mode(app: &tauri::AppHandle, mode: &'static str) {
    let handle = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let _ = start_local_agent();
        if let Ok(dir) = default_dir() {
            if let Ok(status) = control(&dir, CONTROL_PORT, "quick-mode", &json!({"mode": mode})) {
                let _ = handle.emit("agent-updated", status);
            }
        }
    });
}

#[cfg(not(target_os = "android"))]
fn setup_tray(app: &tauri::App) -> tauri::Result<()> {
    use tauri::menu::{MenuBuilder, MenuItemBuilder, PredefinedMenuItem};
    use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};

    let open = MenuItemBuilder::with_id("open", "Открыть HomeProxy").build(app)?;
    let mode_off = MenuItemBuilder::with_id("mode_off", "Выкл").build(app)?;
    let mode_rules = MenuItemBuilder::with_id("mode_rules", "Авто (правила)").build(app)?;
    let mode_all = MenuItemBuilder::with_id("mode_all", "Весь трафик").build(app)?;
    let quit = MenuItemBuilder::with_id("quit", "Выход").build(app)?;
    let menu = MenuBuilder::new(app)
        .items(&[
            &open,
            &PredefinedMenuItem::separator(app)?,
            &mode_off,
            &mode_rules,
            &mode_all,
            &PredefinedMenuItem::separator(app)?,
            &quit,
        ])
        .build()?;

    let mut builder = TrayIconBuilder::new()
        .menu(&menu)
        .tooltip("HomeProxy Agent")
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id().as_ref() {
            "open" => show_main_window(app),
            "mode_off" => tray_quick_mode(app, "off"),
            "mode_rules" => tray_quick_mode(app, "rules"),
            "mode_all" => tray_quick_mode(app, "all"),
            "quit" => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_main_window(tray.app_handle());
            }
        });
    if let Some(icon) = app.default_window_icon() {
        builder = builder.icon(icon.clone());
    }
    builder.build(app)?;
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let builder = tauri::Builder::default();
    #[cfg(not(target_os = "android"))]
    let builder = builder.on_window_event(|window, event| {
        if let tauri::WindowEvent::CloseRequested { api, .. } = event {
            let _ = window.hide();
            api.prevent_close();
        }
    });
    #[cfg(windows)]
    let builder = builder
        .plugin(tauri_plugin_updater::Builder::new().build())
        .manage(windows_updates::WindowsUpdates::default())
        .setup(|app| {
            setup_tray(app)?;
            if std::env::args().any(|arg| arg == "--minimized") {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.hide();
                }
            }
            let handle = app.handle().clone();
            if windows_autostart::load_settings().auto_connect {
                tauri::async_runtime::spawn_blocking(move || {
                    if start_local_agent().is_ok() {
                        if let Ok(dir) = default_dir() {
                            if let Ok(status) = control(&dir, CONTROL_PORT, "status", &Value::Null)
                            {
                                if status["linked"] == true && status["enabled"] == false {
                                    if let Ok(updated) = control(
                                        &dir,
                                        CONTROL_PORT,
                                        "enable",
                                        &json!({"enabled": true}),
                                    ) {
                                        let _ = handle.emit("agent-updated", updated);
                                    }
                                }
                            }
                        }
                    }
                });
            }
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
