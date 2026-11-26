use homeproxy_agent::default_dir;
use serde::{Deserialize, Serialize};
use std::{ffi::OsStr, fs, os::windows::ffi::OsStrExt, path::PathBuf, ptr::null_mut};
use windows_sys::Win32::{
    Foundation::ERROR_FILE_NOT_FOUND,
    System::Registry::{
        RegCloseKey, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW,
        HKEY_CURRENT_USER, KEY_READ, KEY_WRITE, REG_SZ,
    },
};

const RUN_KEY: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
const VALUE_NAME: &str = "HomeProxyAgent";

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct DesktopSettings {
    pub auto_connect: bool,
}

fn wide(value: &str) -> Vec<u16> {
    OsStr::new(value).encode_wide().chain(Some(0)).collect()
}

fn settings_path() -> Result<PathBuf, String> {
    Ok(default_dir()?.join("desktop.json"))
}

pub fn load_settings() -> DesktopSettings {
    let Ok(path) = settings_path() else {
        return DesktopSettings::default();
    };
    let Ok(raw) = fs::read(path) else {
        return DesktopSettings::default();
    };
    serde_json::from_slice(&raw).unwrap_or_default()
}

pub fn save_settings(settings: &DesktopSettings) -> Result<(), String> {
    let path = settings_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|_| "Не удалось создать каталог настроек")?;
    }
    let data = serde_json::to_vec(settings).map_err(|_| "Не удалось сериализовать настройки")?;
    fs::write(path, data).map_err(|_| "Не удалось сохранить настройки автозапуска".into())
}

pub fn is_autostart_enabled() -> bool {
    let key_path = wide(RUN_KEY);
    let value_name = wide(VALUE_NAME);
    let mut hkey = null_mut();
    unsafe {
        if RegOpenKeyExW(HKEY_CURRENT_USER, key_path.as_ptr(), 0, KEY_READ, &mut hkey) != 0 {
            return false;
        }
        let mut kind = 0u32;
        let mut size = 0u32;
        let status = RegQueryValueExW(
            hkey,
            value_name.as_ptr(),
            null_mut(),
            &mut kind,
            null_mut(),
            &mut size,
        );
        RegCloseKey(hkey);
        status == 0 && kind == REG_SZ && size > 2
    }
}

pub fn set_autostart(enabled: bool) -> Result<(), String> {
    let key_path = wide(RUN_KEY);
    let value_name = wide(VALUE_NAME);
    let mut hkey = null_mut();
    let open_status = unsafe {
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            key_path.as_ptr(),
            0,
            KEY_WRITE,
            &mut hkey,
        )
    };
    if open_status != 0 {
        return Err("Не удалось открыть ветку автозапуска Windows".into());
    }
    let result = if enabled {
        let exe = std::env::current_exe().map_err(|_| "Не удалось определить путь приложения")?;
        let command = format!("\"{}\" --minimized", exe.display());
        let encoded = wide(&command);
        let bytes_len = (encoded.len() * std::mem::size_of::<u16>()) as u32;
        let status = unsafe {
            RegSetValueExW(
                hkey,
                value_name.as_ptr(),
                0,
                REG_SZ,
                encoded.as_ptr().cast(),
                bytes_len,
            )
        };
        if status == 0 {
            Ok(())
        } else {
            Err("Не удалось записать автозапуск в реестр Windows".into())
        }
    } else {
        let status = unsafe { RegDeleteValueW(hkey, value_name.as_ptr()) };
        if status == 0 || status == ERROR_FILE_NOT_FOUND {
            Ok(())
        } else {
            Err("Не удалось удалить запись автозапуска из реестра Windows".into())
        }
    };
    unsafe { RegCloseKey(hkey) };
    result
}
