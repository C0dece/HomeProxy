use serde::Serialize;

#[derive(Serialize)]
pub struct Application {
    name: String,
    path: String,
}

#[cfg(windows)]
pub fn running() -> Result<Vec<Application>, String> {
    use std::{collections::BTreeMap, mem};
    use windows_sys::Win32::{
        Foundation::{CloseHandle, INVALID_HANDLE_VALUE},
        System::{
            Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
                TH32CS_SNAPPROCESS,
            },
            Threading::{
                OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
            },
        },
    };

    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return Err("Не удалось прочитать список приложений".into());
    }
    let mut entry: PROCESSENTRY32W = unsafe { mem::zeroed() };
    entry.dwSize = mem::size_of::<PROCESSENTRY32W>() as u32;
    let mut buffer = vec![0u16; 32_768];
    let mut apps = BTreeMap::new();
    unsafe {
        if Process32FirstW(snapshot, &mut entry) != 0 {
            loop {
                let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, entry.th32ProcessID);
                if !handle.is_null() {
                    let mut size = buffer.len() as u32;
                    let found =
                        QueryFullProcessImageNameW(handle, 0, buffer.as_mut_ptr(), &mut size);
                    CloseHandle(handle);
                    if found != 0 {
                        let path = String::from_utf16_lossy(&buffer[..size as usize]);
                        let name = path.rsplit('\\').next().unwrap_or("").to_string();
                        if name.to_ascii_lowercase().ends_with(".exe") {
                            let key = (name.to_lowercase(), path.to_lowercase());
                            apps.entry(key).or_insert(Application { name, path });
                        }
                    }
                }
                if Process32NextW(snapshot, &mut entry) == 0 {
                    break;
                }
            }
        } else {
            CloseHandle(snapshot);
            return Err("Не удалось прочитать список приложений".into());
        }
        CloseHandle(snapshot);
    }
    Ok(apps.into_values().collect())
}

#[cfg(target_os = "linux")]
pub fn running() -> Result<Vec<Application>, String> {
    use std::collections::BTreeMap;
    let mut apps = BTreeMap::new();
    let entries =
        std::fs::read_dir("/proc").map_err(|_| "Не удалось прочитать список приложений")?;
    for entry in entries.flatten() {
        let fname = entry.file_name();
        let Some(pid) = fname.to_str() else { continue };
        if !pid.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let Ok(target) = std::fs::read_link(entry.path().join("exe")) else {
            continue;
        };
        let path = target.to_string_lossy().into_owned();
        let name = target
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string();
        if !name.is_empty() {
            let key = (name.to_lowercase(), path.to_lowercase());
            apps.entry(key).or_insert(Application { name, path });
        }
    }
    Ok(apps.into_values().collect())
}

#[cfg(not(any(windows, target_os = "linux")))]
pub fn running() -> Result<Vec<Application>, String> {
    Err("Список приложений доступен на Windows и Linux".into())
}
