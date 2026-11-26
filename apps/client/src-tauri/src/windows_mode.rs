use homeproxy_agent::{control, default_dir, CONTROL_PORT};
use serde_json::Value;
use std::{
    ffi::{OsStr, OsString},
    fs,
    mem::size_of,
    net::{SocketAddr, TcpStream},
    os::windows::{ffi::OsStrExt, process::CommandExt},
    path::Path,
    process::{Command, Stdio},
    sync::Mutex,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, ERROR_CANCELLED, HANDLE},
    System::Threading::{GetExitCodeProcess, WaitForSingleObject},
    UI::Shell::{ShellExecuteExW, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW},
};

static CHANGE: Mutex<()> = Mutex::new(());
const TUN_TASK_NAME: &str = "HomeProxyAgentTun";
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const ADDRESS: SocketAddr = SocketAddr::new(
    std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
    CONTROL_PORT,
);

struct Elevated(HANDLE);

impl Drop for Elevated {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

fn wide(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(Some(0)).collect()
}

fn elevate(binary: &Path, directory: &Path) -> Result<Elevated, String> {
    let path = wide(binary.as_os_str());
    let verb = wide(OsStr::new("runas"));
    let mut arguments = OsString::from("serve --tun --handoff-tun --data \"");
    arguments.push(directory);
    arguments.push("\"");
    let args = wide(&arguments);
    let mut info = SHELLEXECUTEINFOW {
        cbSize: size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOASYNC | SEE_MASK_NOCLOSEPROCESS,
        lpVerb: verb.as_ptr(),
        lpFile: path.as_ptr(),
        lpParameters: args.as_ptr(),
        ..Default::default()
    };
    if unsafe { ShellExecuteExW(&mut info) } == 0 {
        let error = std::io::Error::last_os_error();
        return Err(if error.raw_os_error() == Some(ERROR_CANCELLED as i32) {
            "Запуск TUN отменён в запросе Windows".into()
        } else {
            "Не удалось запустить TUN с правами администратора".into()
        });
    }
    if info.hProcess.is_null() {
        return Err("Windows не вернула процесс системного режима".into());
    }
    Ok(Elevated(info.hProcess))
}

fn listening() -> bool {
    TcpStream::connect_timeout(&ADDRESS, Duration::from_millis(150)).is_ok()
}

pub fn tun_task_installed() -> bool {
    Command::new("schtasks.exe")
        .args(["/Query", "/TN", TUN_TASK_NAME])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .status()
        .is_ok_and(|s| s.success())
}

fn run_elevated_powershell(script: &str) -> Result<(), String> {
    let temp_script =
        std::env::temp_dir().join(format!("homeproxy-tun-task-{}.ps1", std::process::id()));
    fs::write(&temp_script, script.as_bytes())
        .map_err(|_| "Не удалось подготовить скрипт настройки задачи TUN")?;
    let path = wide(OsStr::new("powershell.exe"));
    let verb = wide(OsStr::new("runas"));
    let mut arguments =
        OsString::from("-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File \"");
    arguments.push(&temp_script);
    arguments.push("\"");
    let args = wide(&arguments);
    let mut info = SHELLEXECUTEINFOW {
        cbSize: size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOASYNC | SEE_MASK_NOCLOSEPROCESS,
        lpVerb: verb.as_ptr(),
        lpFile: path.as_ptr(),
        lpParameters: args.as_ptr(),
        ..Default::default()
    };
    let launched = unsafe { ShellExecuteExW(&mut info) };
    if launched == 0 {
        let _ = fs::remove_file(&temp_script);
        let error = std::io::Error::last_os_error();
        return Err(if error.raw_os_error() == Some(ERROR_CANCELLED as i32) {
            "Настройка задачи TUN отменена в запросе Windows".into()
        } else {
            "Не удалось запустить настройку задачи TUN с правами администратора".into()
        });
    }
    if info.hProcess.is_null() {
        let _ = fs::remove_file(&temp_script);
        return Err("Windows не вернула процесс настройки задачи TUN".into());
    }
    let handle = Elevated(info.hProcess);
    let wait = unsafe { WaitForSingleObject(handle.0, 30_000) };
    let mut exit_code = 1u32;
    let code_ok = unsafe { GetExitCodeProcess(handle.0, &mut exit_code) } != 0;
    let _ = fs::remove_file(&temp_script);
    if wait != 0 || !code_ok || exit_code != 0 {
        return Err("Не удалось зарегистрировать задачу Windows для TUN".into());
    }
    Ok(())
}

pub fn install_tun_task() -> Result<(), String> {
    let _guard = CHANGE.try_lock().map_err(|_| "Режим уже переключается")?;
    let binary = crate::agent_binary()?;
    let directory = default_dir()?;
    let esc = |s: String| s.replace('\'', "''");
    let exe_esc = esc(binary.to_string_lossy().into_owned());
    let dir_esc = esc(directory.to_string_lossy().into_owned());
    let script = format!(
        "$ErrorActionPreference = 'Stop'\n\
         $user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name\n\
         $action = New-ScheduledTaskAction -Execute '{exe_esc}' -Argument 'serve --tun --data \"{dir_esc}\"'\n\
         $principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Highest\n\
         $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew\n\
         Register-ScheduledTask -TaskName '{TUN_TASK_NAME}' -Action $action -Principal $principal -Settings $settings -Force | Out-Null\n"
    );
    run_elevated_powershell(&script)?;
    if !tun_task_installed() {
        return Err("Задача TUN не найдена после регистрации".into());
    }
    Ok(())
}

fn start_tun_task() -> Result<(), String> {
    let status = Command::new("schtasks.exe")
        .args(["/Run", "/TN", TUN_TASK_NAME])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .status()
        .map_err(|_| "Не удалось запустить задачу Windows для TUN")?;
    if !status.success() {
        return Err("Планировщик Windows не смог запустить задачу TUN".into());
    }
    Ok(())
}

pub fn switch(tun: bool) -> Result<Value, String> {
    let _guard = CHANGE.try_lock().map_err(|_| "Режим уже переключается")?;
    let directory = default_dir()?;
    let request = |name| control(&directory, CONTROL_PORT, name, &Value::Null);
    let previous = request("status")?;
    if previous["strict"] == true {
        return Err("Отключите строгий режим из терминала администратора".into());
    }
    if previous["tun"] == tun {
        return Ok(previous);
    }
    if tun {
        if tun_task_installed() {
            if previous["linked"] != true || previous["revision"].is_null() {
                return Err(
                    "Для запуска TUN подключите локальный Agent и дождитесь получения настроек"
                        .into(),
                );
            }
            request("shutdown")?;
            let stop_deadline = Instant::now() + Duration::from_secs(5);
            while listening() {
                if Instant::now() >= stop_deadline {
                    return Err("Локальный Agent ещё освобождает порт".into());
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            if let Err(err) = start_tun_task() {
                let _ = crate::start_local_agent();
                return Err(err);
            }
            let deadline = Instant::now() + Duration::from_secs(25);
            while Instant::now() < deadline {
                if listening() {
                    if let Ok(status) = request("status") {
                        if status["tun"] == true
                            && (status["enabled"] == false || status["routingActive"] == true)
                        {
                            return Ok(status);
                        }
                    }
                }
                std::thread::sleep(Duration::from_millis(150));
            }
            if !listening() {
                let _ = crate::start_local_agent();
                return Err(
                    "TUN не запустился через задачу Windows. Восстановлен локальный прокси".into(),
                );
            }
            return Err("Системный режим ещё не ответил. Проверьте статус подключения".into());
        }
        let child = elevate(&crate::agent_binary()?, &directory)?;
        let deadline = Instant::now() + Duration::from_secs(35);
        while Instant::now() < deadline {
            if unsafe { WaitForSingleObject(child.0, 150) } == 0 {
                if !listening() {
                    crate::start_local_agent()?;
                    return Err("TUN не запустился. Восстановлен локальный прокси".into());
                }
                return Err("TUN не запустился. Проверьте права и доступность адаптера".into());
            }
            if listening() {
                if let Ok(status) = request("status") {
                    if status["tun"] == true
                        && (status["enabled"] == false || status["routingActive"] == true)
                    {
                        return Ok(status);
                    }
                }
            }
        }
        return Err("Системный режим ещё не ответил. Проверьте статус подключения".into());
    }
    request("shutdown")?;
    let deadline = Instant::now() + Duration::from_secs(5);
    while listening() {
        if Instant::now() >= deadline {
            return Err("Системный режим ещё завершает работу".into());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    crate::start_local_agent()?;
    let current = request("status")?;
    if current["tun"] != false {
        return Err("Порт управления занят системным Agent".into());
    }
    Ok(current)
}
