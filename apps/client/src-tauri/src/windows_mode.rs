use homeproxy_agent::{control, default_dir, CONTROL_PORT};
use serde_json::Value;
use std::{
    ffi::{OsStr, OsString},
    mem::size_of,
    net::{SocketAddr, TcpStream},
    os::windows::ffi::OsStrExt,
    path::Path,
    sync::Mutex,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, ERROR_CANCELLED, HANDLE},
    System::Threading::WaitForSingleObject,
    UI::Shell::{ShellExecuteExW, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW},
};

static CHANGE: Mutex<()> = Mutex::new(());
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
