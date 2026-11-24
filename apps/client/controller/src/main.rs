use std::path::PathBuf;

use homeproxy_agent::{
    control,
    controller::{serve, Options},
    default_dir, CONTROL_PORT, PROXY_PORT,
};
use serde_json::Value;

fn run() -> Result<(), String> {
    let mut args = std::env::args_os().skip(1);
    let mode = args
        .next()
        .and_then(|s| s.into_string().ok())
        .unwrap_or_else(|| "serve".into());
    let mut directory = default_dir()?;
    let mut binary = std::env::current_exe()
        .map_err(|_| "Agent path unavailable")?
        .with_file_name("sing-box.exe");
    let mut port = CONTROL_PORT;
    let mut proxy_port = PROXY_PORT;
    let mut dev = false;
    let mut tun = false;
    let mut strict = false;
    let mut seconds = 10;
    let mut command = "status".to_string();
    let mut data = Value::Null;
    while let Some(arg) = args.next() {
        let value = |args: &mut std::iter::Skip<std::env::ArgsOs>| {
            args.next().ok_or("Missing option value")
        };
        match arg.to_str() {
            Some("--data") => directory = PathBuf::from(value(&mut args)?),
            Some("--sing-box") => binary = PathBuf::from(value(&mut args)?),
            Some("--port") => port = number(value(&mut args)?)?,
            Some("--proxy-port") => proxy_port = number(value(&mut args)?)?,
            Some("--probe-seconds") => seconds = u64::from(number(value(&mut args)?)?),
            Some("--allow-loopback-http") => dev = true,
            Some("--tun") if mode == "serve" => tun = true,
            Some("--tun-strict") if mode == "serve" => {
                tun = true;
                strict = true;
            }
            Some("--command") => {
                command = value(&mut args)?
                    .into_string()
                    .map_err(|_| "Invalid command")?
            }
            Some("--json") => {
                data = serde_json::from_str(&value(&mut args)?.to_string_lossy())
                    .map_err(|_| "Invalid JSON")?
            }
            _ => return Err("Unknown option".into()),
        }
    }
    match mode.as_str() {
        "serve" => serve(Options {
            directory,
            binary,
            port,
            proxy_port,
            allow_loopback_http: dev,
            probe_seconds: seconds,
            tun,
            strict,
        }),
        "ctl" => {
            println!("{}", control(&directory, port, &command, &data)?);
            Ok(())
        }
        #[cfg(windows)]
        "firewall-reset" => homeproxy_agent::windows_firewall::reset(),
        _ => Err("Use serve, ctl or firewall-reset".into()),
    }
}

fn number(value: std::ffi::OsString) -> Result<u16, String> {
    value
        .to_str()
        .and_then(|s| s.parse().ok())
        .filter(|n| *n != 0)
        .ok_or_else(|| "Expected a nonzero number".into())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
