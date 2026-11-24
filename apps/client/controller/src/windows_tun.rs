use crate::policy::{process_pattern, tun_dns, Action, Profile};
use serde_json::{json, Value};
use std::path::Path;
use url::{Host, Url};

pub(crate) const DOH_NAME: &str = "dns.quad9.net";
pub(crate) const DOH_ADDRESSES: [&str; 4] =
    ["9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"];

pub(crate) fn configure(
    config: &mut Value,
    profile: Profile,
    custom: Action,
    origin: &Url,
    agent_executable: &Path,
    strict: bool,
) -> Result<(), String> {
    config["inbounds"]
        .as_array_mut()
        .ok_or("Отсутствуют входы ядра")?
        .push(json!({
            "type": "tun", "tag": "windows-tun", "interface_name": "HomeProxy",
            "address": ["172.22.133.1/30", "fdfe:dcba:9877::1/126"],
            "mtu": 1500, "auto_route": true, "strict_route": true, "stack": "gvisor"
        }));
    let rules = config["route"]["rules"]
        .as_array_mut()
        .ok_or("Отсутствуют правила маршрутизации")?;
    rules.insert(
        0,
        json!({"inbound":"windows-tun", "port":53, "action":"hijack-dns"}),
    );
    let port = origin
        .port_or_known_default()
        .ok_or("У сервера нет порта")?;
    let agent_pattern = process_pattern(&agent_executable.to_string_lossy());
    let mut management = json!({
        "inbound": "windows-tun",
        "process_path_regex": [agent_pattern],
        "port": port, "action": "route", "outbound": "local-direct"
    });
    match origin.host().ok_or("У сервера нет адреса")? {
        Host::Domain(name) => management["domain"] = json!([name]),
        Host::Ipv4(ip) => management["ip_cidr"] = json!([format!("{ip}/32")]),
        Host::Ipv6(ip) => management["ip_cidr"] = json!([format!("{ip}/128")]),
    }
    let sniff = rules
        .iter()
        .position(|rule| rule["action"] == "sniff")
        .ok_or("Отсутствует правило распознавания домена")?;
    rules.insert(sniff + 1, management);
    if strict {
        let addresses =
            DOH_ADDRESSES.map(|ip| format!("{ip}/{}", if ip.contains(':') { 128 } else { 32 }));
        rules.insert(
            sniff + 1,
            json!({
                "inbound": "windows-tun", "process_path_regex": [agent_pattern],
                "ip_cidr": addresses, "port": 443, "network": "tcp",
                "action": "route", "outbound": "local-direct"
            }),
        );
    }
    config["route"]["auto_detect_interface"] = json!(true);
    let mut dns = tun_dns(profile, custom);
    dns["servers"]
        .as_array_mut()
        .ok_or("Отсутствуют серверы DNS Windows TUN")?
        .push(json!({
            "type": "hosts", "tag": "windows-loopback",
            "predefined": {"localhost": ["127.0.0.1", "::1"]}
        }));
    dns["rules"]
        .as_array_mut()
        .ok_or("Отсутствуют правила DNS Windows TUN")?
        .insert(
            0,
            json!({"domain": ["localhost"], "action": "route", "server": "windows-loopback"}),
        );
    if strict {
        dns["servers"]
            .as_array_mut()
            .ok_or("Отсутствуют серверы DNS Windows TUN")?
            .push(
                json!({"type": "https", "tag": "bootstrap-dns", "server": DOH_ADDRESSES[0],
                "path": "/dns-query", "tls": {"enabled": true, "server_name": DOH_NAME}}),
            );
        for outbound in config["outbounds"]
            .as_array_mut()
            .ok_or("Отсутствуют выходы ядра")?
        {
            if !matches!(outbound["type"].as_str(), Some("vless" | "http")) {
                continue;
            }
            if let Some(server) = outbound["server"]
                .as_str()
                .filter(|host| host.parse::<std::net::IpAddr>().is_err())
            {
                outbound["domain_resolver"] = json!(if server
                    .trim_end_matches('.')
                    .eq_ignore_ascii_case("localhost")
                {
                    "windows-loopback"
                } else {
                    "bootstrap-dns"
                });
            }
        }
    }
    config["dns"] = dns;
    Ok(())
}

pub(crate) fn with_fresh_interface(config: &Value) -> Result<Value, String> {
    let mut runtime = config.clone();
    let inbound = runtime["inbounds"]
        .as_array_mut()
        .and_then(|inbounds| {
            inbounds
                .iter_mut()
                .find(|inbound| inbound["tag"] == "windows-tun")
        })
        .ok_or("Отсутствует вход Windows TUN")?;
    let mut id = [0; 8];
    getrandom::fill(&mut id).map_err(|_| "Не удалось создать имя адаптера Windows TUN")?;
    // Wintun derives the adapter GUID from the name. Windows can still reserve
    // the old GUID after the previous core exits.
    inbound["interface_name"] = json!(format!("HomeProxy-{:016x}", u64::from_be_bytes(id)));
    Ok(runtime)
}

#[cfg(windows)]
pub(crate) fn check_elevation() -> Result<(), String> {
    use std::{mem::size_of, ptr::null_mut};
    use windows_sys::Win32::{
        Foundation::CloseHandle,
        Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY},
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };

    let mut token = null_mut();
    let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut bytes = 0;
    let elevated = unsafe {
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err("Не удалось проверить права системной маршрутизации".into());
        }
        let result = GetTokenInformation(
            token,
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut bytes,
        );
        CloseHandle(token);
        result != 0 && elevation.TokenIsElevated != 0
    };
    if elevated {
        Ok(())
    } else {
        Err("Windows TUN требует запуска контроллера с правами администратора".into())
    }
}

#[cfg(not(windows))]
pub(crate) fn check_elevation() -> Result<(), String> {
    Err("Этот режим TUN доступен только на Windows".into())
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use std::{
        io::Write,
        path::PathBuf,
        process::{Command, Stdio},
    };

    #[test]
    fn windows_tun_limits_control_traffic_and_passes_core_validation() {
        let mut config = json!({
            "inbounds": [{"type":"mixed","tag":"apps","listen":"127.0.0.1","listen_port":17770}],
            "outbounds": [
                {"type":"direct","tag":"local-direct"},
                {"type":"block","tag":"unavailable"},
                {"type":"selector","tag":"selected-proxy","outbounds":["unavailable"],"default":"unavailable"},
                {"type":"http","tag":"named-backup","server":"proxy.example.test","server_port":3128}
            ],
            "route": {
                "default_domain_resolver":"system",
                "rules":[{"action":"sniff"},{"action":"route","outbound":"selected-proxy"}]
            }
        });
        configure(
            &mut config,
            Profile::Auto,
            Action::Proxy,
            &Url::parse("https://control.example.test:8443").unwrap(),
            Path::new(r"C:\Program Files\HomeProxy\homeproxy-agent.exe"),
            true,
        )
        .unwrap();
        assert_eq!(config["inbounds"][1]["strict_route"], true);
        assert_eq!(config["route"]["rules"][0]["action"], "hijack-dns");
        assert_eq!(config["dns"]["rules"][0]["server"], "windows-loopback");
        assert_eq!(config["dns"]["rules"][1]["server"], "fake");
        let bootstrap = &config["route"]["rules"][2];
        assert_eq!(bootstrap["ip_cidr"][0], "9.9.9.9/32");
        assert_eq!(bootstrap["port"], 443);
        assert_eq!(config["outbounds"][3]["domain_resolver"], "bootstrap-dns");
        let control = &config["route"]["rules"][3];
        assert_eq!(control["domain"], json!(["control.example.test"]));
        assert_eq!(control["port"], 8443);
        assert!(control["process_path_regex"][0].as_str().is_some());
        let first = with_fresh_interface(&config).unwrap();
        let second = with_fresh_interface(&config).unwrap();
        let first_name = first["inbounds"][1]["interface_name"].as_str().unwrap();
        assert!(first_name.starts_with("HomeProxy-"));
        assert_ne!(
            first["inbounds"][1]["interface_name"],
            second["inbounds"][1]["interface_name"]
        );
        assert_eq!(config["inbounds"][1]["interface_name"], "HomeProxy");
        let binary = std::env::var_os("HOMEPROXY_TEST_SINGBOX")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../../../.tools/sing-box-1.14.4-windows-amd64/sing-box.exe")
            });
        if binary.exists() {
            let mut child = Command::new(binary)
                .args(["check", "-c", "stdin"])
                .stdin(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            child
                .stdin
                .take()
                .unwrap()
                .write_all(first.to_string().as_bytes())
                .unwrap();
            let result = child.wait_with_output().unwrap();
            assert!(
                result.status.success(),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
        }
    }
}
