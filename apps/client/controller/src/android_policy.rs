use crate::policy::{
    generate, generate_custom, parse_web, tun_dns, Action, Configuration, CustomProxy, Ports,
    Profile, ProxyListen, Rule, ServiceGroup,
};
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MobileConfig {
    remote: Option<Configuration>,
    #[serde(default)]
    local: Vec<Rule>,
    #[serde(default)]
    local_groups: Vec<ServiceGroup>,
    #[serde(default)]
    config_mode: String,
    #[serde(default)]
    custom_proxy: Option<CustomProxy>,
    #[serde(default)]
    excluded_apps: Vec<String>,
    profile: Profile,
    custom: Action,
    probe_port: u16,
    control_port: u16,
    secret: String,
    #[serde(default)]
    debug_loopback: bool,
}

pub fn render(raw: &str) -> Result<Value, String> {
    let mut input: MobileConfig =
        serde_json::from_str(raw).map_err(|_| "Некорректная конфигурация VPN")?;
    for rule in &mut input.local {
        rule.normalize()?;
    }
    for group in &mut input.local_groups {
        group.entries.retain(|entry| entry.kind != "process");
        group.validate()?;
    }
    let ports = Ports {
        proxy: 0,
        probe: input.probe_port,
        control: input.control_port,
        listen: ProxyListen::default(),
    };
    let mut has_locked = false;
    let generated = if input.config_mode == "custom" {
        let mut cp = input
            .custom_proxy
            .ok_or("Укажите параметры своего прокси")?;
        cp.validate()?;
        generate_custom(
            &cp,
            &input.local_groups,
            &input.local,
            input.profile,
            input.custom,
            &ports,
            &input.secret,
        )
    } else {
        let mut remote = input.remote.ok_or("Некорректная конфигурация VPN")?;
        parse_web(&remote.probe_url, input.debug_loopback)?;
        if remote.api != 1 || remote.revision == 0 || remote.proxies.len() > 16 {
            return Err("Несовместимая конфигурация VPN".into());
        }
        remote.rules.retain(|rule| rule.kind != "process");
        for rule in &mut remote.rules {
            rule.normalize()?;
        }
        for group in &mut remote.groups {
            group.entries.retain(|entry| entry.kind != "process");
            for entry in &mut group.entries {
                entry.normalize()?;
            }
        }
        has_locked = remote.rules.iter().any(|rule| rule.locked)
            || remote.groups.iter().any(|group| group.locked);
        generate(
            &remote,
            &input.local_groups,
            &input.local,
            input.profile,
            input.custom,
            &ports,
            &input.secret,
        )
    };
    let mut config = generated.config;
    let mut tun = json!({
        "type": "tun", "tag": "vpn",
        "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
        "mtu": 1500, "auto_route": true, "strict_route": true, "stack": "gvisor"
    });
    if !input.excluded_apps.is_empty() && !has_locked {
        tun["exclude_package"] = json!(input.excluded_apps);
    }
    let inbounds = config["inbounds"]
        .as_array_mut()
        .ok_or("Отсутствуют входы")?;
    inbounds.retain(|item| item["tag"] == "probe");
    inbounds.push(tun);
    let rules = config["route"]["rules"]
        .as_array_mut()
        .ok_or("Отсутствуют правила")?;
    rules.retain(|rule| {
        !rule["inbound"]
            .as_str()
            .is_some_and(|tag| tag.starts_with("browser-"))
            && rule["action"] != "sniff"
    });
    rules.splice(
        0..0,
        [
            json!({"inbound": "vpn", "action": "sniff", "timeout": "300ms"}),
            json!({"inbound": "vpn", "protocol": "dns", "action": "hijack-dns"}),
        ],
    );
    config["dns"] = tun_dns(input.profile, input.custom);
    Ok(
        json!({"config": config, "candidates": generated.candidates.iter()
        .map(|item| json!({"tag": item.tag, "name": item.name})).collect::<Vec<_>>()}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tun_uses_the_shared_profile_and_blocks_before_probes() {
        let mut fixture = json!({
            "remote": {
                "api": 1, "deviceId": "emulator", "revision": 1, "rules": [],
                "home": {
                    "host": "127.0.0.1", "port": 5940,
                    "id": "fb95215d-f415-46ca-8989-1c4724c55f26",
                    "directId": "58c5f58f-762f-4487-a009-dab50d15fa70",
                    "serverName": "localhost",
                    "publicKey": "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0",
                    "shortId": "0123456789abcdef"
                },
                "proxies": [{"id": "test", "name": "QA", "host": "127.0.0.1", "port": 5960, "tls": false}],
                "probeUrl": "http://127.0.0.1:5950/probe"
            },
            "profile": "AUTO", "custom": "PROXY", "probePort": 5971, "controlPort": 5972,
            "secret": "fixture", "debugLoopback": true
        });
        let result = render(&fixture.to_string()).unwrap();
        let config = &result["config"];
        assert_eq!(config["inbounds"][1]["type"], "tun");
        assert_eq!(config["route"]["rules"][1]["action"], "hijack-dns");
        let selector = config["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|out| out["tag"] == "selected-proxy")
            .unwrap();
        assert_eq!(selector["default"], "unavailable");
        assert_eq!(
            selector["outbounds"],
            json!(["direct-0", "home", "unavailable"])
        );
        let binary = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../.tools/sing-box-1.14.4-windows-amd64/sing-box.exe");
        fixture["profile"] = json!("DIRECT_INTERNET");
        let direct = render(&fixture.to_string()).unwrap();
        assert!(direct["config"]["dns"]["servers"][2]
            .get("detour")
            .is_none());
        if cfg!(windows) && binary.exists() {
            use std::{
                io::Write,
                process::{Command, Stdio},
            };
            for config in [config, &direct["config"]] {
                let mut child = Command::new(&binary)
                    .args(["check", "-c", "stdin"])
                    .stdin(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .unwrap();
                child
                    .stdin
                    .take()
                    .unwrap()
                    .write_all(config.to_string().as_bytes())
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

    #[test]
    fn custom_mode_and_local_groups_render_valid_tun_config() {
        let fixture = json!({
            "configMode": "custom",
            "customProxy": {
                "protocol": "SOCKS5",
                "host": "127.0.0.1",
                "port": 1080,
                "username": "u",
                "password": "p"
            },
            "localGroups": [{
                "id": "lg1",
                "name": "YouTube",
                "action": "PROXY",
                "enabled": true,
                "entries": [
                    {"kind": "package", "pattern": "com.google.android.youtube", "enabled": true},
                    {"kind": "suffix", "pattern": "youtube.com", "enabled": true}
                ]
            }],
            "profile": "DIRECT_INTERNET",
            "custom": "PROXY",
            "probePort": 5973,
            "controlPort": 5974,
            "secret": "fixture",
            "debugLoopback": true
        });
        let result = render(&fixture.to_string()).unwrap();
        let rules = result["config"]["route"]["rules"].as_array().unwrap();
        assert!(rules
            .iter()
            .any(|r| r["package_name"] == json!(["com.google.android.youtube"])));
        assert!(rules
            .iter()
            .any(|r| r["domain_suffix"] == json!(["youtube.com"])));
    }
}
