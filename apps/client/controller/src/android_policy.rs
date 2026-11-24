use crate::policy::{generate, parse_web, tun_dns, Action, Configuration, Ports, Profile, Rule};
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MobileConfig {
    remote: Configuration,
    #[serde(default)]
    local: Vec<Rule>,
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
    parse_web(&input.remote.probe_url, input.debug_loopback)?;
    if input.remote.api != 1 || input.remote.revision == 0 || input.remote.proxies.len() > 16 {
        return Err("Несовместимая конфигурация VPN".into());
    }
    input.remote.rules.retain(|rule| rule.kind != "process");
    for rule in input.remote.rules.iter_mut().chain(&mut input.local) {
        rule.normalize()?;
    }
    let ports = Ports {
        proxy: 0,
        probe: input.probe_port,
        control: input.control_port,
    };
    let generated = generate(
        &input.remote,
        &input.local,
        input.profile,
        input.custom,
        &ports,
        &input.secret,
    );
    let mut config = generated.config;
    let mut tun = json!({
        "type": "tun", "tag": "vpn",
        "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
        "mtu": 1500, "auto_route": true, "strict_route": true, "stack": "gvisor"
    });
    if !input.excluded_apps.is_empty() && !input.remote.rules.iter().any(|rule| rule.locked) {
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
            json!(["home", "backup-0", "unavailable"])
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
}
