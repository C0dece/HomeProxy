"""Test a HomeProxy APK on the dedicated HomeProxy Android emulator."""
import argparse
import base64
import contextlib
import hashlib
import importlib.util
import json
import os
import re
import secrets
import shutil
import socketserver
import sqlite3
import ssl
import subprocess
import tempfile
import threading
from pathlib import Path
from xml.etree import ElementTree

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("loopback", ROOT / "windows-integration.py")
loopback = importlib.util.module_from_spec(spec)
spec.loader.exec_module(loopback)

APP = "app.homeproxy.agent"
PROBE_APP = "app.homeproxy.qa"
TARGET = "10.0.2.2"
IPV6_TARGET = "2001:db8::43"
DNS_TARGET = "android-dns.homeproxy.test"
RELEASE_PORT = 18893
HIDDEN = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def build_probe_apk(sdk, root):
    manifest = root / "AndroidManifest.xml"
    manifest.write_text(f'''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="{PROBE_APP}">
  <uses-sdk android:minSdkVersion="29" android:targetSdkVersion="34" />
  <uses-permission android:name="android.permission.INTERNET" />
  <application android:debuggable="true" android:hasCode="false" android:label="HomeProxy QA HTTP">
    <activity android:name="android.app.Activity" android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.MAIN" />
        <category android:name="android.intent.category.LAUNCHER" />
      </intent-filter>
    </activity>
  </application>
</manifest>''', encoding="utf-8")
    tools = sdk / "build-tools" / "36.0.0"
    unsigned, apk, key = (root / name for name in ("unsigned.apk", "probe.apk", "probe.p12"))
    subprocess.run([tools / "aapt2.exe", "link", "--manifest", manifest, "-I",
                    sdk / "platforms" / "android-36" / "android.jar", "-o", unsigned],
                   check=True, capture_output=True, creationflags=HIDDEN)
    subprocess.run(["keytool", "-genkeypair", "-keyalg", "RSA", "-keysize", "2048", "-alias", "qa",
                    "-dname", "CN=HomeProxy QA", "-validity", "1", "-storepass", "android", "-keystore", key],
                   check=True, capture_output=True, creationflags=HIDDEN)
    subprocess.run([tools / "apksigner.bat", "sign", "--ks", key, "--ks-pass", "pass:android",
                    "--out", apk, unsigned], check=True, capture_output=True, creationflags=HIDDEN)
    return apk


class Releases(loopback.Origin):
    def do_GET(self):
        data = {"/release.json": self.server.manifest, "/release.sig": self.server.signature}
        if self.path in data:
            body = data[self.path]
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/agent.apk":
            self.send_response(200)
            self.send_header("Content-Length", str(self.server.apk.stat().st_size))
            self.end_headers()
            with self.server.apk.open("rb") as stream:
                if self.server.corrupt:
                    byte = stream.read(1)
                    self.wfile.write(bytes([byte[0] ^ 1]))
                shutil.copyfileobj(stream, self.wfile, 65536)
        else:
            self.send_error(404)


class UdpEcho(socketserver.BaseRequestHandler):
    def handle(self):
        payload, socket = self.request
        self.server.received.append(payload)
        socket.sendto(payload, self.client_address)


def release_fixture(args, root):
    with args.update_apk.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    manifest = root / "release.json"
    manifest.write_text(json.dumps({"format": 1, "artifacts": [{
        "component": "agent", "platform": "android", "arch": "x86_64", "channel": "stable",
        "version": "0.1.5", "versionCode": 1005, "size": args.update_apk.stat().st_size,
        "sha256": digest, "apiMin": 1, "apiMax": 1, "notes": "HomeProxy QA",
        "url": f"http://127.0.0.1:{RELEASE_PORT}/agent.apk",
    }]}), encoding="utf-8")
    signature = subprocess.run([args.openssl, "pkeyutl", "-sign", "-rawin", "-inkey", args.update_key, "-in", manifest],
                               check=True, capture_output=True, creationflags=HIDDEN).stdout
    return loopback.launch_http(Releases, port=RELEASE_PORT, manifest=manifest.read_bytes(),
                                signature=base64.b64encode(signature), corrupt=False, apk=args.update_apk)


def test(args, root):
    with contextlib.ExitStack() as stack:
        def adb(*argv, check=True):
            return subprocess.run([str(args.adb), "-s", args.serial, *argv], check=check, capture_output=True,
                                  timeout=40, creationflags=HIDDEN).stdout

        if not args.serial.startswith("emulator-"):
            raise RuntimeError("The test requires an Android emulator")
        actual = adb("emu", "avd", "name").decode().splitlines()[0].strip()
        if not actual.startswith("HomeProxy_QA_"):
            raise RuntimeError("The emulator must be dedicated to HomeProxy")
        install_flags = ("-r", "-d") if args.update_apk else ("-r",)
        adb("install", *install_flags, str(args.apk))
        if args.system_vpn:
            # Package removal clears any Always-on assignment left by an interrupted test.
            stack.callback(adb, "uninstall", APP, check=False)
        probe_apk = build_probe_apk(args.adb.parent.parent, root)
        adb("uninstall", PROBE_APP, check=False)
        adb("install", str(probe_apk))
        stack.callback(adb, "uninstall", PROBE_APP, check=False)
        adb("shell", "input", "keyevent", "KEYCODE_WAKEUP")
        adb("shell", "wm", "dismiss-keyguard")
        stack.callback(lambda: adb("shell", "am", "force-stop", APP, check=False))

        origin = loopback.launch_http(loopback.Origin)
        stack.callback(loopback.stop_http, origin)

        def authority(host):
            return f"[{host}]" if ":" in host else host

        def network(package=None, host=TARGET):
            # Keep stdin open while the fixture's CONNECT proxy relays the response.
            request = f"GET /route HTTP/1.1\\r\\nHost: {authority(host)}\\r\\nConnection: close\\r\\n\\r\\n"
            command = f"toybox nc -w 4 -W 5 {host} {origin.server_port}"
            if package:
                command = f"run-as {package} {command}"
            raw = adb("shell", f"(printf '{request}' && sleep 2) | {command}",
                      check=False)
            return b"homeproxy-origin" in raw

        assert network(), "Android origin must be directly reachable without the VPN"
        assert network(PROBE_APP), "Android test application could not reach the origin without the VPN"
        if args.network_vpn:
            udp = socketserver.UDPServer(("127.0.0.1", 0), UdpEcho)
            udp.received = []
            threading.Thread(target=udp.serve_forever, daemon=True).start()
            stack.callback(udp.server_close)
            stack.callback(udp.shutdown)

            def udp_echo():
                port = udp.server_address[1]
                data = adb("shell", f"(printf homeproxy-udp && sleep 1) | run-as {PROBE_APP} toybox timeout 4 toybox nc -u -q 1 {TARGET} {port}",
                           check=False)
                return b"homeproxy-udp" in data

            assert udp_echo(), "The direct UDP fixture must echo before starting the VPN"
        probe = loopback.launch_http(loopback.Origin)
        stack.callback(loopback.stop_http, probe)
        password = secrets.token_urlsafe(20)
        provider_target = f"{TARGET}:{origin.server_port}"
        provider = loopback.launch_http(
            loopback.Connect,
            auth="Basic " + base64.b64encode(f"android-qa:{password}".encode()).decode(),
            targets={provider_target, loopback.address(probe.server_port),
                     f"{authority(IPV6_TARGET)}:{origin.server_port}", f"{DNS_TARGET}:{origin.server_port}"}, connects=[],
        )
        stack.callback(loopback.stop_http, provider)

        def proxied(package=None, host=TARGET):
            before = len(provider.connects)
            return network(package, host) and f"{authority(host)}:{origin.server_port}" in provider.connects[before:]
        cert, key = root / "handshake.crt", root / "handshake.key"
        subprocess.run([args.openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-subj", "/CN=localhost", "-keyout", key, "-out", cert], check=True,
                       capture_output=True, creationflags=HIDDEN)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(cert, key)
        handshake = loopback.launch_http(loopback.Origin, tls=tls)
        stack.callback(loopback.stop_http, handshake)
        api, tunnel = loopback.new_port(), loopback.new_port()
        admin = secrets.token_urlsafe(32)
        config = root / "server.json"
        with contextlib.closing(sqlite3.connect(root / "store.sqlite")) as old_store:
            old_store.executescript((ROOT.parent / "apps/server/migrations/001.sql").read_text(encoding="utf-8"))
            old_store.execute("PRAGMA user_version=1")
            old_store.executemany(
                "INSERT INTO rules VALUES(?,NULL,?,?,?,0,1)",
                [("old-site", "legacy.example", "domain", "PROXY"), ("old-exe", "legacy.exe", "process", "BLOCK")],
            )
            old_store.commit()
        config.write_text(json.dumps({
            "listen": loopback.address(api), "publicUrl": "http://" + loopback.address(api),
            "database": "store.sqlite", "keyFile": "vault.key", "realityKeyFile": "reality.key",
            "singBox": str(args.sing_box), "tunnelListen": loopback.address(tunnel),
            "tunnelHost": "127.0.0.1", "tunnelPort": tunnel, "serverName": "localhost",
            "handshakeHost": "127.0.0.1", "handshakePort": handshake.server_port,
            "probeUrl": "http://" + loopback.address(probe.server_port) + "/probe", "loopbackDev": True,
        }), encoding="utf-8")
        log = stack.enter_context((root / "server.log").open("wb"))
        def start_server():
            return subprocess.Popen([args.server, "-config", config], creationflags=HIDDEN, stdout=log, stderr=log,
                                    env={**os.environ, "HOMEPROXY_ADMIN_TOKEN": admin})

        server = start_server()

        def stop_server():
            if server.poll() is None:
                server.kill()
                server.wait(timeout=6)

        stack.callback(stop_server)
        health = loopback.eventual(lambda: loopback.request(api, "GET", "/healthz")[0], "Android fixture server")
        assert health["ready"] and health["dbSchema"] == 2
        sockets = [f"tcp:{port}" for port in (api, tunnel, probe.server_port, provider.server_port)]
        if args.update_apk:
            release = release_fixture(args, root)
            stack.callback(loopback.stop_http, release)
            sockets.append(f"tcp:{RELEASE_PORT}")

        def restore_reverses():
            for name in sockets:
                adb("reverse", name, name)

        restore_reverses()
        for name in sockets:
            stack.callback(adb, "reverse", "--remove", name, check=False)

        def change(method, path, data, expected=200):
            return loopback.request(api, method, "/api/v1/admin/" + path, data, admin, expected)[0]

        assert {rule["id"] for rule in change("GET", "state", None)["rules"]} == {"old-site", "old-exe"}
        user = change("POST", "users", {"name": "Android QA"}, 201)["id"]
        proxy = change("PUT", "proxies", {"name": "Android QA CONNECT", "host": "127.0.0.1",
                       "port": provider.server_port, "username": "android-qa", "password": password})["id"]
        change("PUT", "routes", {"userId": user, "proxyIds": [proxy]}, 204)
        invite = change("POST", "invites", {"userId": user, "label": "Android emulator", "transport": "agent"}, 201)

        def launch_app():
            adb("shell", "am", "start", "-n", APP + "/.MainActivity")
            pid = loopback.eventual(lambda: adb("shell", "pidof", APP, check=False).decode().strip(), "Android app").split()[0]
            forward = adb("forward", "tcp:0", "localabstract:webview_devtools_remote_" + pid).decode().strip()
            stack.callback(adb, "forward", "--remove", "tcp:" + forward, check=False)
            return ["node", str(ROOT / "android-webview.mjs"), forward]

        adb("shell", "pm", "clear", APP)
        node = launch_app()

        def ctl(command, data=None):
            process = subprocess.run(node, input=json.dumps({"command": command, "data": data}),
                                     capture_output=True, text=True, encoding="utf-8",
                                     timeout=205 if command == "update-install" else 30,
                                     creationflags=HIDDEN, check=True)
            return json.loads(process.stdout)

        loopback.eventual(lambda: ctl("status").get("platform") == "android", "Android Tauri bridge")
        assert ctl("ui-connect", {"link": invite["link"]})
        loopback.eventual(lambda: ctl("status").get("revision"), "Android enrollment")

        loopback.eventual(lambda: ctl("ui-vpn", {"enabled": True}), "Start VPN button")

        def ui_tree():
            if adb("shell", "uiautomator", "dump", "/sdcard/homeproxy-test-ui.xml").startswith(b"ERROR"):
                raise OSError("Android UI hierarchy is temporarily unavailable")
            return ElementTree.fromstring(adb("shell", "cat", "/sdcard/homeproxy-test-ui.xml"))

        def tap(item):
            x1, y1, x2, y2 = map(int, re.findall(r"\d+", item.get("bounds", "")))
            adb("shell", "input", "tap", str((x1 + x2) // 2), str((y1 + y2) // 2))
            return True

        def press_ok():
            for item in ui_tree().iter("node"):
                if item.get("text") != "OK" or item.get("resource-id") != "android:id/button1":
                    continue
                return tap(item)
            return ctl("status")["enabled"]

        def setting(tree, label, resource_id):
            for row in reversed(list(tree.iter("node"))):
                if row.find(f".//node[@text='{label}']") is None:
                    continue
                widget = row.find(f".//node[@resource-id='{resource_id}']")
                if widget is not None:
                    return widget
                if resource_id == "android:id/switch_widget" and row.get("checkable") == "true":
                    return row
            return None

        def open_system_settings():
            assert ctl("ui-vpn-settings")

            def open_homeproxy():
                gear = setting(ui_tree(), "HomeProxy Agent", "com.android.settings:id/settings_button")
                return gear is not None and tap(gear)

            loopback.eventual(open_homeproxy, "HomeProxy system VPN settings", 25)

        def system_switch(label, enabled):
            def widget():
                item = setting(ui_tree(), label, "android:id/switch_widget")
                return (item,) if item is not None and item.get("enabled") == "true" else None

            item, = loopback.eventual(widget, label, 40)
            target = str(enabled).lower()
            if item.get("checked") != target:
                tap(item)

            def changed():
                if label == "Always-on VPN":
                    owner = adb("shell", "settings", "get", "secure", "always_on_vpn_app").strip()
                    if (owner == APP.encode()) == enabled:
                        return True
                if label == "Block connections without VPN":
                    lockdown = adb("shell", "settings", "get", "secure", "always_on_vpn_lockdown").strip()
                    if (lockdown == b"1") == enabled:
                        return True
                view = ui_tree()
                confirm = view.find(".//node[@resource-id='android:id/button1']")
                if confirm is not None and confirm.get("text") in ("OK", "Turn on", "Turn off"):
                    tap(confirm)
                    return False
                item = setting(view, label, "android:id/switch_widget")
                return item is not None and item.get("checked") == target

            loopback.eventual(changed, label + " toggle", 25)

        def has_tun():
            return any(re.fullmatch(rb"tun\d+", name) for name in adb("shell", "ls", "/sys/class/net").splitlines())

        loopback.eventual(press_ok, "VPN consent dialog", 24)

        loopback.eventual(lambda: ctl("status")["route"]["selected"] == "home", "Android VLESS route", 35)
        loopback.eventual(proxied, "Android HTTP through VLESS")
        apk_version = re.search(rb"versionName=([^\s]+)", adb("shell", "dumpsys", "package", APP)).group(1).decode()
        def reported_version():
            return next((row for row in change("GET", "state", None)["devices"]
                         if row["label"] == "Android emulator" and row["platform"] == "android"
                         and row["installedVersion"] == apk_version), None)
        loopback.eventual(reported_version, "Android installed version report")
        change("PUT", "client-update-policy", {"paused": True})
        ctl("sync")
        assert ctl("update-status")["paused"]
        for command, payload in (("update-check", {"channel": "stable"}), ("update-confirm", None)):
            try:
                ctl(command, payload)
                raise AssertionError(f"Paused Android accepted {command}")
            except subprocess.CalledProcessError as error:
                assert "Администратор приостановил обновления" in error.stderr, error.stderr
        change("PUT", "client-update-policy", {"paused": False})
        ctl("sync")
        assert not ctl("update-status")["paused"]
        print("PASS Android applied and released the administrator update pause", flush=True)
        print("PASS Android link, permission, TUN and real VLESS + REALITY traffic", flush=True)
        if args.network_vpn:
            loopback.eventual(lambda: proxied(PROBE_APP, DNS_TARGET), "Android DNS through VPN", 22)
            loopback.eventual(lambda: proxied(PROBE_APP, IPV6_TARGET), "Android IPv6 through VPN", 22)
            received = len(udp.received)
            assert not udp_echo() and len(udp.received) == received, "UDP escaped the selected TCP-only route"

            def physical_network(kind):
                dump = adb("shell", "dumpsys", "connectivity")
                default = re.search(rb"Active default network: (\d+)", dump)
                return default and any(
                    b"NetworkAgentInfo{network{" + default[1] + b"}" in line and b"ni{" + kind in line
                    for line in dump.splitlines()
                )

            assert ctl("profile", {"profile": "DIRECT_INTERNET"})["enabled"]
            assert physical_network(b"WIFI")
            stack.callback(adb, "shell", "svc", "wifi", "enable", check=False)
            adb("shell", "svc", "wifi", "disable")
            loopback.eventual(lambda: physical_network(b"MOBILE"), "Android emulated mobile network", 40)
            loopback.eventual(lambda: network(PROBE_APP), "Android TUN on emulated mobile network", 32)
            assert ctl("status")["enabled"]
            adb("shell", "svc", "wifi", "enable")
            loopback.eventual(lambda: physical_network(b"WIFI"), "Android restored Wi-Fi", 40)
            assert network(PROBE_APP) and ctl("status")["enabled"]
            ctl("profile", {"profile": "AUTO"})
            loopback.eventual(proxied, "Android proxy after switching networks")
            print("PASS Android DNS, IPv6, UDP blocking and TUN across emulated network switches", flush=True)
        def active_screen():
            content = ctl("ui-text")
            return "Остановить VPN" in content and "HomeProxy Server" in content

        loopback.eventual(active_screen, "Android status screen", 15)
        shot = Path("dist/qa/android-vpn.png")
        shot.parent.mkdir(parents=True, exist_ok=True)
        shot.write_bytes(adb("exec-out", "screencap", "-p"))
        state_on_disk = adb("exec-out", "run-as", APP, "cat", "no_backup/homeproxy.sealed")
        assert state_on_disk[:1] == b"\x01" and password.encode() not in state_on_disk
        assert b"configuration.json" not in adb("shell", "run-as", APP, "ls", "-1", "no_backup/core").splitlines()
        adb("shell", "input", "keyevent", "KEYCODE_HOME")
        assert network(), "VPN stopped when the activity went into the background"
        adb("shell", "am", "start", "-n", APP + "/.MainActivity")
        print("PASS Android background routing and encrypted persisted settings", flush=True)

        global_rule = change("PUT", "rules", {"kind": "package", "pattern": PROBE_APP, "action": "BLOCK"})
        legacy_invite = change("POST", "invites", {"userId": user, "label": "QA API", "transport": "agent"}, 201)["link"]
        legacy_key = secrets.token_urlsafe(32)
        loopback.request(api, "POST", "/api/v1/connect", {
            "token": legacy_invite.split("#")[1], "deviceKey": legacy_key, "transport": "agent",
        }, expected=201)
        legacy, legacy_tag = loopback.request(api, "GET", "/api/v1/config", token=legacy_key)
        android, android_tag = loopback.request(api, "GET", "/api/v1/config?platform=android", token=legacy_key,
                                                 headers={"If-None-Match": legacy_tag})
        assert legacy_tag != android_tag
        assert {rule["id"] for rule in legacy["rules"]} == {"old-site", "old-exe"}
        assert {rule["id"] for rule in android["rules"]} == {"old-site", global_rule["id"]}
        assert ctl("sync")["route"]["selected"] == "home"
        assert not network(PROBE_APP), "GLOBAL package BLOCK did not block its app"
        assert proxied(), "GLOBAL package BLOCK affected another UID"
        assert ctl("ui-apps")
        row = loopback.eventual(lambda: ctl("ui-package", {"package": PROBE_APP}), "Android package row and icon")
        assert all(value in row for value in ("HomeProxy QA HTTP", PROBE_APP, "GLOBAL", "Блокировать"))

        exclusion = {"package": PROBE_APP, "excluded": True}
        assert ctl("vpn-exclusion", exclusion)["excludedApps"] == [PROBE_APP]
        before = len(provider.connects)
        assert network(PROBE_APP), "Excluded UID did not reach the origin"
        assert provider_target not in provider.connects[before:]
        assert proxied(), "Excluding one UID changed the route of another"
        loopback.eventual(lambda: PROBE_APP in ctl("ui-exclusions"), "Android exclusions screen")
        (Path("dist/qa") / "android-exclusions.png").write_bytes(adb("exec-out", "screencap", "-p"))
        mandatory = change("PUT", "rules", {
            "kind": "domain", "pattern": "mandatory.homeproxy.test", "action": "BLOCK", "locked": True,
        })
        status = ctl("sync")
        assert not status["exclusionsAllowed"] and status["excludedApps"] == [PROBE_APP]
        assert not network(PROBE_APP), "An exclusion bypassed the mandatory policy guard"
        assert ctl("vpn-exclusion", {**exclusion, "excluded": False})["excludedApps"] == []
        change("DELETE", "rules/" + mandatory["id"], None, 204)
        assert ctl("sync")["exclusionsAllowed"]
        print("PASS Android per-UID VPN exclusion and mandatory-policy suspension", flush=True)

        package = {"package": PROBE_APP, "scope": "LOCAL", "action": "LOCAL_DIRECT"}
        loopback.eventual(lambda: ctl("ui-package-save", package), "Android LOCAL package form")
        loopback.eventual(lambda: any(rule["pattern"] == PROBE_APP and rule["action"] == "LOCAL_DIRECT"
                                      for rule in ctl("status")["rules"]), "Android LOCAL package rule")
        before = len(provider.connects)
        assert network(PROBE_APP), "LOCAL package rule did not route directly"
        assert provider_target not in provider.connects[before:]
        row = ctl("ui-package", package)
        assert "LOCAL" in row and "Напрямую с устройства" in row
        assert ctl("ui-app-search", {"query": PROBE_APP})
        (Path("dist/qa") / "android-apps.png").write_bytes(adb("exec-out", "screencap", "-p"))

        personal = {**package, "scope": "PERSONAL", "action": "PROXY"}
        loopback.eventual(lambda: ctl("ui-package-save", personal), "Android PERSONAL package form")
        loopback.eventual(lambda: any(rule.get("userId") and rule["pattern"] == PROBE_APP and rule["action"] == "PROXY"
                                      for rule in ctl("status")["remoteRules"]), "Android PERSONAL package sync")
        assert ctl("local-rule", {"kind": "package", "pattern": PROBE_APP, "action": "INHERIT"})["rules"] == []
        assert proxied(PROBE_APP), "PERSONAL package rule did not override GLOBAL"
        print("PASS Android package rules, app icon and LOCAL/PERSONAL/GLOBAL precedence across two UIDs", flush=True)

        if args.update_apk:
            before_update = ctl("local-rule", {"kind": "domain", "pattern": "update-persist.homeproxy.test", "action": "BLOCK"})
            assert ctl("ui-updates")
            assert ctl("update-status")["configured"]
            signature = release.signature
            release.signature = base64.b64encode(bytes(64))
            try:
                ctl("update-check", {"channel": "stable"})
                raise AssertionError("Invalid manifest signature accepted")
            except subprocess.CalledProcessError:
                assert ctl("update-status")["offer"] is None
            release.signature = signature
            offer = ctl("update-check", {"channel": "stable"})["offer"]
            assert offer["version"] == "0.1.5"
            loopback.eventual(lambda: "HomeProxy 0.1.5" in ctl("ui-text"), "Android verified update offer", 18)
            (Path("dist/qa") / "android-update.png").write_bytes(adb("exec-out", "screencap", "-p"))
            if not ctl("update-status")["allowed"]:
                ctl("update-permission")
                system_switch("Allow from this source", True)
                adb("shell", "am", "start", "-n", APP + "/.MainActivity")

            version = {"channel": "stable", "version": offer["version"]}
            release.corrupt = True
            try:
                ctl("update-install", version)
                raise AssertionError("Tampered APK accepted")
            except subprocess.CalledProcessError:
                assert not ctl("update-status")["active"]
            release.corrupt = False
            assert ctl("update-install", version)["active"]
            loopback.eventual(lambda: ctl("update-status")["confirm"], "Android PackageInstaller callback")
            ctl("update-confirm")

            def confirm_install():
                for item in ui_tree().iter("node"):
                    if item.get("text", "").lower() in ("update", "install") and item.get("clickable") == "true":
                        return tap(item)
                return False

            loopback.eventual(confirm_install, "Android installation consent")
            loopback.eventual(lambda: b"versionName=0.1.5" in adb("shell", "dumpsys", "package", APP),
                              "Updated APK version", 70)
            # Wait for the system installer to release the Activity and its old resources.
            loopback.eventual(ui_tree, "Android installer idle", 25)
            node = launch_app()
            restored = loopback.eventual(lambda: ctl("status"), "Android state after update")
            assert restored["linked"] and restored["revision"] >= before_update["revision"]
            assert restored["rules"] == before_update["rules"]
            loopback.eventual(lambda: ctl("ui-vpn", {"enabled": True}), "Start VPN after update")
            loopback.eventual(press_ok, "VPN permission after update", 25)
            loopback.eventual(proxied, "Android VPN traffic after update")
            print("PASS Android manifest signature, corrupt APK rejection and PackageInstaller upgrade preserving profiles", flush=True)

        stop_server()
        loopback.eventual(lambda: ctl("status")["route"]["selected"] == "backup-0", "Android offline backup", 35)
        assert proxied(), "Android fallback did not deliver HTTP"

        adb("shell", "am", "force-stop", APP)
        node = launch_app()
        loopback.eventual(lambda: ctl("status").get("revision"), "Android cached configuration")
        loopback.eventual(lambda: ctl("ui-vpn", {"enabled": True}), "Start VPN offline")
        loopback.eventual(press_ok, "VPN permission after restart", 24)
        loopback.eventual(lambda: ctl("status")["route"]["selected"] == "backup-0", "Android restored offline backup", 35)
        assert proxied(), "VPN did not restore HTTP traffic after a cold offline start"
        print("PASS Android cold restart using the encrypted offline configuration", flush=True)

        if args.system_vpn:
            open_system_settings()
            system_switch("Always-on VPN", True)
            system_switch("Block connections without VPN", True)
            adb("shell", "am", "start", "-n", APP + "/.MainActivity")

            def locked():
                status = ctl("status")
                return status["enabled"] and status["alwaysOn"] and status["lockdown"]

            loopback.eventual(locked, "Android reported system VPN policy")
            assert not ctl("ui-vpn", {"enabled": False})
            assert ctl("vpn-exclusion", exclusion)["excludedApps"] == [PROBE_APP]
            loopback.eventual(proxied, "Included UID after applying the exclusion under lockdown", 28)
            assert not network(PROBE_APP), "An excluded UID escaped Android lockdown"
            assert ctl("vpn-exclusion", {**exclusion, "excluded": False})["excludedApps"] == []
            print("PASS Android lockdown blocks an excluded UID", flush=True)

            boot_id = adb("shell", "cat", "/proc/sys/kernel/random/boot_id")
            adb("reboot")

            def rebooted():
                current = adb("shell", "cat", "/proc/sys/kernel/random/boot_id")
                return current != boot_id and adb("shell", "getprop", "sys.boot_completed").strip() == b"1"

            loopback.eventual(rebooted, "Android reboot", 120)
            restore_reverses()
            adb("shell", "input", "keyevent", "KEYCODE_WAKEUP")
            adb("shell", "wm", "dismiss-keyguard")
            loopback.eventual(has_tun, "Always-on TUN without launching the activity", 50)
            loopback.eventual(lambda: proxied(PROBE_APP), "Always-on HTTP after reboot", 65)
            print("PASS Android system Always-on VPN started before the activity after reboot", flush=True)

            adb("shell", "input", "keyevent", "KEYCODE_SLEEP")
            loopback.eventual(lambda: b"mCommittedState=OFF" in adb("shell", "dumpsys", "display"), "Android screen off")
            assert proxied(PROBE_APP), "Always-on VPN stopped forwarding with the screen off"
            adb("shell", "input", "keyevent", "KEYCODE_WAKEUP")
            adb("shell", "wm", "dismiss-keyguard")
            node = launch_app()
            loopback.eventual(locked, "Restored Android lockdown status")
            loopback.eventual(lambda: (ctl("ui-vpn-policy") or "").count("Включено") == 2,
                              "HomeProxy policy screen", 20)
            loopback.eventual(ui_tree, "Android policy screen is idle", 25)
            (Path("dist/qa") / "android-lockdown.png").write_bytes(adb("exec-out", "screencap", "-p"))

        loopback.stop_http(provider)
        def blocked():
            status = ctl("status")
            return status["enabled"] and status["route"]["selected"] is None

        loopback.eventual(blocked, "Android blocked proxy", 35)
        assert not network(), "VPN selected a different egress after proxy failure"
        print("PASS Android offline HTTP CONNECT fallback and fail-closed routing", flush=True)
        if args.system_vpn:
            server = start_server()
            loopback.eventual(lambda: loopback.request(api, "GET", "/healthz")[0]["ready"], "Reopened Android fixture server")
            change("DELETE", "devices/" + invite["id"], None, 204)
            status = {}

            def revoked():
                status.update(ctl("sync"))
                return not status["linked"] and not status["enabled"]

            try:
                loopback.eventual(revoked, "Revocation under Android lockdown", 20)
            except AssertionError as error:
                fields = ("linked", "enabled", "alwaysOn", "lockdown", "online", "error")
                raise AssertionError({key: status.get(key) for key in fields}) from error
            loopback.eventual(lambda: not has_tun(), "Closed TUN after server revocation")
            assert adb("shell", "settings", "get", "secure", "always_on_vpn_app").strip() == APP.encode()
            assert adb("shell", "settings", "get", "secure", "always_on_vpn_lockdown").strip() == b"1"
            assert not network(PROBE_APP), "Android allowed direct traffic without a TUN under lockdown"
            loopback.eventual(lambda: "Подключите устройство" in ctl("ui-text"), "Android revoked UI", 20)
            open_system_settings()
            system_switch("Block connections without VPN", False)
            loopback.eventual(lambda: network(PROBE_APP), "Android direct origin after disabling lockdown")
            system_switch("Always-on VPN", False)
            print("PASS Android screen-off forwarding, lockdown without a TUN, and release through Settings", flush=True)
        else:
            loopback.eventual(lambda: ctl("ui-vpn", {"enabled": False}), "Stop VPN button")
            loopback.eventual(network, "Android direct origin after VPN stop")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    for flag in ("adb", "apk", "server", "sing-box"):
        parser.add_argument("--" + flag, type=lambda value: Path(value).resolve(strict=True), required=True)
    parser.add_argument("--serial", default="emulator-5570")
    parser.add_argument("--system-vpn", action="store_true", help="Exercise native Always-on and lockdown with an emulator reboot")
    parser.add_argument("--network-vpn", action="store_true", help="Exercise DNS, IPv6, UDP and emulated Wi-Fi/mobile switches")
    parser.add_argument("--update-apk", type=lambda value: Path(value).resolve(strict=True))
    parser.add_argument("--update-key", type=lambda value: Path(value).resolve(strict=True))
    parser.add_argument("--openssl", default=r"C:\Program Files\Git\usr\bin\openssl.exe")
    params = parser.parse_args()
    if bool(params.update_apk) != bool(params.update_key):
        parser.error("--update-apk and --update-key must be used together")
    with tempfile.TemporaryDirectory(prefix="HomeProxy-Android-") as temporary:
        test(params, Path(temporary))
