"""Loopback integration. Requires Windows, Python 3, sing-box and OpenSSL."""
import argparse
import base64
import contextlib
import ctypes
import hashlib
import http.client
import http.server
import json
import os
import secrets
import select
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
from pathlib import Path


class Origin(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_HEAD(self):
        self.send_response(204)
        self.end_headers()

    def do_GET(self):
        if urllib.parse.urlsplit(self.path).path == "/browser-fixture":
            port = self.server.server_port
            body = f'<!doctype html><title>HomeProxy QA</title><h1>HomeProxy QA</h1><link rel="stylesheet" href="http://asset.homeproxy.test:{port}/asset.css">'.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        body = b"homeproxy-origin"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class NamedApiProxy(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def forward(self):
        size = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(size) if size else None
        headers = {name: self.headers[name] for name in ("Authorization", "Content-Type", "If-None-Match")
                   if name in self.headers}
        with contextlib.closing(http.client.HTTPConnection("127.0.0.1", self.server.api_port, timeout=4)) as api:
            try:
                api.request(self.command, self.path, body=body, headers=headers)
                response = api.getresponse()
                data = response.read()
            except (OSError, http.client.HTTPException):
                with contextlib.suppress(BrokenPipeError, ConnectionResetError):
                    self.send_error(502)
                return
            if self.path == "/api/v1/config" and response.status == 200:
                config = json.loads(data)
                for proxy in config.get("proxies", []):
                    if proxy["port"] == self.server.named_proxy_port:
                        proxy["host"] = self.server.named_host
                data = json.dumps(config).encode()
            self.send_response(response.status)
            for name in ("Content-Type", "ETag"):
                if value := response.getheader(name):
                    self.send_header(name, value)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    do_GET = do_POST = do_PUT = forward


class Connect(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def allowed(self):
        return self.headers.get("Proxy-Authorization") == self.server.auth

    def do_HEAD(self):
        target = urllib.parse.urlsplit(self.path)
        self.send_response(204 if self.allowed() and target.netloc in self.server.targets else 407)
        self.end_headers()

    def do_CONNECT(self):
        if not self.allowed() or self.path not in self.server.targets:
            self.send_response(407)
            self.end_headers()
            return
        with socket.create_connection(("127.0.0.1", int(self.path.rsplit(":", 1)[-1])), timeout=5) as upstream:
            self.server.connects.append(self.path)
            self.send_response(200)
            self.end_headers()
            peers = {self.connection: upstream, upstream: self.connection}
            while ready := select.select(list(peers), [], [], 6)[0]:
                for source in ready:
                    data = source.recv(65536)
                    if not data:
                        return
                    peers[source].sendall(data)


def address(port):
    return f"127.0.0.1:{port}"


def new_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def proxy_ports():
    for _ in range(20):
        base = 20_000 + secrets.randbelow(20_000)
        try:
            with contextlib.ExitStack() as sockets:
                for offset in (0, 2, 3, 4):
                    listener = sockets.enter_context(socket.socket())
                    listener.bind(("127.0.0.1", base + offset))
                return base
        except OSError:
            continue
    raise RuntimeError("No free range for the isolated proxy listeners")


def launch_http(handler, port=0, tls=None, **attrs):
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), handler)
    for name, value in attrs.items():
        setattr(server, name, value)
    if tls:
        server.socket = tls.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def stop_http(server):
    server.shutdown()
    server.server_close()


def eventual(condition, label, timeout=32):
    until = time.monotonic() + timeout
    last = None
    while time.monotonic() < until:
        try:
            if result := condition():
                return result
        except (OSError, subprocess.CalledProcessError, http.client.HTTPException) as error:
            last = error
        time.sleep(.25)
    raise AssertionError(f"{label} timed out ({type(last).__name__})") from last


def request(port, method, path, data=None, token=None, expected=200, headers=None):
    headers = (headers or {}).copy()
    if token:
        headers["Authorization"] = "Bearer " + token
    if data is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(data)
    with contextlib.closing(http.client.HTTPConnection("127.0.0.1", port, timeout=25)) as connection:
        connection.request(method, path, body=data, headers=headers)
        response = connection.getresponse()
        body = response.read()
        assert response.status == expected, (path, response.status, body[:160])
        return (json.loads(body) if body else None), response.getheader("ETag")


def proxied(proxy, target):
    with contextlib.closing(http.client.HTTPConnection("127.0.0.1", proxy, timeout=4)) as connection:
        connection.request("GET", f"http://localhost:{target}/route")
        response = connection.getresponse()
        return response.status == 200 and response.read() == b"homeproxy-origin"


def blocked(proxy, target):
    try:
        return not proxied(proxy, target)
    except (OSError, http.client.HTTPException):
        return True


def curl_through(proxy, target):
    curl = Path(os.environ["SystemRoot"]) / "System32" / "curl.exe"
    result = subprocess.run(
        [curl, "--fail", "--silent", "--noproxy", "", "--max-time", "4", "--proxy",
         "http://" + address(proxy), f"http://localhost:{target}/route"],
        capture_output=True, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    return result.returncode == 0 and result.stdout == b"homeproxy-origin"


def test(args, root):
    if args.tun_vm and (os.name != "nt" or not ctypes.windll.shell32.IsUserAnAdmin()):
        raise RuntimeError("TUN QA requires an elevated process in the dedicated Windows VM")
    for attr in ("server", "agent"):
        original = getattr(args, attr)
        copy = root / original.name
        shutil.copy2(original, copy)
        setattr(args, attr, copy)
    with contextlib.ExitStack() as stack:
        curl = Path(os.environ["SystemRoot"]) / "System32" / "curl.exe"
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        if args.strict_vm:
            host = "www.msftconnecttest.com"
            endpoint = socket.getaddrinfo(host, 80, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
            dns_question = bytes.fromhex("123401000001000000000000") + b"\x03www\x0fmsftconnecttest\x03com\x00\x00\x01\x00\x01"

            def direct_dns():
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                    client.settimeout(2)
                    try:
                        client.connect((args.strict_dns, 53))
                        client.send(dns_question)
                        response = client.recv(512)
                        return len(response) >= 12 and response[:2] == dns_question[:2] and bool(response[2] & 128)
                    except OSError:
                        return False

            def outside_tunnel():
                try:
                    with socket.create_connection((endpoint, 80), timeout=2):
                        return True
                except OSError:
                    return False

            assert outside_tunnel(), "Direct Internet probe must work before arming STRICT"
            assert direct_dns(), "Direct UDP DNS probe must work before arming STRICT"

            def reset_firewall():
                subprocess.run([args.agent, "firewall-reset"], check=True, creationflags=flags)

            stack.callback(reset_firewall)

        def remember(process):
            def cleanup():
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=6)
            stack.callback(cleanup)
            return process

        origin = launch_http(Origin)
        stack.callback(stop_http, origin)
        probe = launch_http(Origin)
        stack.callback(stop_http, probe)
        hosts = ("localhost", "127.0.0.1", "app.homeproxy.test", "asset.homeproxy.test")
        tun_hosts = ("192.0.2.43", "[2001:db8::43]", "windows-tun.homeproxy.test")
        if args.tun_vm:
            hosts += tun_hosts
        targets = {f"{host}:{server.server_port}" for host in hosts for server in (origin, probe)}
        proxy_password = secrets.token_urlsafe(20)
        auth = "Basic " + base64.b64encode(f"test-user:{proxy_password}".encode()).decode()
        provider = launch_http(Connect, auth=auth, targets=targets, connects=[])
        stack.callback(stop_http, provider)
        secondary = launch_http(Connect, auth=auth, targets=targets, connects=[])
        stack.callback(stop_http, secondary)

        cert, key = root / "test.crt", root / "test.key"
        subprocess.run([args.openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-subj", "/CN=localhost", "-keyout", key, "-out", cert],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(cert, key)
        camouflage = launch_http(Origin, tls=tls)
        stack.callback(stop_http, camouflage)

        api, tunnel, control = (new_port() for _ in range(3))
        named_host = "127-0-0-1.sslip.io" if args.strict_named_api else None
        if named_host:
            ca_cert, ca_key, ca_der = (root / name for name in ("api-ca.crt", "api-ca.key", "api-ca.cer"))
            api_cert, api_key, api_request, extensions = (root / name for name in ("api.crt", "api.key", "api.csr", "api.ext"))
            subprocess.run([args.openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                            "-subj", "/CN=HomeProxy STRICT QA", "-keyout", ca_key, "-out", ca_cert], capture_output=True, check=True)
            subprocess.run([args.openssl, "req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", f"/CN={named_host}",
                            "-keyout", api_key, "-out", api_request], capture_output=True, check=True)
            extensions.write_text(f"subjectAltName=DNS:{named_host}\nbasicConstraints=critical,CA:FALSE\nextendedKeyUsage=serverAuth\n", encoding="ascii")
            subprocess.run([args.openssl, "x509", "-req", "-in", api_request, "-CA", ca_cert, "-CAkey", ca_key,
                            "-CAcreateserial", "-extfile", extensions, "-days", "1", "-out", api_cert], capture_output=True, check=True)
            subprocess.run([args.openssl, "x509", "-in", ca_cert, "-outform", "DER", "-out", ca_der], check=True)
            certutil = Path(os.environ["SystemRoot"]) / "System32" / "certutil.exe"
            thumbprint = hashlib.sha1(ca_der.read_bytes(), usedforsecurity=False).hexdigest()
            subprocess.run([certutil, "-addstore", "Root", ca_der], capture_output=True, check=True)
            stack.callback(subprocess.run, [certutil, "-delstore", "Root", thumbprint], capture_output=True, check=True)
            api_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            api_tls.load_cert_chain(api_cert, api_key)
            named_api = launch_http(NamedApiProxy, tls=api_tls, api_port=api,
                                    named_host=named_host, named_proxy_port=provider.server_port)
            stack.callback(stop_http, named_api)
        local = proxy_ports()
        if args.browser_qa:
            local = 17770
            if control in (17770, 17772, 17773, 17774):
                control = new_port()
        admin = secrets.token_urlsafe(32)
        env = {**os.environ, "HOMEPROXY_ADMIN_TOKEN": admin}
        config = root / "server.json"
        settings = {
            "listen": address(api), "publicUrl": "http://" + address(api), "database": "store.sqlite",
            "keyFile": "vault.key", "realityKeyFile": "reality.key", "singBox": str(args.sing_box),
            "tunnelListen": address(tunnel), "tunnelHost": "127.0.0.1", "tunnelPort": tunnel,
            "serverName": "localhost", "handshakeHost": "127.0.0.1", "handshakePort": camouflage.server_port,
            "probeUrl": f"http://127.0.0.1:{probe.server_port}/probe", "loopbackDev": True,
        }
        if args.admin_dir:
            settings["adminDir"] = str(args.admin_dir)
        if args.browser_qa:
            settings["manageAutomaticUpdates"] = True
        config.write_text(json.dumps(settings), encoding="utf-8")
        log = stack.enter_context((root / "server.log").open("w", encoding="utf-8"))
        agent_log = stack.enter_context((root / "agent.log").open("w", encoding="utf-8"))

        def start_server():
            process = remember(subprocess.Popen([args.server, "-config", config], env=env, stdout=log, stderr=log,
                                                creationflags=flags))
            try:
                eventual(lambda: request(api, "GET", "/healthz")[0]["ready"], "server health", 10)
            except Exception:
                print((root / "server.log").read_text(encoding="utf-8"))
                raise
            return process

        def start_agent():
            tun_flags = ["--tun-strict"] if args.strict_vm else ["--tun"] if args.tun_vm else []
            return remember(subprocess.Popen(
                [args.agent, "serve", "--data", root / "agent", "--sing-box", args.sing_box, "--port", str(control),
                 "--proxy-port", str(local), "--probe-seconds", "6" if args.strict_vm else "2",
                 "--allow-loopback-http", *tun_flags],
                stdout=agent_log, stderr=agent_log, creationflags=flags))

        def terminate(process):
            process.kill()
            process.wait(timeout=6)

        def ctl(command, data=None):
            run = subprocess.run([args.agent, "ctl", "--data", root / "agent", "--port", str(control),
                                  "--command", command, "--json", json.dumps(data)], capture_output=True,
                                 timeout=48, creationflags=flags)
            if run.returncode:
                raise subprocess.CalledProcessError(run.returncode, command, stderr=run.stderr)
            return json.loads(run.stdout)

        def change(method, endpoint, data=None, expected=200):
            return request(api, method, "/api/v1/admin/" + endpoint, data, admin, expected)[0]

        server = start_server()
        agent = start_agent()

        def agent_status():
            if (exit_code := agent.poll()) is not None:
                raise RuntimeError(f"Agent exited during startup (0x{exit_code & 0xFFFFFFFF:08X})")
            return ctl("status")

        try:
            eventual(agent_status, "agent ready", 10)
        except Exception as error:
            details = (root / "agent.log").read_text(encoding="utf-8", errors="replace").strip()
            if isinstance(error.__cause__, subprocess.CalledProcessError):
                stderr = error.__cause__.stderr.decode("utf-8", errors="replace").strip()
                if stderr:
                    print(f"Agent status: {stderr[-1200:]}", flush=True)
            if details:
                print(f"Agent startup log: {details[-1200:]}", flush=True)
            raise
        request(api, "GET", "/api/v1/admin/state", expected=401)
        if args.strict_vm:
            assert ctl("status")["strict"] and not outside_tunnel() and not direct_dns(), "STRICT leaked before connecting"
        if named_host:
            # The disposable local CA has no revocation endpoint.
            tls_check = subprocess.run([curl, "--fail", "--silent", "--show-error", "--ssl-no-revoke", "--max-time", "5", "--noproxy", "*",
                                        "--resolve", f"{named_host}:{named_api.server_port}:127.0.0.1",
                                        f"https://{named_host}:{named_api.server_port}/healthz"], capture_output=True)
            assert tls_check.returncode == 0, tls_check.stderr.decode(errors="replace")
        user = change("POST", "users", {"name": "Windows QA"}, 201)["id"]
        change("PUT", "proxies", {"name": "Rejected", "host": "127.0.0.1", "port": provider.server_port,
                                 "username": "wrong", "password": "wrong"}, 422)
        proxy = change("PUT", "proxies", {"name": "QA CONNECT", "host": "127.0.0.1", "port": provider.server_port,
                                        "username": "test-user", "password": proxy_password})["id"]
        backup_proxy = change("PUT", "proxies", {"name": "Резервный HTTP CONNECT для изолированной проверки", "host": "127.0.0.1",
                                                "port": secondary.server_port, "username": "test-user", "password": proxy_password})["id"]
        change("PUT", "routes", {"userId": user, "proxyIds": [proxy, backup_proxy]}, 204)
        if args.serve:
            print(f"HomeProxy Admin  http://{address(api)}", flush=True)
            print(f"Test admin key   {admin}", flush=True)
            print(f"Test proxy       {address(local)} (after onboarding)", flush=True)
            print(f"Agent data       {root / 'agent'}", flush=True)
            print(f"Agent API        {address(control)}", flush=True)
            try:
                input("Enter stops the isolated session. ")
            except (EOFError, KeyboardInterrupt):
                pass
            return
        other = change("POST", "users", {"name": "Без назначенных прокси"}, 201)["id"]
        other_invite = change("POST", "invites", {"userId": other, "label": "Other agent", "transport": "agent"}, 201)
        other_key = secrets.token_urlsafe(32)
        request(api, "POST", "/api/v1/connect", {"token": other_invite["link"].split("#")[1], "deviceKey": other_key,
                                                "transport": "agent"}, expected=201)
        assert request(api, "GET", "/api/v1/config", token=other_key)[0]["proxies"] == []
        request(api, "GET", "/api/v1/admin/state", token=other_key, expected=401)
        def reported(label):
            return next(row for row in change("GET", "state")["devices"] if row["label"] == label)

        assert reported("Other agent")["installedVersion"] == ""
        _, android_tag = request(api, "GET", "/api/v1/config?platform=android", token=other_key,
                                 headers={"X-HomeProxy-Version": "1.2.3"})
        request(api, "GET", "/api/v1/config?platform=android", token=other_key, expected=304,
                headers={"If-None-Match": android_tag, "X-HomeProxy-Version": "1.2.4"})
        eventual(lambda: reported("Other agent")["installedVersion"] == "1.2.4", "Android version report on 304")
        assert reported("Other agent")["platform"] == "android"
        browser_link = change("POST", "invites", {"userId": user, "label": "Browser QA", "transport": "browser"}, 201)
        browser_key = secrets.token_urlsafe(32)
        pair = {"token": browser_link["link"].split("#")[1], "deviceKey": browser_key, "transport": "browser"}
        request(api, "POST", "/api/v1/connect", pair, expected=201)
        request(api, "POST", "/api/v1/connect", pair, expected=401)
        browser, etag = request(api, "GET", "/api/v1/config", token=browser_key)
        assert "proxies" not in browser and "home" not in browser
        request(api, "GET", "/api/v1/config", token=browser_key, expected=304, headers={"If-None-Match": etag})

        invite = change("POST", "invites", {"userId": user, "label": "Agent QA", "transport": "agent"}, 201)
        link = invite["link"]
        if named_host:
            link = urllib.parse.urlsplit(link)._replace(scheme="https", netloc=f"{named_host}:{named_api.server_port}").geturl()
        status = ctl("connect", {"link": link})
        assert status["linked"] and status["revision"], status
        eventual(lambda: ctl("status")["route"]["selected"] == "home", "REALITY primary")
        assert proxied(local, origin.server_port)
        eventual(lambda: reported("Agent QA")["installedVersion"], "Windows installed version report")
        assert reported("Agent QA")["platform"] == "windows"
        print("PASS registration, scoped configuration, REALITY and authenticated CONNECT", flush=True)
        if named_host:
            status = ctl("sync")
            assert status["online"] and not status["error"], status
            print("PASS STRICT cold connection and resync with a named TLS API while plain DNS is blocked", flush=True)

        def through_tun(host):
            response = subprocess.run(
                [curl, "--fail", "--silent", "--noproxy", "*", "--max-time", "5",
                 f"http://{host}:{origin.server_port}/route"],
                capture_output=True, creationflags=flags,
            )
            return response.returncode == 0 and response.stdout == b"homeproxy-origin"

        if args.tun_vm:
            for host in tun_hosts:
                before = len(provider.connects)
                eventual(lambda: through_tun(host), f"Windows transparent route for {host}")
                assert f"{host}:{origin.server_port}" in provider.connects[before:]
            print("PASS Windows TUN IPv4, IPv6 and DNS with transparent HTTP", flush=True)
        apps = ctl("list-apps")
        assert any(Path(app["path"]) == Path(sys.executable) for app in apps)
        curl_path = str(Path(os.environ["SystemRoot"]) / "System32" / "curl.exe")
        assert curl_through(local, origin.server_port)
        process_rule = {"kind": "process", "pattern": curl_path.swapcase().replace("\\", "/"), "action": "BLOCK"}
        try:
            ctl("local-rule", process_rule)
        except subprocess.CalledProcessError as error:
            print(f"Controller error: {error.stderr.decode('utf-8', errors='replace').strip()[-800:]}", flush=True)
            print(f"Core log: {(root / 'agent.log').read_text(encoding='utf-8', errors='replace').strip()[-1500:]}",
                  flush=True)
            raise
        assert not curl_through(local, origin.server_port)
        if args.tun_vm:
            assert not through_tun(tun_hosts[0])
        assert proxied(local, origin.server_port)
        ctl("local-rule", {**process_rule, "action": "INHERIT"})
        global_process = change("PUT", "rules", {**process_rule, "pattern": "CURL.EXE"})
        synced = ctl("sync")
        assert not synced["error"], f"Global EXE rule sync failed: {synced['error']}"
        assert any(rule["id"] == global_process["id"] for rule in synced["remoteRules"]), (
            f"Global EXE rule missing in applied revision {synced['revision']}"
        )
        assert not curl_through(local, origin.server_port)
        assert proxied(local, origin.server_port)
        assert all(r["kind"] != "process" for r in request(api, "GET", "/api/v1/config", token=browser_key)[0]["rules"])
        ctl("personal-rule", {**process_rule, "action": "LOCAL_DIRECT"})
        eventual(lambda: ctl("explain", {"exe": curl_path})["scope"] == "PERSONAL", "personal process rule")
        assert curl_through(local, origin.server_port)
        change("DELETE", "rules/" + global_process["id"], expected=204)
        personal = next(r for r in change("GET", "state")["rules"] if r["kind"] == "process")
        change("DELETE", "rules/" + personal["id"], expected=204)
        ctl("sync")
        print("PASS Windows process enumeration and EXE routing across LOCAL/PERSONAL/GLOBAL", flush=True)
        if args.browser_qa:
            history = root / ".homeproxy-update-history"
            history.mkdir()
            records = (
                {"outcome": "installed", "phase": "apply", "version": "1.2.3"},
                {"outcome": "failed", "phase": "recovery", "exitCode": 7},
                {"outcome": "no-update", "phase": "apply"},
                {"outcome": "paused", "phase": "policy"},
            )
            for index, record in enumerate(records, 1):
                (history / f"{index:021d}-{index:032x}.json").write_text(
                    json.dumps({"startedAt": 1720000000, "finishedAt": 1720000010, **record}), encoding="utf-8"
                )
            (history / f"{5:021d}-{5:032x}.json").write_text('{"outcome":"unknown"}', encoding="utf-8")
            request(api, "GET", "/api/v1/admin/update-history", expected=401)
            entries, _ = request(api, "GET", "/api/v1/admin/update-history", token=admin)
            assert [entry["outcome"] for entry in entries] == ["paused", "no-update", "failed", "installed"], entries
            request(api, "PUT", "/api/v1/admin/update-policy", {"paused": True}, expected=401)
            change("PUT", "update-policy", {"paused": None}, 400)
            link = change("POST", "invites", {"userId": user, "label": "Chromium QA", "transport": "browser"}, 201)["link"]
            browser_env = {
                **env, "HOMEPROXY_QA_API": f"http://{address(api)}", "HOMEPROXY_QA_INVITE": link,
                "HOMEPROXY_QA_ORIGIN_PORT": str(origin.server_port), "HOMEPROXY_QA_AGENT": str(args.agent),
                "HOMEPROXY_QA_STATE": str(root / "agent"), "HOMEPROXY_QA_CTL": str(control),
            }
            browser_run = subprocess.run(["node", args.browser_qa], env=browser_env, timeout=100, capture_output=True,
                                         encoding="utf-8", creationflags=flags)
            print(browser_run.stdout, end="", flush=True)
            if browser_run.returncode:
                print(browser_run.stderr, flush=True)
                browser_run.check_returncode()
            assert not (root / "store.sqlite.updates-paused").exists()

        terminate(server)
        eventual(lambda: ctl("status")["route"]["selected"] == "backup-0", "offline backup")
        assert proxied(local, origin.server_port)
        if named_host:
            print("PASS STRICT failover through a named HTTP proxy", flush=True)
        ctl("profile", {"profile": "HOME_SERVER"})
        assert blocked(local, origin.server_port)
        ctl("profile", {"profile": "DIRECT_INTERNET"})
        origin_requests = sum(destination.endswith(f":{origin.server_port}") for destination in provider.connects)
        assert proxied(local, origin.server_port)
        assert origin_requests == sum(destination.endswith(f":{origin.server_port}") for destination in provider.connects)
        ctl("profile", {"profile": "AUTO"})
        if args.strict_vm:
            powershell = Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
            result = subprocess.run(
                [powershell, "-NoProfile", "-Command",
                 f"(Get-CimInstance Win32_Process -Filter \"ParentProcessId={agent.pid} AND Name='sing-box.exe'\").ProcessId"],
                check=True, capture_output=True, creationflags=flags,
            )
            children = result.stdout.split()
            assert len(children) == 1 and children[0].isdigit(), f"Expected one test core PID, got {children}"
            subprocess.run(["taskkill.exe", "/PID", children[0].decode(), "/F"], check=True,
                           capture_output=True, creationflags=flags)
            assert not outside_tunnel(), "STRICT leaked after killing the core"
            assert not direct_dns(), "STRICT leaked UDP DNS after killing the core"
            print("PASS STRICT blocked direct IPv4 and UDP DNS after core termination", flush=True)
        terminate(agent)
        if args.strict_vm:
            assert not outside_tunnel(), "STRICT leaked after killing the controller"
            assert not direct_dns(), "STRICT leaked UDP DNS after killing the controller"
            print("PASS STRICT blocked direct IPv4 and UDP DNS after controller termination", flush=True)
        agent = start_agent()
        eventual(lambda: ctl("status")["route"]["selected"] == "backup-0", "cache after offline restart")
        assert proxied(local, origin.server_port)
        ctl("local-rule", {"pattern": "localhost", "kind": "domain", "action": "BLOCK"})
        assert blocked(local, origin.server_port)
        ctl("local-rule", {"pattern": "localhost", "kind": "domain", "action": "INHERIT"})
        assert proxied(local, origin.server_port)
        print("PASS offline failover, protected cache restart and LOCAL rules", flush=True)

        server = start_server()
        eventual(lambda: ctl("status")["route"]["selected"] == "home", "primary recovery")
        rule = {"pattern": "localhost", "kind": "domain", "action": "BLOCK"}
        change("PUT", "rules", rule)
        ctl("sync")
        assert blocked(local, origin.server_port)
        ctl("personal-rule", {**rule, "action": "SERVER_DIRECT"})
        eventual(lambda: ctl("explain", {"host": "localhost"})["scope"] == "PERSONAL", "personal sync")
        assert proxied(local, origin.server_port)
        global_rule = next(
            r for r in change("GET", "state")["rules"]
            if "userId" not in r and r["kind"] == rule["kind"] and r["pattern"] == rule["pattern"]
        )
        change("PUT", "rules", {**rule, "locked": True, "revision": global_rule["revision"]})
        change("PUT", "rules", {**rule, "locked": True, "revision": global_rule["revision"]}, 409)
        ctl("sync")
        ctl("local-rule", {**rule, "action": "LOCAL_DIRECT"})
        assert blocked(local, origin.server_port)
        for policy in change("GET", "state")["rules"]:
            change("DELETE", "rules/" + policy["id"], expected=204)
        ctl("local-rule", {**rule, "action": "INHERIT"})
        ctl("sync")
        backup = root / "backups" / change("POST", "backups", expected=201)["file"]
        assert backup.is_file()
        database = (root / "store.sqlite").read_bytes()
        assert proxy_password.encode() not in database
        assert proxy_password.encode() not in (root / "agent" / "state.dpapi").read_bytes()
        print("PASS recovery, GLOBAL/PERSONAL/locked rules, conflict, acknowledgements and backup", flush=True)

        terminate(server)
        stop_http(provider)
        eventual(lambda: ctl("status")["route"]["selected"] == "backup-1", "second backup")
        assert proxied(local, origin.server_port)
        if args.tun_vm:
            assert through_tun(tun_hosts[0])
        stop_http(secondary)
        eventual(lambda: ctl("status")["route"]["selected"] is None, "all unavailable")
        assert blocked(local, origin.server_port)
        if args.tun_vm:
            assert not through_tun(tun_hosts[0])
        server = start_server()
        change("DELETE", "devices/" + invite["id"], expected=204)
        rev_before = change("GET", "state")["revision"]
        status = ctl("sync")
        assert not status["linked"] and blocked(local, origin.server_port)
        restore = [args.server, "-config", config, "-restore", backup]
        assert subprocess.run(restore, env=env, capture_output=True, creationflags=flags).returncode != 0
        terminate(server)
        subprocess.run(restore, env=env, check=True, creationflags=flags)
        server = start_server()
        restored = change("GET", "state")
        assert restored["revision"] > rev_before
        assert next(d for d in restored["devices"] if d["id"] == invite["id"])["status"] == "revoked"
        print("PASS fail-closed with no healthy proxy, revocation and SQLite restore", flush=True)
        ctl("shutdown")
        assert agent.wait(timeout=10) == 0
        print("PASS authenticated Windows controller shutdown for a coordinated update", flush=True)
    if args.strict_vm:
        eventual(direct_dns, "direct DNS after removing STRICT", 15)
        eventual(outside_tunnel, "direct Internet after removing STRICT", 20)
        print("PASS explicit STRICT reset restored direct Internet", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    for arg in ("server", "agent", "sing-box"):
        parser.add_argument("--" + arg, type=lambda p: Path(p).resolve(), required=True)
    parser.add_argument("--openssl", default=shutil.which("openssl") or r"C:\Program Files\Git\usr\bin\openssl.exe")
    parser.add_argument("--admin-dir", type=lambda p: Path(p).resolve())
    parser.add_argument("--browser-qa", type=lambda p: Path(p).resolve())
    parser.add_argument("--serve", action="store_true")
    parser.add_argument("--tun-vm", action="store_true", help="Enable TUN and dynamic WFP filters in an isolated Windows VM")
    parser.add_argument("--strict-vm", action="store_true", help="Check persistent WFP protection in an isolated Windows VM")
    parser.add_argument("--strict-dns", help="Guest IPv4 DNS server for the strict-mode UDP leak check")
    parser.add_argument("--strict-named-api", action="store_true", help="Check a named TLS API and proxy in the STRICT VM")
    args = parser.parse_args()
    if args.strict_vm and not args.tun_vm:
        parser.error("--strict-vm requires --tun-vm")
    if args.strict_vm and not args.strict_dns:
        parser.error("--strict-vm requires --strict-dns")
    if args.strict_named_api and not args.strict_vm:
        parser.error("--strict-named-api requires --strict-vm")
    with tempfile.TemporaryDirectory(prefix="HomeProxyIntegration-") as temp:
        root = Path(temp)
        try:
            test(args, root)
        except Exception as error:
            if isinstance(error, subprocess.CalledProcessError) and error.stderr:
                stderr = error.stderr
                if isinstance(stderr, bytes):
                    stderr = stderr.decode("utf-8", errors="replace")
                print(f"Command error: {stderr.strip()[-1200:]}", flush=True)
            agent_log = root / "agent.log"
            if args.tun_vm and agent_log.is_file():
                details = agent_log.read_text(encoding="utf-8", errors="replace").strip()
                if details:
                    faults = [line for line in details.splitlines() if line.startswith(("FATAL", "ERROR"))]
                    if faults:
                        print("Core errors:\n" + "\n".join(faults[-6:])[-1400:], flush=True)
                    print(f"Agent and core log tail:\n{details[-1200:]}", flush=True)
            raise
