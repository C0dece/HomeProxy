package app.homeproxy.agent

import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.os.SystemClock
import android.util.Base64
import okhttp3.Credentials
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.ServerSocket
import java.net.URI
import java.security.SecureRandom
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

internal class MobileFailure(message: String) : Exception(message)

private data class Reply(val code: Int, val body: String, val etag: String?)

internal object NativePlan {
    init { System.loadLibrary("homeproxy_desktop_lib") }
    @JvmStatic external fun render(payload: String): String
}

internal object MobileRuntime {
    val worker = Executors.newSingleThreadScheduledExecutor()
    private val http = OkHttpClient.Builder().proxy(Proxy.NO_PROXY)
        .callTimeout(5, TimeUnit.SECONDS).followRedirects(false).followSslRedirects(false).build()
    private val jsonType = "application/json; charset=utf-8".toMediaType()
    private val tokenFormat = Regex("[A-Za-z0-9_-]{43}")
    private val packageName = Regex("[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+")
    private val profiles = setOf("AUTO", "HOME_SERVER", "DIRECT_HTTP", "DIRECT_INTERNET", "CUSTOM")
    private val actions = setOf("PROXY", "LOCAL_DIRECT", "SERVER_DIRECT", "BLOCK", "AUTO", "INHERIT")
    private var online = false
    private var message: String? = null
    private var nextSync = 0L
    private var syncInterval = 12_000L
    private var state: JSONObject? = null
    private var engine: HomeProxyVpnService? = null

    private fun state(context: Context): JSONObject =
        state ?: HomeStore(context).read().also { state = it }

    private fun persist(context: Context, next: JSONObject) {
        HomeStore(context).save(next)
        state = next
    }

    private fun exclusions(current: JSONObject): JSONArray = current.optJSONArray("excludedApps") ?: JSONArray()

    private fun exclusionsAllowed(current: JSONObject): Boolean {
        val rules = current.optJSONObject("remote")?.optJSONArray("rules") ?: return false
        return (0 until rules.length()).none { rules.getJSONObject(it).optBoolean("locked") }
    }

    private fun localSettings(current: JSONObject): JSONObject = JSONObject()
        .put("local", current.optJSONArray("local") ?: JSONArray())
        .put("localGroups", current.optJSONArray("localGroups") ?: JSONArray())
        .put("excludedApps", exclusions(current))
        .put("autoStart", current.optBoolean("autoStart", false))
        .apply {
            if (current.has("customProxy")) put("customProxy", current.getJSONObject("customProxy"))
            if (current.has("configMode")) put("configMode", current.getString("configMode"))
            if (current.has("autoBaseRoute")) put("autoBaseRoute", current.getString("autoBaseRoute"))
        }

    fun isReady(current: JSONObject): Boolean {
        val mode = current.optString("configMode", "subscription")
        return if (mode == "custom") current.optJSONObject("customProxy") != null
        else current.optJSONObject("remote") != null
    }

    fun requireLinked(context: Context) {
        if (state(context).optJSONObject("remote") == null) throw MobileFailure("Сначала подключите устройство")
    }

    fun requireReady(context: Context) {
        if (!isReady(state(context))) throw MobileFailure("Сначала настройте подключение")
    }

    fun debug(context: Context) = context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0

    fun randomToken(): String = ByteArray(32).also { SecureRandom().nextBytes(it) }.let {
        Base64.encodeToString(it, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
    }

    fun port(): Int = ServerSocket(0, 1, InetAddress.getByName("127.0.0.1")).use { it.localPort }

    fun hasRemote(context: Context): Boolean = try {
        isReady(state(context))
    } catch (_: Exception) { false }

    fun isVpnRunning(): Boolean = engine?.connected == true

    fun isAlwaysOnVpn(): Boolean = engine?.isAlwaysOn == true

    fun currentProfile(context: Context): String = try {
        state(context).optString("profile", "AUTO")
    } catch (_: Exception) { "AUTO" }

    fun currentModeLabel(context: Context): String = when (currentProfile(context)) {
        "DIRECT_INTERNET" -> "Авто"
        "AUTO" -> "Весь трафик"
        else -> "Свой профиль"
    }

    fun status(context: Context): JSONObject {
        val current = state(context)
        val remote = current.optJSONObject("remote")
        val profile = current.optString("profile", "AUTO")
        val custom = current.optString("custom", "PROXY")
        val enabled = engine?.connected == true
        val savedMode = current.optString("routingMode", "")
        val routingMode = when {
            !enabled -> "off"
            savedMode == "auto" || savedMode == "all" -> savedMode
            profile == "DIRECT_INTERNET" || (profile == "CUSTOM" && custom == "LOCAL_DIRECT") -> "auto"
            else -> "all"
        }
        val configMode = if (current.optString("configMode", "subscription") == "custom") "custom" else "subscription"
        val customProxyRaw = current.optJSONObject("customProxy")
        val customProxySafe = customProxyRaw?.let { cp ->
            JSONObject()
                .put("protocol", cp.optString("protocol", "HTTP"))
                .put("host", cp.optString("host", ""))
                .put("port", cp.optInt("port", 8080))
                .put("username", cp.optString("username", ""))
                .put("hasPassword", cp.optString("password", "").isNotEmpty())
                .put("tls", cp.optBoolean("tls", false))
                .put("serverName", cp.optString("serverName", ""))
        } ?: JSONObject.NULL
        return JSONObject()
            .put("platform", "android")
            .put("linked", current.has("key"))
            .put("online", online)
            .put("enabled", enabled)
            .put("autoStart", current.optBoolean("autoStart", false))
            .put("alwaysOn", engine?.isAlwaysOn ?: JSONObject.NULL)
            .put("lockdown", engine?.isLockdownEnabled ?: JSONObject.NULL)
            .put("excludedApps", exclusions(current))
            .put("exclusionsAllowed", exclusionsAllowed(current))
            .put("configMode", configMode)
            .put("customProxy", customProxySafe)
            .put("canEditGlobal", remote?.optBoolean("canEditGlobal", false) ?: false)
            .put("routingMode", routingMode)
            .put("autoBaseRoute", if (current.optString("autoBaseRoute", "direct") == "proxy") "proxy" else "direct")
            .put("profile", profile)
            .put("custom", custom)
            .put("revision", remote?.optLong("revision") ?: JSONObject.NULL)
            .put("ack", current.optLong("ack"))
            .put("proxyPort", 0)
            .put("error", message ?: JSONObject.NULL)
            .put("rules", current.optJSONArray("local") ?: JSONArray())
            .put("localGroups", current.optJSONArray("localGroups") ?: JSONArray())
            .put("remoteRules", remote?.optJSONArray("rules") ?: JSONArray())
            .put("remoteGroups", remote?.optJSONArray("groups") ?: JSONArray())
            .put("pending", JSONArray())
            .put("route", engine?.routeStatus() ?: JSONObject()
                .put("selected", JSONObject.NULL).put("fallback", false)
                .put("serverDirectAvailable", false).put("candidates", JSONArray()))
    }

    fun command(context: Context, command: String, args: JSONObject): JSONObject {
        val current = state(context)
        when (command) {
            "status" -> {}
            "connect" -> connect(context, args.getString("link"), current)
            "enable" -> {
                requireManualVpn()
                stop(context)
            }
            "disconnect" -> {
                requireManualVpn()
                stop(context)
                persist(context, localSettings(current))
                online = false
                message = null
            }
            "sync" -> sync(context)
            "probe" -> engine?.probe()
            "vpn-exclusion" -> {
                requireLinked(context)
                val name = args.getString("package").trim()
                val excluded = args.getBoolean("excluded")
                if (!packageName.matches(name) || name.length > 255) throw MobileFailure("Недопустимое имя пакета")
                val previous = exclusions(current)
                val saved = (0 until previous.length()).map(previous::getString)
                if (excluded && name !in saved) {
                    if (!exclusionsAllowed(current)) throw MobileFailure("Обязательные правила запрещают исключения")
                    if (!AndroidApps.canExclude(context, name)) throw MobileFailure("Нужен установленный пакет с отдельным UID")
                }
                val next = if (excluded) (saved + name).distinct() else saved.filterNot { it == name }
                if (next != saved) apply(context, JSONObject(current.toString()).put("excludedApps", JSONArray(next)))
            }
            "profile" -> {
                requireReady(context)
                val profile = args.getString("profile")
                val custom = if (profile == "CUSTOM") args.getString("action") else current.optString("custom", "PROXY")
                if (profile !in profiles || custom !in actions || custom == "AUTO" || custom == "INHERIT")
                    throw MobileFailure("Проверьте профиль подключения")
                apply(context, JSONObject(current.toString()).put("profile", profile).put("custom", custom))
            }
            "set-config-mode" -> {
                val mode = args.optString("mode")
                if (mode != "subscription" && mode != "custom") throw MobileFailure("Неверный источник подключения")
                val next = JSONObject(current.toString()).put("configMode", mode)
                if (isReady(next)) apply(context, next) else persist(context, next)
            }
            "save-custom-proxy" -> {
                val proto = args.optString("protocol", "HTTP").trim().uppercase()
                if (proto !in setOf("HTTP", "SOCKS5", "VLESS")) throw MobileFailure("Неверный протокол прокси")
                val host = args.optString("host", "").trim()
                val port = args.optInt("port", 0)
                if (host.isEmpty() || port !in 1..65535) throw MobileFailure("Укажите адрес и порт прокси")
                val username = args.optString("username", "").trim()
                val keepPassword = args.optBoolean("keepPassword", false)
                val prevPass = current.optJSONObject("customProxy")?.optString("password", "") ?: ""
                val inputPass = args.optString("password", "")
                val password = if (inputPass.isNotEmpty() || !keepPassword) inputPass else prevPass
                if (proto == "VLESS" && username.isEmpty()) throw MobileFailure("Для VLESS укажите UUID в поле логина")
                if (proto != "VLESS" && password.isNotEmpty() && username.isEmpty()) throw MobileFailure("Укажите логин для пароля прокси")
                val cp = JSONObject()
                    .put("protocol", proto)
                    .put("host", host)
                    .put("port", port)
                    .put("username", username)
                    .put("password", password)
                    .put("tls", args.optBoolean("tls", proto == "VLESS"))
                    .put("serverName", args.optString("serverName", "").trim())
                val next = JSONObject(current.toString()).put("customProxy", cp).put("configMode", "custom")
                apply(context, next)
            }
            "select-proxy" -> {
                val tag = args.optString("tag").trim()
                if (tag.isEmpty()) throw MobileFailure("Укажите выходной узел")
                engine?.selectCandidate(tag) ?: throw MobileFailure("VPN не запущен")
            }
            "save-local-group" -> {
                val name = args.optString("name", "").trim()
                val action = args.optString("action", "PROXY")
                if (name.isEmpty() || name.length > 100 || action !in actions) throw MobileFailure("Проверьте название и маршрут ресурса")
                val groupId = args.optString("id", "").trim().ifEmpty { randomToken() }
                val group = JSONObject(args.toString()).put("id", groupId).put("name", name).put("locked", false)
                val old = current.optJSONArray("localGroups") ?: JSONArray()
                val next = JSONArray()
                next.put(group)
                for (i in 0 until old.length()) {
                    val item = old.getJSONObject(i)
                    if (item.optString("id") != groupId && !item.optString("name").equals(name, ignoreCase = true)) {
                        next.put(item)
                    }
                }
                val updated = JSONObject(current.toString()).put("localGroups", next)
                if (isReady(updated)) apply(context, updated) else persist(context, updated)
            }
            "delete-local-group" -> {
                val id = args.optString("id", "").trim()
                val old = current.optJSONArray("localGroups") ?: JSONArray()
                val next = JSONArray()
                for (i in 0 until old.length()) {
                    val item = old.getJSONObject(i)
                    if (item.optString("id") != id) next.put(item)
                }
                val updated = JSONObject(current.toString()).put("localGroups", next)
                if (isReady(updated)) apply(context, updated) else persist(context, updated)
            }
            "save-shared-group" -> {
                requireLinked(context)
                val result = request(current, "/shared-groups", "PUT", args)
                if (result.code == 403) throw MobileFailure("Нет прав на изменение общих ресурсов")
                if (result.code == 409) throw MobileFailure("Конфликт версии ресурса. Обновите настройки")
                if (result.code !in 200..299) throw MobileFailure("Сервер отклонил сохранение общего ресурса")
                sync(context)
            }
            "delete-shared-group" -> {
                requireLinked(context)
                val id = args.getString("id").trim()
                val result = request(current, "/shared-groups/$id", "DELETE")
                if (result.code == 403) throw MobileFailure("Нет прав на изменение общих ресурсов")
                if (result.code !in 200..299 && result.code != 404) throw MobileFailure("Сервер отклонил удаление общего ресурса")
                sync(context)
            }
            "local-rule", "personal-rule" -> {
                if (command == "personal-rule") requireLinked(context) else requireReady(context)
                val kind = args.getString("kind")
                val pattern = args.getString("pattern").trim()
                val destination = when (kind) {
                    "package" -> pattern.takeIf { it.length <= 255 && packageName.matches(it) }
                    "domain", "suffix" -> pattern.lowercase().trimEnd('.').takeIf { it.length <= 253 }
                    else -> null
                } ?: throw MobileFailure("Недопустимое значение правила")
                val action = args.getString("action")
                if (action !in actions) throw MobileFailure("Недопустимый маршрут")
                val enabled = args.optBoolean("enabled", true)
                val rule = JSONObject().put("kind", kind).put("pattern", destination)
                    .put("action", action).put("enabled", enabled)
                if (command == "personal-rule") {
                    rule.put("revision", args.optLong("revision"))
                    val result = request(current, "/personal-rules", "PUT", rule)
                    if (result.code == 409) throw MobileFailure("Правило изменилось. Синхронизируйте настройки")
                    if (result.code !in 200..299) throw MobileFailure("Сервер отклонил правило")
                    sync(context)
                } else {
                    val old = current.optJSONArray("local") ?: JSONArray()
                    val next = JSONArray()
                    for (index in 0 until old.length()) {
                        val entry = old.getJSONObject(index)
                        if (entry.optString("pattern") != destination || entry.optString("kind") != kind) next.put(entry)
                    }
                    if (action != "INHERIT") next.put(rule)
                    apply(context, JSONObject(current.toString()).put("local", next))
                }
            }
            "delete-personal-rule" -> {
                requireLinked(context)
                val id = args.getString("id").trim()
                if (id.isEmpty()) throw MobileFailure("Укажите идентификатор правила")
                val result = request(current, "/personal-rules/$id", "DELETE")
                if (result.code !in 200..299 && result.code != 404) throw MobileFailure("Сервер отклонил удаление правила")
                sync(context)
            }
            "quick-mode" -> applyQuickMode(context, args)
            "android-autostart" -> {
                val enabled = args.getBoolean("autoStart")
                persist(context, JSONObject(current.toString()).put("autoStart", enabled))
            }
            "recent-domains" -> {
                engine?.pollConnections()
                return JSONObject().put("domains", engine?.recentDomainsJson() ?: JSONArray())
            }
            "clear-recent-domains" -> {
                engine?.clearRecentDomains()
                return JSONObject().put("domains", JSONArray())
            }
            "bulk-domain-rules" -> {
                requireLinked(context)
                val domains = args.getJSONArray("domains")
                val scope = args.optString("scope", "LOCAL")
                val kind = args.optString("kind", "domain")
                val action = args.optString("action", "PROXY")
                if (kind !in setOf("domain", "suffix") || action !in actions || domains.length() == 0)
                    throw MobileFailure("Выберите домены и корректный маршрут")
                val cleaned = (0 until domains.length()).map { domains.getString(it).trim().lowercase().trimEnd('.') }
                    .filter { it.isNotEmpty() && it.length <= 253 }.distinct()
                if (cleaned.isEmpty()) throw MobileFailure("Нет корректных доменов")
                if (scope == "PERSONAL") {
                    val remoteRules = current.optJSONObject("remote")?.optJSONArray("rules") ?: JSONArray()
                    for (dom in cleaned) {
                        var rev = 0L
                        for (i in 0 until remoteRules.length()) {
                            val r = remoteRules.getJSONObject(i)
                            if (r.optString("userId").isNotEmpty() && r.optString("kind") == kind && r.optString("pattern") == dom) {
                                rev = r.optLong("revision")
                                break
                            }
                        }
                        val rule = JSONObject().put("kind", kind).put("pattern", dom)
                            .put("action", action).put("enabled", true).put("revision", rev)
                        val result = request(current, "/personal-rules", "PUT", rule)
                        if (result.code == 409) throw MobileFailure("Конфликт правила для $dom. Синхронизируйте настройки")
                        if (result.code !in 200..299) throw MobileFailure("Сервер отклонил правило для $dom")
                    }
                    sync(context)
                } else {
                    val old = current.optJSONArray("local") ?: JSONArray()
                    val next = JSONArray()
                    val replacing = cleaned.toSet()
                    for (i in 0 until old.length()) {
                        val entry = old.getJSONObject(i)
                        if (entry.optString("kind") != kind || entry.optString("pattern") !in replacing) next.put(entry)
                    }
                    if (action != "INHERIT") {
                        for (dom in cleaned) {
                            next.put(JSONObject().put("kind", kind).put("pattern", dom).put("action", action).put("enabled", true))
                        }
                    }
                    apply(context, JSONObject(current.toString()).put("local", next))
                }
            }
            else -> throw MobileFailure("Команда недоступна на Android")
        }
        return status(context)
    }

    private fun connect(context: Context, link: String, current: JSONObject) {
        if (current.has("key")) throw MobileFailure("Устройство уже подключено")
        val url = try { URI(link.trim()) } catch (_: Exception) { throw MobileFailure("Неверная ссылка") }
        val httpAllowed = debug(context) && url.scheme == "http" && url.host == "127.0.0.1"
        if (!(url.scheme == "https" || httpAllowed) || url.path != "/connect" || url.host == null ||
            url.userInfo != null || url.query != null || !tokenFormat.matches(url.fragment ?: ""))
            throw MobileFailure("Укажите персональную HTTPS-ссылку")
        val pending = JSONObject(current.toString())
            .put("origin", URI(url.scheme, null, url.host, url.port, null, null, null).toString())
            .put("key", randomToken())
        val result = try {
            request(pending, "/connect", "POST",
                JSONObject().put("token", url.fragment).put("deviceKey", pending.getString("key")).put("transport", "agent"))
        } catch (_: IOException) { throw MobileFailure("Сервер подключения недоступен") }
        if (result.code != 201) throw MobileFailure("Ссылка просрочена или использована")
        persist(context, pending.put("configMode", "subscription"))
        sync(context)
    }

    private fun sync(context: Context) {
        val current = state(context)
        if (!current.has("key")) return
        val remote = current.optJSONObject("remote")
        val tag = current.optString("etag").takeIf { it.isNotEmpty() }
        try {
            val (code, body, nextTag) = request(current, "/config?platform=android", "GET", etag = tag,
                version = AndroidUpdates.installedVersion(context))
            online = code == 200 || code == 304
            if (code == 401) {
                dropConnection(context)
                persist(context, localSettings(current))
                online = false
                message = "Сервер отозвал доступ устройства"
                return
            }
            if (code == 200) {
                val next = JSONObject(body)
                if (remote != null && (next.getString("deviceId") != remote.getString("deviceId") ||
                        next.getLong("revision") < remote.getLong("revision")))
                    throw MobileFailure("Сервер вернул устаревшие настройки")
                apply(context, JSONObject(current.toString()).put("remote", next).put("etag", nextTag))
            } else if (code != 304) throw MobileFailure("Сервер не выдал настройки")
            val saved = state(context)
            val revision = saved.getJSONObject("remote").getLong("revision")
            if (revision > saved.optLong("ack")) {
                val (ack, _) = request(saved, "/ack", "POST", JSONObject().put("revision", revision))
                if (ack == 204) persist(context, JSONObject(saved.toString()).put("ack", revision))
            }
            message = null
            syncInterval = 12_000L
        } catch (_: IOException) {
            online = false
            message = "Сервер недоступен. Используются сохранённые настройки"
            syncInterval = minOf(syncInterval * 2, 120_000L)
        } catch (error: Exception) {
            message = if (error is MobileFailure) error.message else "Сервер вернул неверные настройки"
            syncInterval = minOf(syncInterval * 2, 120_000L)
        }
        nextSync = SystemClock.elapsedRealtime() + syncInterval
    }

    private fun request(account: JSONObject, path: String, method: String, body: JSONObject? = null,
                        etag: String? = null, version: String? = null): Reply {
        val builder = Request.Builder().url(account.getString("origin") + "/api/v1" + path)
        if (path != "/connect") builder.header("Authorization", "Bearer " + account.getString("key"))
        if (etag != null) builder.header("If-None-Match", etag)
        if (!version.isNullOrEmpty()) builder.header("X-HomeProxy-Version", version)
        builder.method(method, body?.toString()?.toRequestBody(jsonType))
        http.newCall(builder.build()).execute().use { response ->
            val output = ByteArrayOutputStream()
            response.body?.byteStream()?.use { stream ->
                val buffer = ByteArray(8192)
                while (true) {
                    val n = stream.read(buffer)
                    if (n < 0) break
                    if (output.size() + n > 1024 * 1024) throw MobileFailure("Настройки слишком большие")
                    output.write(buffer, 0, n)
                }
            }
            return Reply(response.code, output.toString("UTF-8"), response.header("ETag"))
        }
    }

    fun plan(context: Context, state: JSONObject, probePort: Int, controlPort: Int, secret: String): JSONObject {
        val argument = JSONObject()
            .put("local", state.optJSONArray("local") ?: JSONArray())
            .put("localGroups", state.optJSONArray("localGroups") ?: JSONArray())
            .put("configMode", state.optString("configMode", "subscription"))
            .put("excludedApps", exclusions(state))
            .put("profile", state.optString("profile", "AUTO"))
            .put("custom", state.optString("custom", "PROXY"))
            .put("probePort", probePort).put("controlPort", controlPort).put("secret", secret)
            .put("debugLoopback", debug(context))
        state.optJSONObject("remote")?.let { argument.put("remote", it) }
        state.optJSONObject("customProxy")?.let { argument.put("customProxy", it) }
        val result = JSONObject(NativePlan.render(argument.toString()))
        if (result.has("error")) throw MobileFailure(result.getString("error"))
        return result
    }

    private fun apply(context: Context, next: JSONObject) {
        val previous = state(context)
        plan(context, next, 20_010, 20_011, randomToken())
        val service = engine
        try {
            service?.apply(next)
            persist(context, next)
        } catch (_: Exception) {
            if (service != null) {
                if (isReady(previous)) {
                    try { service.apply(previous) } catch (_: Exception) { dropConnection(context) }
                } else dropConnection(context)
            }
            throw MobileFailure("Не удалось применить настройки VPN")
        }
    }

    fun started(service: HomeProxyVpnService) {
        engine = service
        establish(service)
    }

    private fun establish(service: HomeProxyVpnService) {
        try {
            val current = state(service)
            if (!isReady(current)) {
                if (!service.isAlwaysOn) stop(service)
                return
            }
            service.apply(current)
            message = null
        } catch (_: Exception) {
            dropConnection(service)
            message = "Не удалось запустить VPN"
        }
    }

    fun tick(service: HomeProxyVpnService) {
        if (engine !== service) return
        if (service.connected) {
            try { service.probe() } catch (_: Exception) { message = "Проверка маршрута VPN не удалась" }
            try { service.pollConnections() } catch (_: Exception) { }
        } else if (service.isAlwaysOn) {
            establish(service)
        } else {
            stop(service)
        }
        if (engine === service && state?.has("key") == true && SystemClock.elapsedRealtime() >= nextSync) sync(service)
    }

    fun stopped(service: HomeProxyVpnService) {
        if (engine === service) engine = null
        service.close()
    }

    private fun stop(context: Context) {
        val service = engine
        engine = null
        service?.close()
        context.stopService(Intent(context, HomeProxyVpnService::class.java))
    }

    private fun dropConnection(context: Context) {
        val service = engine
        if (service?.isAlwaysOn == true) service.close() else stop(context)
    }

    private fun requireManualVpn() {
        if (engine?.isAlwaysOn == true) throw MobileFailure("Выключите Always-on VPN в настройках Android")
    }

    fun testRoute(url: String, port: Int, name: String, secret: String): Boolean = try {
        val probe = http.newBuilder()
            .proxy(Proxy(Proxy.Type.HTTP, InetSocketAddress("127.0.0.1", port)))
            .proxyAuthenticator { _, response ->
                if (response.request.header("Proxy-Authorization") != null) null
                else response.request.newBuilder().header("Proxy-Authorization", Credentials.basic(name, secret)).build()
            }.build()
        probe.newCall(Request.Builder().url(url).head().build()).execute().use { it.isSuccessful }
    } catch (_: Exception) { false }

    fun applyQuickMode(context: Context, mode: String) {
        applyQuickMode(context, JSONObject().put("mode", mode))
    }

    fun applyQuickMode(context: Context, args: JSONObject) {
        val current = state(context)
        val next = JSONObject(current.toString())
        val baseRoute = args.optString("baseRoute", "")
        if (baseRoute == "direct" || baseRoute == "proxy") {
            next.put("autoBaseRoute", baseRoute)
        }
        val effectiveBase = next.optString("autoBaseRoute", "direct")
        when (args.optString("mode")) {
            "off" -> {
                requireManualVpn()
                next.put("routingMode", "off")
                persist(context, next)
                stop(context)
            }
            "rules", "auto" -> {
                requireReady(context)
                next.put("routingMode", "auto")
                next.put("profile", if (effectiveBase == "proxy") "AUTO" else "DIRECT_INTERNET")
                apply(context, next)
            }
            "all" -> {
                requireReady(context)
                next.put("routingMode", "all")
                next.put("profile", "AUTO")
                apply(context, next)
            }
            else -> throw MobileFailure("Неверный быстрый режим")
        }
        engine?.showNotification()
        HomeProxyTileService.requestUpdate(context)
    }

    fun applyQuickModeSafe(context: Context, mode: String) {
        try {
            applyQuickMode(context, mode)
        } catch (_: Exception) {
        }
    }

    fun fetchConnections(port: Int, secret: String): JSONArray = try {
        http.newCall(
            Request.Builder().url("http://127.0.0.1:$port/connections")
                .header("Authorization", "Bearer $secret").build()
        ).execute().use { response ->
            if (!response.isSuccessful) JSONArray()
            else JSONObject(response.body?.string() ?: "{}").optJSONArray("connections") ?: JSONArray()
        }
    } catch (_: Exception) { JSONArray() }

    fun select(port: Int, name: String, secret: String) {
        http.newCall(Request.Builder().url("http://127.0.0.1:$port/proxies/selected-proxy")
            .header("Authorization", "Bearer $secret")
            .put(JSONObject().put("name", name).toString().toRequestBody(jsonType)).build()).execute().use {
            if (!it.isSuccessful) throw MobileFailure("Не удалось переключить маршрут")
        }
    }
}
