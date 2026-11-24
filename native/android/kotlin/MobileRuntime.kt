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
        .put("excludedApps", exclusions(current))

    fun requireLinked(context: Context) {
        if (state(context).optJSONObject("remote") == null) throw MobileFailure("Сначала подключите устройство")
    }

    fun debug(context: Context) = context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0

    fun randomToken(): String = ByteArray(32).also { SecureRandom().nextBytes(it) }.let {
        Base64.encodeToString(it, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
    }

    fun port(): Int = ServerSocket(0, 1, InetAddress.getByName("127.0.0.1")).use { it.localPort }

    fun status(context: Context): JSONObject {
        val current = state(context)
        val remote = current.optJSONObject("remote")
        return JSONObject()
            .put("platform", "android")
            .put("linked", current.has("key"))
            .put("online", online)
            .put("enabled", engine?.connected == true)
            .put("alwaysOn", engine?.isAlwaysOn ?: JSONObject.NULL)
            .put("lockdown", engine?.isLockdownEnabled ?: JSONObject.NULL)
            .put("excludedApps", exclusions(current))
            .put("exclusionsAllowed", exclusionsAllowed(current))
            .put("profile", current.optString("profile", "AUTO"))
            .put("custom", current.optString("custom", "PROXY"))
            .put("revision", remote?.optLong("revision") ?: JSONObject.NULL)
            .put("ack", current.optLong("ack"))
            .put("proxyPort", 0)
            .put("error", message ?: JSONObject.NULL)
            .put("rules", current.optJSONArray("local") ?: JSONArray())
            .put("remoteRules", remote?.optJSONArray("rules") ?: JSONArray())
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
                requireLinked(context)
                val profile = args.getString("profile")
                val custom = if (profile == "CUSTOM") args.getString("action") else current.optString("custom", "PROXY")
                if (profile !in profiles || custom !in actions || custom == "AUTO" || custom == "INHERIT")
                    throw MobileFailure("Проверьте профиль подключения")
                apply(context, JSONObject(current.toString()).put("profile", profile).put("custom", custom))
            }
            "local-rule", "personal-rule" -> {
                requireLinked(context)
                val kind = args.getString("kind")
                val pattern = args.getString("pattern").trim()
                val destination = when (kind) {
                    "package" -> pattern.takeIf { it.length <= 255 && packageName.matches(it) }
                    "domain", "suffix" -> pattern.lowercase().trimEnd('.').takeIf { it.length <= 253 }
                    else -> null
                } ?: throw MobileFailure("Недопустимое значение правила")
                val action = args.getString("action")
                if (action !in actions) throw MobileFailure("Недопустимый маршрут")
                val rule = JSONObject().put("kind", kind).put("pattern", destination).put("action", action)
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
        persist(context, pending)
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
            online = true
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
            .put("remote", state.getJSONObject("remote"))
            .put("local", state.optJSONArray("local") ?: JSONArray())
            .put("excludedApps", exclusions(state))
            .put("profile", state.optString("profile", "AUTO"))
            .put("custom", state.optString("custom", "PROXY"))
            .put("probePort", probePort).put("controlPort", controlPort).put("secret", secret)
            .put("debugLoopback", debug(context))
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
                if (previous.has("remote")) {
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
            if (!current.has("remote")) {
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

    fun select(port: Int, name: String, secret: String) {
        http.newCall(Request.Builder().url("http://127.0.0.1:$port/proxies/selected-proxy")
            .header("Authorization", "Bearer $secret")
            .put(JSONObject().put("name", name).toString().toRequestBody(jsonType)).build()).execute().use {
            if (!it.isSuccessful) throw MobileFailure("Не удалось переключить маршрут")
        }
    }
}
