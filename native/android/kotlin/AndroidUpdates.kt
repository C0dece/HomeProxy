package app.homeproxy.agent

import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInfo
import android.content.pm.PackageInstaller
import android.content.pm.PackageManager
import android.os.Build
import android.util.Base64
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject
import java.io.File
import java.io.FileNotFoundException
import java.io.InputStream
import java.net.ConnectException
import java.net.NoRouteToHostException
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import java.security.MessageDigest
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

internal object AndroidUpdates {
    private const val RESULT = "app.homeproxy.agent.UPDATE_RESULT"
    private const val MAX_APK = 1L shl 30
    private class RateLimitException : Exception()
    val worker = Executors.newSingleThreadExecutor()
    private val client = OkHttpClient.Builder().followRedirects(false).followSslRedirects(false)
        .connectTimeout(15, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .callTimeout(3, TimeUnit.MINUTES).build()
    private val channels = setOf("dev", "beta", "stable")
    private val versionFormat = Regex("v?(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)")
    private val shaFormat = Regex("[a-fA-F0-9]{64}")

    private data class Offer(val channel: String, val version: String, val code: Long, val url: String, val size: Long, val hash: String, val notes: String)
    private var offer: Offer? = null
    @Volatile private var confirmation: Intent? = null
    @Volatile private var notice: String? = null

    @JvmStatic private external fun verify(key: ByteArray, payload: ByteArray, signature: ByteArray): Boolean

    private fun source(context: Context): JSONObject? = try {
        context.assets.open("update-source.json").bufferedReader().use { JSONObject(it.readText()) }
            .takeIf { it.has("key") }
    } catch (_: FileNotFoundException) { null }

    @Suppress("DEPRECATION")
    private fun installed(context: Context, flags: Int = PackageManager.GET_SIGNING_CERTIFICATES) = context.packageManager.getPackageInfo(
        context.packageName, flags
    )

    fun installedVersion(context: Context): String = installed(context, 0).versionName.orEmpty()

    private fun sessions(context: Context) = context.packageManager.packageInstaller.mySessions
        .filter { it.appPackageName == context.packageName }

    private fun paused(context: Context) =
        HomeStore(context).read().optJSONObject("remote")?.optBoolean("clientUpdatesPaused") == true

    private fun requireUpdatesAllowed(context: Context) {
        if (paused(context)) throw MobileFailure("Администратор приостановил обновления")
    }

    fun status(context: Context): JSONObject = JSONObject()
        .put("configured", source(context) != null)
        .put("installed", installedVersion(context))
        .put("paused", paused(context))
        .put("allowed", context.packageManager.canRequestPackageInstalls())
        .put("active", sessions(context).isNotEmpty())
        .put("confirm", confirmation != null)
        .put("notice", notice ?: JSONObject.NULL)
        .put("offer", offer?.let {
            JSONObject().put("channel", it.channel).put("version", it.version).put("size", it.size).put("notes", it.notes)
        } ?: JSONObject.NULL)

    fun check(context: Context, channel: String): JSONObject {
        requireUpdatesAllowed(context)
        offer = null
        notice = null
        if (channel !in channels) throw MobileFailure("Неизвестный канал обновлений")
        val source = source(context) ?: throw MobileFailure("Источник обновлений не задан в сборке")
        val manifest: ByteArray
        val sig: ByteArray
        try {
            manifest = request(context, source.getString("manifest")) { it.readBounded(262_144) }
            sig = request(context, source.getString("signature")) { it.readBounded(512) }
        } catch (_: RateLimitException) {
            notice = "Превышен лимит запросов GitHub API. Попробуйте позже."
            return status(context)
        } catch (_: SocketTimeoutException) {
            notice = "Превышено время ожидания ответа от GitHub."
            return status(context)
        } catch (_: UnknownHostException) {
            notice = "Нет подключения к сети. Проверьте интернет."
            return status(context)
        } catch (_: ConnectException) {
            notice = "Нет подключения к сети или сервер обновлений недоступен."
            return status(context)
        } catch (_: NoRouteToHostException) {
            notice = "Нет подключения к сети. Проверьте интернет."
            return status(context)
        }
        System.loadLibrary("homeproxy_desktop_lib")
        val key = decode(source.getString("key").trim().removeSurrounding("-----BEGIN PUBLIC KEY-----", "-----END PUBLIC KEY-----"))
        if (!verify(key, manifest, decode(sig.toString(Charsets.US_ASCII)))) {
            throw MobileFailure("Подпись манифеста не совпадает")
        }
        val release = JSONObject(manifest.toString(Charsets.UTF_8))
        if (release.getInt("format") != 1) throw MobileFailure("Неподдерживаемый формат манифеста")
        val entries = release.getJSONArray("artifacts")
        val current = installed(context)
        val currentVersion = version(current.versionName ?: "")
        var newest: Offer? = null
        for (i in 0 until entries.length()) {
            val entry = entries.getJSONObject(i)
            if (entry.optString("component") != "agent" || entry.optString("platform") != "android" ||
                entry.optString("arch") != source.getString("arch") || entry.optString("channel") != channel) continue
            val next = Offer(channel, entry.getString("version").removePrefix("v"), entry.getLong("versionCode"), entry.getString("url"),
                entry.getLong("size"), entry.getString("sha256"), entry.optString("notes").take(1000))
            val count = version(next.version)
            val min = entry.getInt("apiMin")
            val max = entry.getInt("apiMax")
            if (next.size !in 1..MAX_APK || !shaFormat.matches(next.hash) || min < 1 || max < min) {
                throw MobileFailure("Некорректная запись обновления")
            }
            if (next.code <= current.longVersionCode || compare(count, currentVersion) <= 0 || 1 !in min..max) continue
            url(context, next.url)
            val previous = newest
            val order = if (previous == null) 1 else compare(count, version(previous.version))
            if (order == 0) throw MobileFailure("Повторяющаяся версия в манифесте")
            if (order > 0) newest = next
        }
        offer = newest
        if (offer == null) notice = "Совместимых обновлений нет"
        return status(context)
    }

    private fun version(value: String): List<Long> =
        versionFormat.matchEntire(value)?.groupValues?.drop(1)?.map(String::toLong)
            ?: throw MobileFailure("Ожидается версия major.minor.patch")

    private fun compare(a: List<Long>, b: List<Long>): Int {
        for (i in a.indices) {
            val result = a[i].compareTo(b[i])
            if (result != 0) return result
        }
        return 0
    }

    private fun decode(value: String): ByteArray = try {
        Base64.decode(value.filterNot(Char::isWhitespace), Base64.DEFAULT)
    } catch (_: IllegalArgumentException) {
        throw MobileFailure("Некорректная подпись или открытый ключ")
    }

    private fun url(context: Context, value: String): HttpUrl {
        val parsed = value.toHttpUrlOrNull() ?: throw MobileFailure("Некорректный адрес обновления")
        val dev = MobileRuntime.debug(context) && parsed.host == "127.0.0.1"
        if (parsed.username.isNotEmpty() || parsed.password.isNotEmpty() ||
            (!parsed.isHttps && !dev)) throw MobileFailure("Источник обновлений должен использовать HTTPS")
        return parsed
    }

    private fun <T> request(context: Context, address: String, read: (InputStream) -> T): T {
        var next = url(context, address)
        repeat(6) {
            val req = Request.Builder().url(next).header("User-Agent", "HomeProxy-Android").build()
            client.newCall(req).execute().use { response ->
                if (response.isRedirect) {
                    val location = response.header("Location")?.let(next::resolve)
                        ?: throw MobileFailure("Некорректный адрес перенаправления")
                    next = url(context, location.toString())
                } else {
                    if (response.code == 429 || (response.code == 403 && response.header("X-RateLimit-Remaining") == "0")) {
                        throw RateLimitException()
                    }
                    if (!response.isSuccessful) throw MobileFailure("Источник обновлений недоступен")
                    return response.body?.byteStream()?.use(read) ?: throw MobileFailure("Пустой ответ источника")
                }
            }
        }
        throw MobileFailure("Слишком много перенаправлений")
    }

    private fun InputStream.readBounded(size: Int): ByteArray {
        val output = java.io.ByteArrayOutputStream()
        val buffer = ByteArray(8192)
        while (true) {
            val count = read(buffer)
            if (count < 0) return output.toByteArray()
            if (output.size() + count > size) throw MobileFailure("Слишком большой манифест или подпись")
            output.write(buffer, 0, count)
        }
    }

    fun install(context: Context, channel: String, version: String): JSONObject {
        requireUpdatesAllowed(context)
        val next = offer?.takeIf { it.channel == channel && it.version == version }
            ?: throw MobileFailure("Сначала проверьте обновления")
        if (!context.packageManager.canRequestPackageInstalls()) throw MobileFailure("Разрешите установки в настройках Android")
        if (sessions(context).isNotEmpty()) throw MobileFailure("Сначала завершите предыдущую установку")
        val cache = File(context.cacheDir, "homeproxy-update.apk")
        try {
            val digest = MessageDigest.getInstance("SHA-256")
            var written = 0L
            request(context, next.url) { input ->
                cache.outputStream().use { output ->
                    val buffer = ByteArray(65_536)
                    while (true) {
                        val count = input.read(buffer)
                        if (count < 0) break
                        written += count
                        if (written > next.size) throw MobileFailure("Размер APK не совпадает")
                        digest.update(buffer, 0, count)
                        output.write(buffer, 0, count)
                    }
                }
            }
            if (written != next.size || !digest.digest().joinToString("") { "%02x".format(it) }.equals(next.hash, true)) {
                throw MobileFailure("Контрольная сумма APK не совпадает")
            }
            verifyApk(context, cache, next)
            requireUpdatesAllowed(context)
            stage(context, cache, next.size)
        } finally {
            cache.delete()
        }
        return status(context)
    }

    @Suppress("DEPRECATION")
    private fun verifyApk(context: Context, apk: File, next: Offer) {
        val candidate = context.packageManager.getPackageArchiveInfo(apk.path, PackageManager.GET_SIGNING_CERTIFICATES)
            ?: throw MobileFailure("APK повреждён или не поддерживается")
        val current = installed(context)
        if (candidate.packageName != context.packageName || candidate.longVersionCode != next.code ||
            candidate.longVersionCode <= current.longVersionCode || candidate.versionName != next.version) {
            throw MobileFailure("APK не соответствует версии манифеста")
        }
        fun signers(info: PackageInfo) = info.signingInfo?.apkContentsSigners?.map { it.toCharsString() }?.toSet().orEmpty()
        val expected = signers(current)
        if (expected.isEmpty() || signers(candidate) != expected) throw MobileFailure("У APK другой сертификат подписи")
    }

    private fun stage(context: Context, apk: File, size: Long) {
        val installer = context.packageManager.packageInstaller
        val params = PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL).apply {
            setAppPackageName(context.packageName)
            setSize(size)
            if (Build.VERSION.SDK_INT >= 31) setRequireUserAction(PackageInstaller.SessionParams.USER_ACTION_REQUIRED)
        }
        val sessionId = installer.createSession(params)
        try {
            installer.openSession(sessionId).use { session ->
                session.openWrite("base.apk", 0, size).use { output ->
                    apk.inputStream().use { it.copyTo(output) }
                    session.fsync(output)
                }
                val result = Intent(context, AndroidUpdateResult::class.java).setAction(RESULT)
                val callback = PendingIntent.getBroadcast(context, sessionId, result,
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE)
                notice = "Ожидание подтверждения Android"
                session.commit(callback.intentSender)
            }
        } catch (error: Exception) {
            installer.abandonSession(sessionId)
            throw error
        }
    }

    fun confirmation(context: Context): Intent {
        requireUpdatesAllowed(context)
        return confirmation?.let(::Intent) ?: throw MobileFailure("Android ещё не запросил подтверждение")
    }

    fun cancel(context: Context): JSONObject {
        val installer = context.packageManager.packageInstaller
        sessions(context).forEach { installer.abandonSession(it.sessionId) }
        confirmation = null
        notice = "Установка отменена"
        return status(context)
    }

    @Suppress("DEPRECATION")
    fun result(intent: Intent) {
        if (intent.action != RESULT) return
        val status = intent.getIntExtra(PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE)
        confirmation = if (status == PackageInstaller.STATUS_PENDING_USER_ACTION) intent.getParcelableExtra(Intent.EXTRA_INTENT) else null
        notice = when (status) {
            PackageInstaller.STATUS_PENDING_USER_ACTION -> "Подтвердите установку в Android"
            PackageInstaller.STATUS_SUCCESS -> "Обновление установлено"
            PackageInstaller.STATUS_FAILURE_ABORTED -> "Установка отменена"
            else -> "Android отклонил установку"
        }
    }
}

class AndroidUpdateResult : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) = AndroidUpdates.result(intent)
}
