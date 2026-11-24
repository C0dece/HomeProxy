package app.homeproxy.agent

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import io.nekohasekai.libbox.CommandServer
import io.nekohasekai.libbox.CommandServerHandler
import io.nekohasekai.libbox.Libbox
import io.nekohasekai.libbox.OverrideOptions
import io.nekohasekai.libbox.SetupOptions
import io.nekohasekai.libbox.SystemProxyStatus
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit

class HomeProxyVpnService : VpnService(), CommandServerHandler {
    private val platform by lazy { VpnPlatform(this) }
    private var core: CommandServer? = null
    private var ticker: ScheduledFuture<*>? = null
    private var started = false
    private val secret = MobileRuntime.randomToken()
    private val probePort = MobileRuntime.port()
    private val controlPort = generateSequence { MobileRuntime.port() }.first { it != probePort }
    private var probeUrl = ""
    private var candidates = JSONArray()
    private var selected: String? = null
    private var serverDirect = false
    private val health = mutableMapOf<String, Int>()
    private val probes = Executors.newFixedThreadPool(4)
    internal var connected = false
        private set

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent == null && !isAlwaysOn) {
            stopSelf(startId)
            return START_NOT_STICKY
        }
        showNotification()
        if (!started) {
            started = true
            MobileRuntime.worker.execute { MobileRuntime.started(this) }
            ticker = MobileRuntime.worker.scheduleWithFixedDelay({ MobileRuntime.tick(this) }, 6, 6, TimeUnit.SECONDS)
        }
        return if (isAlwaysOn) START_STICKY else START_NOT_STICKY
    }

    private fun showNotification() {
        val notifications = getSystemService(NotificationManager::class.java)
        notifications.createNotificationChannel(NotificationChannel("homeproxy.vpn", "HomeProxy VPN", NotificationManager.IMPORTANCE_LOW))
        val launch = packageManager.getLaunchIntentForPackage(packageName)
        val pending = launch?.let { PendingIntent.getActivity(this, 0, it, PendingIntent.FLAG_IMMUTABLE) }
        startForeground(410, Notification.Builder(this, "homeproxy.vpn")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentTitle("HomeProxy VPN")
            .setContentText("Маршрутизация через HomeProxy")
            .setContentIntent(pending)
            .setOngoing(true)
            .build())
    }

    internal fun apply(state: JSONObject) {
        val plan = MobileRuntime.plan(this, state, probePort, controlPort, secret)
        val config = plan.getJSONObject("config").toString()
        Libbox.checkConfig(config)
        val service = core ?: createCore()
        service.startOrReloadService(config, OverrideOptions())
        candidates = plan.getJSONArray("candidates")
        probeUrl = state.getJSONObject("remote").getString("probeUrl")
        health.clear()
        selected = null
        connected = true
        probe()
    }

    private fun createCore(): CommandServer {
        val home = File(noBackupFilesDir, "core").apply { mkdirs() }
        Libbox.setup(SetupOptions().apply {
            basePath = home.absolutePath
            workingPath = home.absolutePath
            tempPath = cacheDir.absolutePath
            logMaxLines = 32L
            fixAndroidStack = true
            commandServerSecret = secret
        })
        return Libbox.newCommandServer(this, platform.platform).also {
            core = it
            it.start()
        }
    }

    internal fun probe() {
        if (!connected) return
        val tags = (0 until candidates.length()).map { candidates.getJSONObject(it).getString("tag") }
        val all = tags + "server-direct"
        val results = probes.invokeAll(all.map { tag -> Callable { MobileRuntime.testRoute(probeUrl, probePort, tag, secret) } },
            7, TimeUnit.SECONDS)
        all.zip(results).forEach { (tag, result) ->
            val available = !result.isCancelled && result.get()
            health[tag] = if (available) minOf(2, (health[tag] ?: 0) + 1) else 0
        }
        serverDirect = (health["server-direct"] ?: 0) > 0
        val currentGood = (selected?.let { health[it] } ?: 0) > 0
        val minimum = if (currentGood) 2 else 1
        val next = tags.firstOrNull { it == selected && currentGood || (health[it] ?: 0) >= minimum }
        if (next != selected) {
            MobileRuntime.select(controlPort, next ?: "unavailable", secret)
            selected = next
        }
    }

    internal fun routeStatus(): JSONObject {
        val list = JSONArray()
        for (index in 0 until candidates.length()) {
            val entry = JSONObject(candidates.getJSONObject(index).toString())
            list.put(entry.put("available", (health[entry.getString("tag")] ?: 0) > 0))
        }
        return JSONObject().put("selected", selected ?: JSONObject.NULL).put("candidates", list)
            .put("fallback", selected?.startsWith("backup-") == true).put("serverDirectAvailable", serverDirect)
    }

    internal fun close() {
        connected = false
        candidates = JSONArray()
        selected = null
        serverDirect = false
        health.clear()
        val service = core
        core = null
        if (service != null) {
            try { service.closeService() } catch (_: Exception) { }
            try { service.close() } catch (_: Exception) { }
        }
        try { platform.close() } catch (_: Exception) { }
    }

    override fun onDestroy() {
        ticker?.cancel(false)
        MobileRuntime.worker.execute {
            MobileRuntime.stopped(this)
            probes.shutdownNow()
        }
        super.onDestroy()
    }

    override fun onRevoke() = stopSelf()
    override fun serviceStop() = stopSelf()
    override fun serviceReload() { throw UnsupportedOperationException("Reload through HomeProxy") }
    override fun getSystemProxyStatus(): SystemProxyStatus = SystemProxyStatus()
    override fun setSystemProxyEnabled(enabled: Boolean) { throw UnsupportedOperationException("System proxy unavailable") }
    override fun triggerNativeCrash() { throw UnsupportedOperationException("Crash command unavailable") }
    override fun writeDebugMessage(message: String) { }
    override fun connectSSHAgent(): Int { throw UnsupportedOperationException("SSH agent unavailable") }
}
