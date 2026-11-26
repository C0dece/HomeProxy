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
    companion object {
        const val ACTION_MODE_OFF = "app.homeproxy.agent.MODE_OFF"
        const val ACTION_MODE_RULES = "app.homeproxy.agent.MODE_RULES"
        const val ACTION_MODE_ALL = "app.homeproxy.agent.MODE_ALL"
        private const val MAX_RECENT_DOMAINS = 120
        private val ipLike = Regex("^[0-9.:\\[\\]]+$")
    }

    private data class RecentDomain(
        val domain: String,
        var rule: String,
        var chain: String,
        var lastSeen: Long,
        var count: Int
    )

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
    private val recentDomains = LinkedHashMap<String, RecentDomain>()
    private val probes = Executors.newFixedThreadPool(4)
    internal var connected = false
        private set

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent == null && !isAlwaysOn) {
            stopSelf(startId)
            return START_NOT_STICKY
        }
        val action = intent?.action
        if (action == ACTION_MODE_OFF && !isAlwaysOn) {
            MobileRuntime.worker.execute {
                try {
                    MobileRuntime.applyQuickMode(this, "off")
                } catch (_: Exception) {
                }
            }
            return START_NOT_STICKY
        }
        showNotification()
        if (!started) {
            started = true
            MobileRuntime.worker.execute {
                MobileRuntime.started(this)
                if (action == ACTION_MODE_RULES) MobileRuntime.applyQuickModeSafe(this, "rules")
                else if (action == ACTION_MODE_ALL) MobileRuntime.applyQuickModeSafe(this, "all")
            }
            ticker = MobileRuntime.worker.scheduleWithFixedDelay({ MobileRuntime.tick(this) }, 6, 6, TimeUnit.SECONDS)
        } else if (action == ACTION_MODE_RULES) {
            MobileRuntime.worker.execute { MobileRuntime.applyQuickModeSafe(this, "rules") }
        } else if (action == ACTION_MODE_ALL) {
            MobileRuntime.worker.execute { MobileRuntime.applyQuickModeSafe(this, "all") }
        }
        return if (isAlwaysOn) START_STICKY else START_NOT_STICKY
    }

    private fun actionIntent(action: String, requestCode: Int, title: String): Notification.Action {
        val intent = Intent(this, HomeProxyVpnService::class.java).setAction(action)
        val pending = PendingIntent.getForegroundService(
            this,
            requestCode,
            intent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        return Notification.Action.Builder(null, title, pending).build()
    }

    internal fun showNotification() {
        val notifications = getSystemService(NotificationManager::class.java)
        notifications.createNotificationChannel(
            NotificationChannel("homeproxy.vpn", "HomeProxy VPN", NotificationManager.IMPORTANCE_LOW)
        )
        val launch = packageManager.getLaunchIntentForPackage(packageName)
        val pending = launch?.let { PendingIntent.getActivity(this, 0, it, PendingIntent.FLAG_IMMUTABLE) }
        val mode = MobileRuntime.currentModeLabel(this)
        val builder = Notification.Builder(this, "homeproxy.vpn")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentTitle("HomeProxy VPN · $mode")
            .setContentText(if (connected) "Туннель активен" else "Подготовка подключения")
            .setContentIntent(pending)
            .setOngoing(true)
            .addAction(actionIntent(ACTION_MODE_RULES, 411, "Авто"))
            .addAction(actionIntent(ACTION_MODE_ALL, 412, "Весь трафик"))
        if (!isAlwaysOn) {
            builder.addAction(actionIntent(ACTION_MODE_OFF, 413, "Выкл"))
        }
        startForeground(410, builder.build())
        HomeProxyTileService.requestUpdate(this)
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
        showNotification()
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

    internal fun pollConnections() {
        if (!connected) return
        val connections = MobileRuntime.fetchConnections(controlPort, secret)
        val now = System.currentTimeMillis() / 1000L
        synchronized(recentDomains) {
            for (index in 0 until connections.length()) {
                val conn = connections.optJSONObject(index) ?: continue
                val meta = conn.optJSONObject("metadata") ?: continue
                val host = meta.optString("host").trim().lowercase().trimEnd('.')
                if (host.isEmpty() || !host.contains('.') || ipLike.matches(host)) continue
                val rule = conn.optString("rule")
                val chains = conn.optJSONArray("chains")
                val chain = if (chains != null && chains.length() > 0) chains.optString(0) else ""
                val existing = recentDomains.remove(host)
                if (existing != null) {
                    existing.rule = rule
                    existing.chain = chain
                    existing.lastSeen = now
                    existing.count += 1
                    recentDomains[host] = existing
                } else {
                    if (recentDomains.size >= MAX_RECENT_DOMAINS) {
                        val oldest = recentDomains.keys.firstOrNull()
                        if (oldest != null) recentDomains.remove(oldest)
                    }
                    recentDomains[host] = RecentDomain(host, rule, chain, now, 1)
                }
            }
        }
    }

    internal fun recentDomainsJson(): JSONArray {
        val list = synchronized(recentDomains) {
            recentDomains.values.toList().asReversed()
        }
        val out = JSONArray()
        for (item in list) {
            out.put(
                JSONObject()
                    .put("domain", item.domain)
                    .put("rule", item.rule)
                    .put("chain", item.chain)
                    .put("lastSeen", item.lastSeen)
                    .put("count", item.count)
            )
        }
        return out
    }

    internal fun clearRecentDomains() {
        synchronized(recentDomains) { recentDomains.clear() }
    }

    internal fun routeStatus(): JSONObject {
        val list = JSONArray()
        for (index in 0 until candidates.length()) {
            val entry = JSONObject(candidates.getJSONObject(index).toString())
            list.put(entry.put("available", (health[entry.getString("tag")] ?: 0) > 0))
        }
        val primary = if (candidates.length() > 0) candidates.getJSONObject(0).getString("tag") else null
        val isFallback = selected != null && primary != null && selected != primary
        return JSONObject().put("selected", selected ?: JSONObject.NULL).put("candidates", list)
            .put("fallback", isFallback).put("serverDirectAvailable", serverDirect)
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
        HomeProxyTileService.requestUpdate(this)
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
