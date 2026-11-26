package app.homeproxy.agent

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService

class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent?) {
        if (intent?.action != Intent.ACTION_BOOT_COMPLETED) return
        val pending = goAsync()
        MobileRuntime.worker.execute {
            try {
                val saved = HomeStore(context).read()
                if (saved.optBoolean("autoStart", false) &&
                    saved.has("remote") &&
                    VpnService.prepare(context) == null
                ) {
                    context.startForegroundService(Intent(context, HomeProxyVpnService::class.java))
                }
            } catch (_: Exception) {
            } finally {
                pending.finish()
            }
        }
    }
}
