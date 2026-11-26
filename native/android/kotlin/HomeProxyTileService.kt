package app.homeproxy.agent

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService

class HomeProxyTileService : TileService() {
    override fun onStartListening() {
        super.onStartListening()
        refreshTile()
    }

    override fun onClick() {
        super.onClick()
        if (!MobileRuntime.hasRemote(this) || VpnService.prepare(this) != null) {
            val launch = packageManager.getLaunchIntentForPackage(packageName) ?: return
            launch.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            if (Build.VERSION.SDK_INT >= 34) {
                val pending = android.app.PendingIntent.getActivity(
                    this,
                    420,
                    launch,
                    android.app.PendingIntent.FLAG_IMMUTABLE or android.app.PendingIntent.FLAG_UPDATE_CURRENT
                )
                startActivityAndCollapse(pending)
            } else {
                @Suppress("DEPRECATION")
                startActivityAndCollapse(launch)
            }
            return
        }
        MobileRuntime.worker.execute {
            val nextAction = when {
                !MobileRuntime.isVpnRunning() -> HomeProxyVpnService.ACTION_MODE_RULES
                MobileRuntime.currentProfile(this) == "DIRECT_INTERNET" -> HomeProxyVpnService.ACTION_MODE_ALL
                !MobileRuntime.isAlwaysOnVpn() -> HomeProxyVpnService.ACTION_MODE_OFF
                else -> HomeProxyVpnService.ACTION_MODE_RULES
            }
            startForegroundService(Intent(this, HomeProxyVpnService::class.java).setAction(nextAction))
            refreshTile()
        }
    }

    private fun refreshTile() {
        val tile = qsTile ?: return
        val active = MobileRuntime.isVpnRunning()
        tile.state = if (active) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
        if (Build.VERSION.SDK_INT >= 29) {
            tile.subtitle = if (active) MobileRuntime.currentModeLabel(this) else "Выкл"
        }
        tile.updateTile()
    }

    companion object {
        fun requestUpdate(context: Context) {
            try {
                requestListeningState(context, ComponentName(context, HomeProxyTileService::class.java))
            } catch (_: Exception) {
            }
        }
    }
}
