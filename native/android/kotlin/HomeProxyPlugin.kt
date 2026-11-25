package app.homeproxy.agent

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.net.VpnService
import android.provider.Settings
import androidx.activity.result.ActivityResult
import app.tauri.annotation.ActivityCallback
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import org.json.JSONObject

@InvokeArg
class MobileCommand {
    lateinit var command: String
    lateinit var dataJson: String
}

@TauriPlugin
class HomeProxyPlugin(private val activity: Activity) : Plugin(activity) {
    @Command
    fun execute(invoke: Invoke) {
        val request = invoke.parseArgs(MobileCommand::class.java)
        val args = if (request.dataJson == "null") JSONObject() else JSONObject(request.dataJson)
        val app = activity.applicationContext
        if (request.command.startsWith("update-")) {
            update(invoke, request.command, args)
            return
        }
        MobileRuntime.worker.execute {
            try {
                if (request.command == "enable" && args.getBoolean("enabled")) {
                    MobileRuntime.requireLinked(app)
                    activity.runOnUiThread {
                        val approval = VpnService.prepare(activity)
                        if (approval == null) startVpn(invoke)
                        else startActivityForResult(invoke, approval, "vpnPermission")
                    }
                } else if (request.command == "vpn-settings") {
                    activity.runOnUiThread {
                        try {
                            activity.startActivity(Intent(Settings.ACTION_VPN_SETTINGS))
                            invoke.resolve()
                        } catch (_: Exception) {
                            invoke.reject("Не удалось открыть настройки VPN")
                        }
                    }
                } else if (request.command == "list-apps") {
                    invoke.resolveObject(AndroidApps.list(app))
                } else {
                    invoke.resolve(JSObject(MobileRuntime.command(app, request.command, args).toString()))
                }
            } catch (error: MobileFailure) {
                invoke.reject(error.message ?: "Операция не выполнена")
            } catch (_: Exception) {
                invoke.reject("Операция Android не выполнена")
            }
        }
    }

    private fun update(invoke: Invoke, command: String, args: JSONObject) {
        if (command == "update-permission" || command == "update-confirm") {
            activity.runOnUiThread {
                try {
                    val target = if (command == "update-confirm") AndroidUpdates.confirmation(activity.applicationContext) else Intent(
                        Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, Uri.fromParts("package", activity.packageName, null)
                    )
                    activity.startActivity(target)
                    invoke.resolve()
                } catch (error: MobileFailure) {
                    invoke.reject(error.message ?: "Действие недоступно")
                } catch (_: Exception) {
                    invoke.reject("Не удалось открыть системный установщик Android")
                }
            }
            return
        }
        val app = activity.applicationContext
        AndroidUpdates.worker.execute {
            try {
                val result = when (command) {
                    "update-status" -> AndroidUpdates.status(app)
                    "update-check" -> AndroidUpdates.check(app, args.getString("channel"))
                    "update-install" -> AndroidUpdates.install(app, args.getString("channel"), args.getString("version"))
                    "update-cancel" -> AndroidUpdates.cancel(app)
                    else -> throw MobileFailure("Неизвестное действие обновления")
                }
                invoke.resolve(JSObject(result.toString()))
            } catch (error: MobileFailure) {
                invoke.reject(error.message ?: "Обновление недоступно")
            } catch (_: Exception) {
                invoke.reject("Не удалось проверить или подготовить обновление")
            }
        }
    }

    @ActivityCallback
    fun vpnPermission(invoke: Invoke, result: ActivityResult) {
        if (result.resultCode == Activity.RESULT_OK) startVpn(invoke)
        else invoke.reject("Android не разрешил подключение VPN")
    }

    private fun startVpn(invoke: Invoke) {
        try {
            activity.startForegroundService(Intent(activity, HomeProxyVpnService::class.java))
            MobileRuntime.worker.execute {
                try {
                    invoke.resolve(JSObject(MobileRuntime.status(activity).toString()))
                } catch (_: Exception) {
                    invoke.reject("Не удалось проверить состояние VPN")
                }
            }
        } catch (_: Exception) {
            invoke.reject("Не удалось запустить VPN")
        }
    }
}
