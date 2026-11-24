package app.homeproxy.agent

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.drawable.Drawable
import android.os.Build
import android.util.Base64
import java.io.ByteArrayOutputStream
import java.text.Collator

internal object AndroidApps {
    @Suppress("DEPRECATION")
    fun canExclude(context: Context, name: String): Boolean {
        if (name == context.packageName) return false
        return try {
            val manager = context.packageManager
            val info = manager.getPackageInfo(name, 0)
            val uid = info.applicationInfo?.uid ?: return false
            info.sharedUserId == null && manager.getPackagesForUid(uid)?.singleOrNull() == name
        } catch (_: PackageManager.NameNotFoundException) {
            false
        }
    }

    fun list(context: Context): List<Map<String, String>> {
        val manager = context.packageManager
        val launcher = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        @Suppress("DEPRECATION")
        val entries = if (Build.VERSION.SDK_INT >= 33) {
            manager.queryIntentActivities(launcher, PackageManager.ResolveInfoFlags.of(0))
        } else {
            manager.queryIntentActivities(launcher, 0)
        }
        val order = Collator.getInstance()
        return entries.asSequence()
            .map { it.activityInfo.applicationInfo }
            .filter { it.packageName != context.packageName }
            .distinctBy { it.packageName }
            .map { info ->
                mapOf(
                    "name" to info.loadLabel(manager).toString(),
                    "path" to info.packageName,
                    "icon" to thumbnail(info.loadIcon(manager)),
                )
            }
            .sortedWith(compareBy(order) { it.getValue("name") })
            .toList()
    }

    private fun thumbnail(drawable: Drawable): String {
        val bitmap = Bitmap.createBitmap(48, 48, Bitmap.Config.ARGB_8888)
        return try {
            drawable.setBounds(0, 0, bitmap.width, bitmap.height)
            drawable.draw(Canvas(bitmap))
            val png = ByteArrayOutputStream()
            bitmap.compress(Bitmap.CompressFormat.PNG, 100, png)
            "data:image/png;base64," + Base64.encodeToString(png.toByteArray(), Base64.NO_WRAP)
        } finally {
            bitmap.recycle()
        }
    }
}
