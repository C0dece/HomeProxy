package app.homeproxy.agent

import android.content.Context
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.system.OsConstants
import io.nekohasekai.libbox.ConnectionOwner
import io.nekohasekai.libbox.InterfaceUpdateListener
import io.nekohasekai.libbox.Libbox
import io.nekohasekai.libbox.NetworkInterface
import io.nekohasekai.libbox.NetworkInterfaceIterator
import io.nekohasekai.libbox.PlatformInterface
import io.nekohasekai.libbox.StringIterator
import io.nekohasekai.libbox.TunOptions
import java.lang.reflect.InvocationHandler
import java.lang.reflect.Method
import java.lang.reflect.Proxy
import java.net.InetSocketAddress
import java.net.NetworkInterface as JavaInterface

internal class VpnPlatform(private val vpn: VpnService) : InvocationHandler {
    private val connectivity = vpn.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
    private var tunnel: ParcelFileDescriptor? = null
    private var callback: ConnectivityManager.NetworkCallback? = null
    val platform: PlatformInterface = Proxy.newProxyInstance(
        PlatformInterface::class.java.classLoader, arrayOf(PlatformInterface::class.java), this
    ) as PlatformInterface

    override fun invoke(proxy: Any, method: Method, values: Array<out Any?>?): Any? {
        val args = values.orEmpty()
        return when (method.name) {
            "openTun" -> openTun(args[0] as TunOptions)
            "usePlatformAutoDetectInterfaceControl" -> true
            "autoDetectInterfaceControl" -> {
                check(vpn.protect(args[0] as Int))
                null
            }
            "startDefaultInterfaceMonitor" -> monitor(args[0] as InterfaceUpdateListener)
            "closeDefaultInterfaceMonitor" -> unmonitor()
            "getInterfaces" -> interfaces()
            "findConnectionOwner" -> connectionOwner(args)
            "localDNSTransport", "readWIFIState", "clearDNSCache", "sendNotification",
            "cancelNotification", "startNeighborMonitor", "closeNeighborMonitor", "registerMyInterface" -> null
            "underNetworkExtension", "includeAllNetworks", "usePlatformShell", "usePlatformBridge" -> false
            "tailscaleHostname" -> "homeproxy-android"
            "equals" -> proxy === args[0]
            "hashCode" -> System.identityHashCode(proxy)
            "toString" -> "HomeProxy Android network"
            else -> throw UnsupportedOperationException(method.name)
        }
    }

    private fun openTun(options: TunOptions): Int {
        check(VpnService.prepare(vpn) == null)
        val builder = vpn.Builder().setSession("HomeProxy").setMtu(options.mtu).setMetered(false)
        val addresses = listOf(options.inet4Address, options.inet6Address)
        for (iterator in addresses) {
            while (iterator.hasNext()) iterator.next().let { builder.addAddress(it.address(), it.prefix()) }
        }
        if (options.autoRoute) {
            val dns = options.dnsServerAddress
            while (dns.hasNext()) builder.addDnsServer(dns.next())
            builder.addRoute("0.0.0.0", 0)
            builder.addRoute("::", 0)
        }
        builder.addDisallowedApplication(vpn.packageName)
        val excluded = options.excludePackage
        while (excluded.hasNext()) {
            val name = excluded.next()
            if (AndroidApps.canExclude(vpn, name)) {
                try {
                    builder.addDisallowedApplication(name)
                } catch (_: PackageManager.NameNotFoundException) {
                    // The application can be uninstalled while the VPN is being established.
                }
            }
        }
        val next = builder.establish() ?: error("Android TUN unavailable")
        tunnel?.close()
        tunnel = next
        return next.fd
    }

    private fun physical(): List<Network> = connectivity.allNetworks.filter { network ->
        val capabilities = connectivity.getNetworkCapabilities(network)
        capabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) == true
    }

    private fun monitor(listener: InterfaceUpdateListener): Any? {
        unmonitor()
        fun publish() {
            val actual = physical()
            val best = connectivity.activeNetwork?.takeIf { it in actual } ?: actual.firstOrNull()
            val name = best?.let { connectivity.getLinkProperties(it)?.interfaceName }
            if (best != null && name != null) {
                val index = JavaInterface.getByName(name)?.index ?: return
                val metered = connectivity.getNetworkCapabilities(best)
                    ?.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED) != true
                listener.updateDefaultInterface(name, index, metered, false)
                vpn.setUnderlyingNetworks(arrayOf(best))
            } else {
                listener.updateDefaultInterface("", -1, false, false)
                vpn.setUnderlyingNetworks(null)
            }
        }
        val monitor = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) = publish()
            override fun onLinkPropertiesChanged(network: Network, properties: android.net.LinkProperties) = publish()
            override fun onLost(network: Network) = publish()
        }
        connectivity.registerNetworkCallback(NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN).build(), monitor)
        callback = monitor
        publish()
        return null
    }

    private fun unmonitor(): Any? {
        callback?.let { connectivity.unregisterNetworkCallback(it) }
        callback = null
        return null
    }

    private fun interfaces(): NetworkInterfaceIterator {
        val all = physical().mapNotNull { network ->
            val link = connectivity.getLinkProperties(network) ?: return@mapNotNull null
            val name = link.interfaceName ?: return@mapNotNull null
            val system = JavaInterface.getByName(name) ?: return@mapNotNull null
            val capabilities = connectivity.getNetworkCapabilities(network) ?: return@mapNotNull null
            NetworkInterface().apply {
                this.name = name
                index = system.index
                mtu = system.mtu
                flags = OsConstants.IFF_UP or OsConstants.IFF_RUNNING
                type = when {
                    capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> Libbox.InterfaceTypeWIFI
                    capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> Libbox.InterfaceTypeCellular
                    capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> Libbox.InterfaceTypeEthernet
                    else -> Libbox.InterfaceTypeOther
                }
                addresses = strings(link.linkAddresses.map { it.toString() })
                dnsServer = strings(link.dnsServers.mapNotNull { it.hostAddress })
                gateway = strings(link.routes.filter { it.isDefaultRoute }.mapNotNull { it.gateway?.hostAddress })
                metered = !capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED)
            }
        }.distinctBy { it.index }.iterator()
        return object : NetworkInterfaceIterator {
            override fun hasNext() = all.hasNext()
            override fun next() = all.next()
        }
    }

    private fun connectionOwner(args: Array<out Any?>): ConnectionOwner {
        val uid = connectivity.getConnectionOwnerUid(
            args[0] as Int,
            InetSocketAddress(args[1] as String, args[2] as Int),
            InetSocketAddress(args[3] as String, args[4] as Int)
        )
        check(uid >= 0) { "Android connection owner unavailable" }
        return ConnectionOwner().apply {
            userId = uid
            setAndroidPackageNames(strings(vpn.packageManager.getPackagesForUid(uid)?.toList().orEmpty()))
        }
    }

    fun close() {
        unmonitor()
        tunnel?.close()
        tunnel = null
    }

    private fun strings(list: List<String>): StringIterator {
        val it = list.iterator()
        return object : StringIterator {
            override fun hasNext() = it.hasNext()
            override fun next() = it.next()
            override fun len() = list.size
        }
    }
}
