package top.zztweb.zshield.vpn

import android.net.LinkProperties
import java.net.Inet6Address
import java.net.InetAddress

/**
 * A single address assigned to the underlying interface, reduced to what the IPv6 decision needs.
 *
 * The real input is `LinkProperties.linkAddresses`; keeping the decision over this simplified shape
 * is what makes it testable on the JVM without a device (task card §1).
 */
data class IpAddressEntry(
    /** Numeric address, e.g. `fe80::1` or `240e:83:205:1cd::1`. A `%scope` suffix is ignored. */
    val address: String,
    val prefixLength: Int = 64,
)

/** A single route of the underlying interface, reduced to destination and prefix length. */
data class IpRouteEntry(
    /** Numeric destination, e.g. `::` for the IPv6 default route or `0.0.0.0` for IPv4. */
    val destination: String,
    val prefixLength: Int,
)

/**
 * Whether the network *underneath* the tunnel can carry IPv6.
 *
 * # Why this decides the tunnel's shape
 *
 * A tunnel that advertises IPv6 (TUN address `fd00:7a73::1`, `::/0`) while the link below it has
 * no IPv6 default route makes dual-stack sites unreachable: the client resolves AAAA, connects to
 * the virtual IPv6 address, the local handshake succeeds, and the outbound connection then fails
 * with `Network is unreachable`. Clients do not fall back to IPv4 after a completed TCP handshake,
 * so the page simply breaks (MYS-2710). The tunnel therefore only carries IPv6 when the link under
 * it really does.
 *
 * "Really does" means both halves must hold, because either one alone is not enough:
 * * a **global unicast** source address — without one the stack cannot originate IPv6 traffic
 *   (a link-local `fe80::/10` address alone is what an IPv6-less Wi-Fi still shows);
 * * an **IPv6 default route** (`::/0`) — without one there is nowhere to send the packets.
 */
object Ipv6Availability {

    /**
     * The whole decision: a global unicast IPv6 address **and** an IPv6 default route.
     *
     * Pure by construction, so the acceptance cases (link-local only, no default route, both
     * present, ULA) are unit tests rather than device experiments.
     */
    fun isAvailable(addresses: List<IpAddressEntry>, routes: List<IpRouteEntry>): Boolean =
        addresses.any { isGlobalUnicastIpv6(it.address) } && hasIpv6DefaultRoute(routes)

    /**
     * True when [address] is an IPv6 address the interface could originate traffic from.
     *
     * Excluded (RFC 4291 / RFC 6890): the unspecified address, loopback, multicast, link-local,
     * the deprecated site-local range, IPv4-mapped addresses and ULA `fc00::/7`. ULA is excluded on
     * purpose: `fd00::/8` is exactly the tunnel's own address range, and an underlying network that
     * only hands out ULA cannot reach the IPv6 internet either.
     */
    fun isGlobalUnicastIpv6(address: String): Boolean {
        val bytes = parseIpv6(address) ?: return false
        // :: (unspecified) and ::1 (loopback)
        if (bytes.all { it == 0.toByte() }) return false
        if (bytes.take(15).all { it == 0.toByte() } && bytes[15] == 1.toByte()) return false
        // ::ffff:0:0/96 — an IPv4 address wearing an IPv6 hat.
        if (bytes.take(10).all { it == 0.toByte() } &&
            bytes[10] == 0xff.toByte() &&
            bytes[11] == 0xff.toByte()
        ) {
            return false
        }
        val first = bytes[0].toInt() and 0xff
        val second = bytes[1].toInt() and 0xff
        // ff00::/8 multicast
        if (first == 0xff) return false
        // fe80::/10 link-local and fec0::/10 site-local: not globally reachable.
        if (first == 0xfe && (second and 0xc0) != 0x00) return false
        // fc00::/7 unique local (fd00::/8 is the tunnel's own range).
        if ((first and 0xfe) == 0xfc) return false
        return true
    }

    /** True when [routes] contains an IPv6 default route (`::/0`). */
    fun hasIpv6DefaultRoute(routes: List<IpRouteEntry>): Boolean =
        routes.any { route ->
            route.prefixLength == 0 && parseIpv6(route.destination) != null
        }

    /**
     * Reads the decision out of the platform's description of the underlying link.
     *
     * `null` (no network, no `ConnectivityManager`) means "cannot tell", which is answered
     * conservatively as *no IPv6*: an IPv4-only tunnel always works, whereas a wrong "IPv6
     * available" is the outage this whole class exists to prevent.
     */
    fun fromLinkProperties(properties: LinkProperties?): Boolean {
        if (properties == null) return false
        val addresses = properties.linkAddresses.mapNotNull { linkAddress ->
            val host = linkAddress.address?.hostAddress ?: return@mapNotNull null
            IpAddressEntry(stripScope(host), linkAddress.prefixLength)
        }
        val routes = properties.routes.mapNotNull { route ->
            val destination = route.destination ?: return@mapNotNull null
            val host = destination.address?.hostAddress ?: return@mapNotNull null
            IpRouteEntry(stripScope(host), destination.prefixLength)
        }
        return isAvailable(addresses, routes)
    }

    /**
     * Parses a numeric IPv6 address, or returns `null`.
     *
     * The `':'` requirement keeps [InetAddress.getByName] from ever treating the input as a
     * hostname — this runs on the query path's decision, and a DNS lookup here would be both wrong
     * and slow.
     */
    private fun parseIpv6(address: String): ByteArray? {
        val candidate = stripScope(address.trim())
        if (!candidate.contains(':')) return null
        val parsed = runCatching { InetAddress.getByName(candidate) }.getOrNull() ?: return null
        return (parsed as? Inet6Address)?.address
    }

    /** `fe80::1%wlan0` and `fe80::1` describe the same address for this decision. */
    private fun stripScope(address: String): String {
        val percent = address.indexOf('%')
        return if (percent >= 0) address.substring(0, percent) else address
    }
}
