package top.zztweb.zshield.vpn

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The IPv6-availability decision behind MYS-2710.
 *
 * Every case here is a shape a real Android link reports: a Wi-Fi network with only a link-local
 * address (the Pixel 5 the bug was found on), a link with a global address but no default route, a
 * dual-stack link, and the ULA range that the tunnel itself uses.
 */
class Ipv6AvailabilityTest {

    private fun addresses(vararg address: String) = address.map { IpAddressEntry(it, 64) }

    private val ipv6DefaultRoute = IpRouteEntry("::", 0)
    private val ipv4DefaultRoute = IpRouteEntry("0.0.0.0", 0)

    @Test
    fun `link-local address alone is not enough`() {
        // Exactly the Pixel 5's Wi-Fi before the fix: `inet6 fe80::...` and no IPv6 default route.
        assertFalse(
            Ipv6Availability.isAvailable(
                addresses("fe80::24c2:9cd7:bbf:ce99"),
                listOf(ipv4DefaultRoute),
            ),
        )
    }

    @Test
    fun `global address without an ipv6 default route is not enough`() {
        assertFalse(
            Ipv6Availability.isAvailable(
                addresses("240e:83:205:1cd::1"),
                listOf(ipv4DefaultRoute),
            ),
        )
    }

    @Test
    fun `default route without a global address is not enough`() {
        assertFalse(
            Ipv6Availability.isAvailable(
                addresses("fe80::1"),
                listOf(ipv6DefaultRoute, ipv4DefaultRoute),
            ),
        )
    }

    @Test
    fun `global address plus ipv6 default route is available`() {
        assertTrue(
            Ipv6Availability.isAvailable(
                addresses("240e:83:205:1cd::1"),
                listOf(ipv6DefaultRoute, ipv4DefaultRoute),
            ),
        )
    }

    @Test
    fun `ula is not a global address`() {
        // fd00::/8 is the tunnel's own range; a link that only hands out ULA cannot reach the
        // IPv6 internet either, so it must not make the tunnel advertise IPv6.
        assertFalse(Ipv6Availability.isGlobalUnicastIpv6("fd00:7a73::1"))
        assertFalse(Ipv6Availability.isGlobalUnicastIpv6("fc00::1"))
        assertFalse(Ipv6Availability.isGlobalUnicastIpv6("fdff:ffff::1"))
        assertFalse(
            Ipv6Availability.isAvailable(
                addresses("fd12:3456:789a::1"),
                listOf(ipv6DefaultRoute),
            ),
        )
        // …while a neighbouring range is still global.
        assertTrue(Ipv6Availability.isGlobalUnicastIpv6("2400:3200::1"))
        assertTrue(Ipv6Availability.isGlobalUnicastIpv6("2001:db8::1"))
    }

    @Test
    fun `special purpose addresses are rejected`() {
        assertFalse(Ipv6Availability.isGlobalUnicastIpv6("::"))
        assertFalse(Ipv6Availability.isGlobalUnicastIpv6("::1"))
        assertFalse(Ipv6Availability.isGlobalUnicastIpv6("ff02::1"))
        assertFalse(Ipv6Availability.isGlobalUnicastIpv6("fec0::1"))
        assertFalse(Ipv6Availability.isGlobalUnicastIpv6("::ffff:192.0.2.1"))
        // Not an address at all.
        assertFalse(Ipv6Availability.isGlobalUnicastIpv6("example.com"))
        assertFalse(Ipv6Availability.isGlobalUnicastIpv6(""))
        assertFalse(Ipv6Availability.isGlobalUnicastIpv6("10.0.0.1"))
    }

    @Test
    fun `scope suffixes do not change the answer`() {
        assertFalse(Ipv6Availability.isGlobalUnicastIpv6("fe80::1%wlan0"))
        assertTrue(Ipv6Availability.isGlobalUnicastIpv6("240e:83::1%rmnet0"))
        assertTrue(
            Ipv6Availability.hasIpv6DefaultRoute(listOf(IpRouteEntry("::%rmnet0", 0))),
        )
    }

    @Test
    fun `only a default route counts as an ipv6 default route`() {
        assertTrue(Ipv6Availability.hasIpv6DefaultRoute(listOf(IpRouteEntry("::", 0))))
        assertFalse(Ipv6Availability.hasIpv6DefaultRoute(listOf(IpRouteEntry("::", 1))))
        assertFalse(Ipv6Availability.hasIpv6DefaultRoute(listOf(IpRouteEntry("fe80::", 64))))
        assertFalse(Ipv6Availability.hasIpv6DefaultRoute(listOf(ipv4DefaultRoute)))
        // A default route for the wrong family must not be mistaken for IPv6.
        assertFalse(Ipv6Availability.hasIpv6DefaultRoute(emptyList()))
    }

    @Test
    fun `no network information means no ipv6`() {
        // Conservative on purpose: an IPv4-only tunnel always works, while a wrong "IPv6
        // available" is the outage this decision prevents.
        assertFalse(Ipv6Availability.fromLinkProperties(null))
        assertFalse(Ipv6Availability.isAvailable(emptyList(), emptyList()))
    }
}
