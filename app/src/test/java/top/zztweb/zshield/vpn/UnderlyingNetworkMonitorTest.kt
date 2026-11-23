package top.zztweb.zshield.vpn

import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The restart decision behind MYS-2710: the tunnel is rebuilt exactly once when IPv6 availability
 * changes, and never when it does not.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class UnderlyingNetworkMonitorTest {

    private val debounce = 2_000L

    @Test
    fun `a change in availability schedules one restart after the debounce`() = runTest {
        var restarts = 0
        val monitor = UnderlyingNetworkMonitor(
            scope = this,
            debounceMillis = debounce,
            restart = { restarts++ },
        )
        monitor.onTunnelEstablished(ipv6 = false)

        monitor.onAvailabilityChanged(true)
        advanceTimeBy(debounce - 1)
        assertEquals("the restart must wait for the link to settle", 0, restarts)

        advanceUntilIdle()
        assertEquals(1, restarts)
    }

    @Test
    fun `unchanged availability never rebuilds`() = runTest {
        var restarts = 0
        val monitor = UnderlyingNetworkMonitor(
            scope = this,
            debounceMillis = debounce,
            restart = { restarts++ },
        )
        monitor.onTunnelEstablished(ipv6 = false)

        // A link-property change that does not touch availability (new DNS server, new MTU, an
        // address renewal) reports the same value; the tunnel is already correct for it.
        repeat(5) { assertFalse(monitor.onAvailabilityChanged(false)) }
        advanceUntilIdle()

        assertEquals(0, restarts)
    }

    @Test
    fun `unchanged availability cancels a restart scheduled by a blip`() = runTest {
        var restarts = 0
        val monitor = UnderlyingNetworkMonitor(
            scope = this,
            debounceMillis = debounce,
            restart = { restarts++ },
        )
        monitor.onTunnelEstablished(ipv6 = true)

        // A momentary report of "no IPv6" (the link is re-negotiating) must not tear the tunnel
        // down, because the next observation inside the debounce window says otherwise.
        assertTrue(monitor.onAvailabilityChanged(false))
        advanceTimeBy(500)
        assertFalse(monitor.onAvailabilityChanged(true))
        advanceUntilIdle()

        assertEquals(0, restarts)
    }

    @Test
    fun `repeated changes inside the debounce window produce a single restart`() = runTest {
        var restarts = 0
        val monitor = UnderlyingNetworkMonitor(
            scope = this,
            debounceMillis = debounce,
            restart = { restarts++ },
        )
        monitor.onTunnelEstablished(ipv6 = false)

        assertTrue(monitor.onAvailabilityChanged(true))
        advanceTimeBy(200)
        // Still pending: a second observation must not queue a second rebuild.
        assertTrue(monitor.onAvailabilityChanged(true))
        advanceUntilIdle()

        assertEquals(1, restarts)
    }

    @Test
    fun `a fresh tunnel cancels the restart scheduled against the old one`() = runTest {
        var restarts = 0
        val monitor = UnderlyingNetworkMonitor(
            scope = this,
            debounceMillis = debounce,
            restart = { restarts++ },
        )
        monitor.onTunnelEstablished(ipv6 = false)
        monitor.onAvailabilityChanged(true)

        // The UI or the platform already rebuilt the tunnel (for another reason) with the new
        // value; rebuilding again would be a pointless second outage.
        monitor.onTunnelEstablished(ipv6 = true)
        advanceUntilIdle()

        assertEquals(0, restarts)
    }

    @Test
    fun `availability can flip back and forth and the tunnel follows once per change`() = runTest {
        var restarts = 0
        val monitor = UnderlyingNetworkMonitor(
            scope = this,
            debounceMillis = debounce,
            restart = { restarts++ },
        )
        monitor.onTunnelEstablished(ipv6 = false)

        monitor.onAvailabilityChanged(true)
        advanceUntilIdle()
        assertEquals(1, restarts)

        // A restart does not tell the monitor what the new tunnel ended up with (the service does,
        // through `onTunnelEstablished`), so simulate that hand-off here.
        monitor.onTunnelEstablished(ipv6 = true)
        monitor.onAvailabilityChanged(false)
        advanceUntilIdle()
        assertEquals(2, restarts)
    }
}
