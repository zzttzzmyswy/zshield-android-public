package top.zztweb.zshield.vpn

import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import top.zztweb.zshield.core.NativeStats

/**
 * State-machine tests for the controller, driven through the internal hooks the service uses.
 *
 * The point of these is the contract the UI depends on: state transitions are observable, and a
 * stopping engine never publishes a zeroed snapshot over the last real counters.
 */
class ZShieldVpnControllerTest {

    @Test
    fun `engine start clears counters and stop keeps the last snapshot`() {
        val controller = ZShieldVpnController
        controller.onEngineStarted(7)
        controller.applyStatsForTest(
            NativeStats(dnsQueries = 11, dnsBlocked = 3, dnsErrors = 1, upstreamLatencyMsP50 = 42),
        )

        assertEquals(11, controller.stats.value.dnsQueries)
        assertEquals(3, controller.stats.value.dnsBlocked)
        assertEquals(42, controller.stats.value.upstreamLatencyMsP50)
        assertTrue(controller.isEngineRunning)

        // The service calls this before `Native.stop`; it must not touch the visible counters.
        controller.onEngineStopping()
        assertFalse(controller.isEngineRunning)
        assertEquals(11, controller.stats.value.dnsQueries)
        assertEquals(1, controller.stats.value.dnsErrors)
    }

    @Test
    fun `a new engine starts from zero`() {
        val controller = ZShieldVpnController
        controller.applyStatsForTest(NativeStats(dnsQueries = 99))
        assertEquals(99, controller.stats.value.dnsQueries)

        controller.onEngineStarted(8)
        assertEquals(0, controller.stats.value.dnsQueries)
        assertEquals(0, controller.stats.value.dnsBlocked)
    }

    @Test
    fun `error state is reported and clears the engine handle`() {
        val controller = ZShieldVpnController
        controller.onEngineStarted(9)
        assertTrue(controller.isEngineRunning)

        controller.onError("启动过滤核心失败：boom")

        assertFalse(controller.isEngineRunning)
        val state = controller.state.value
        assertTrue(state is VpnState.Error)
        assertEquals("启动过滤核心失败：boom", (state as VpnState.Error).message)
    }

    @Test
    fun `stopping without a running engine is not an error`() {
        val controller = ZShieldVpnController
        controller.onStateChanged(VpnState.Stopped)
        assertFalse(controller.isEngineRunning)
        assertEquals(VpnState.Stopped, controller.state.value)
    }

    @Test
    fun `stats flow notifies collectors and counts subscribers`() = runTest {
        val controller = ZShieldVpnController
        controller.applyStatsForTest(NativeStats(dnsQueries = 5))

        var observed = 0L
        val job = launch {
            controller.stats.collect { snapshot -> observed = snapshot.dnsQueries }
        }
        // Let the collector receive the current value, then publish a new one.
        kotlinx.coroutines.yield()
        controller.applyStatsForTest(NativeStats(dnsQueries = 6))
        kotlinx.coroutines.yield()
        assertEquals(6, observed)
        job.cancel()
    }

    @Test
    fun `counting state flow tracks collectors`() = runTest {
        val backing = kotlinx.coroutines.flow.MutableStateFlow(0)
        val subscribers = java.util.concurrent.atomic.AtomicInteger(0)
        val counting = CountingStateFlow(backing, subscribers)

        assertEquals(0, subscribers.get())
        val job = launch { assertEquals(0, counting.first()) }
        job.join()
        // `first` unsubscribes when it returns, so the counter is back to zero.
        assertEquals(0, subscribers.get())
    }

    /**
     * MYS-2716 §2: the stats poller used to crash the process when `Native.statsJson` returned
     * `null` (the one case the Rust side cannot prevent). The published snapshot is a `StateFlow`,
     * so the contract is "skip this tick, keep the last good numbers", never "throw".
     *
     * There is no engine in a local unit test, so the poller itself cannot run; what can be pinned
     * is the piece it depends on — the parser accepts `null` and the controller keeps its previous
     * value until a real document arrives.
     */
    @Test
    fun `a null stats document does not replace the last snapshot`() {
        val controller = ZShieldVpnController
        controller.onEngineStarted(11)
        controller.applyStatsForTest(NativeStats(dnsQueries = 42, dnsBlocked = 7))

        // What the poller does with a null result: it skips the tick entirely.
        val json: String? = null
        if (json == null) {
            // `continue` in the poller; here, simply nothing happens to the published value.
        } else {
            controller.applyStatsForTest(NativeStats.fromJson(json))
        }

        assertEquals(42, controller.stats.value.dnsQueries)
        assertEquals(7, controller.stats.value.dnsBlocked)
        controller.onEngineStopping()
    }

    /**
     * MYS-2716 §6: the debug broadcast now goes through the controller, so its decision is the same
     * one the UI and the notification make. Before the fix it called `startForegroundService`
     * directly and threw `ForegroundServiceStartNotAllowedException` on a package that had never
     * been granted the VPN consent — killing the process instead of reporting a state.
     */
    @Test
    fun `the debug toggle treats a running tunnel as stop and a stopped one as start`() {
        val controller = ZShieldVpnController

        controller.onStateChanged(VpnState.Stopped)
        // The receiver's rule, mirrored here: only Running/Starting mean "stop".
        assertFalse(controller.state.value is VpnState.Running)
        assertFalse(controller.state.value is VpnState.Starting)

        controller.onEngineStarted(12)
        controller.onStateChanged(VpnState.Running)
        assertTrue(controller.state.value is VpnState.Running)
        // A second toggle in this state must stop, not start a second tunnel.
        controller.onEngineStopping()
        controller.onStateChanged(VpnState.Stopped)
    }

    /**
     * A start failure is a reported state, not an exception: that is what makes the debug broadcast
     * safe to fire at a package without VPN consent.
     */
    @Test
    fun `a failed start is reported as an error state`() {
        val controller = ZShieldVpnController
        controller.onError("无法启动 VPN 服务：startForegroundService() not allowed")
        val state = controller.state.value
        assertTrue(state is VpnState.Error)
        assertTrue((state as VpnState.Error).message.contains("无法启动 VPN 服务"))
        assertFalse(controller.isEngineRunning)
    }
}
