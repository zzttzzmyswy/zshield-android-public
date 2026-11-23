package top.zztweb.zshield.health

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * `HealthState` / `HealthReader` contract (M4a task card §4 and acceptance §1).
 *
 * The rule being tested is "a value that cannot be read is `null` (or the documented safe fallback),
 * never an exception": the self-check page exists to help the user fix protection, so it must not
 * be the thing that crashes when an OEM build hides a setting.
 */
class HealthStateTest {

    /** A probe that returns configured values, or throws when asked for a "hidden" one. */
    private class FakeProbe(
        private val vpnPermission: Boolean = true,
        // Healthy by default (always-on and lockdown on); the individual tests override what they
        // are about, so "no problems" is the baseline rather than an accident of the defaults.
        private val alwaysOn: Boolean? = true,
        private val lockdown: Boolean? = true,
        private val ignoringBatteryOptimizations: Boolean = true,
        private val notificationsAllowed: Boolean = true,
        private val backgroundRestricted: Boolean = false,
        private val standbyBucket: Int? = 10,
        private val privateDnsStrict: Boolean = false,
        private val throwOn: Set<String> = emptySet(),
    ) : HealthProbe {
        override fun vpnPermission(): Boolean = nonNull("vpnPermission", vpnPermission)
        override fun alwaysOn(): Boolean? = value("alwaysOn", alwaysOn)
        override fun lockdown(): Boolean? = value("lockdown", lockdown)
        override fun ignoringBatteryOptimizations(): Boolean =
            nonNull("ignoringBatteryOptimizations", ignoringBatteryOptimizations)

        override fun notificationsAllowed(): Boolean =
            nonNull("notificationsAllowed", notificationsAllowed)

        override fun backgroundRestricted(): Boolean =
            nonNull("backgroundRestricted", backgroundRestricted)

        override fun standbyBucket(): Int? = value("standbyBucket", standbyBucket)
        override fun privateDnsStrict(): Boolean = nonNull("privateDnsStrict", privateDnsStrict)

        private fun nonNull(name: String, actual: Boolean): Boolean {
            if (name in throwOn) throw IllegalStateException("$name is not readable on this build")
            return actual
        }

        private fun <T> value(name: String, actual: T): T? {
            if (name in throwOn) throw IllegalStateException("$name is not readable on this build")
            return actual
        }
    }

    private fun read(probe: HealthProbe, revoked: Boolean = false) = HealthReader.read(probe, revoked)

    @Test
    fun `a healthy device has nothing to fix`() {
        val state = read(FakeProbe())
        assertTrue(state.vpnPermission)
        assertEquals(true, state.alwaysOn)
        assertEquals(true, state.lockdown)
        assertTrue(state.ignoringBatteryOptimizations)
        assertTrue(state.notificationsAllowed)
        assertFalse(state.backgroundRestricted)
        assertEquals(10, state.standbyBucket)
        assertFalse(state.privateDnsStrict)
        assertFalse(state.revokedBySystem)
        assertTrue("healthy device must report no problems", state.healthy)
        assertEquals(emptyList<HealthItem>(), state.problems)
    }

    @Test
    fun `every failing item is listed once, in fix order`() {
        val state = HealthState(
            vpnPermission = false,
            alwaysOn = false,
            lockdown = false,
            ignoringBatteryOptimizations = false,
            notificationsAllowed = false,
            backgroundRestricted = true,
            standbyBucket = 40,
            privateDnsStrict = true,
            revokedBySystem = true,
        )
        assertEquals(
            listOf(
                HealthItem.REVOKED_BY_SYSTEM,
                HealthItem.VPN_PERMISSION,
                HealthItem.ALWAYS_ON,
                HealthItem.LOCKDOWN,
                HealthItem.BATTERY_OPTIMIZATIONS,
                HealthItem.NOTIFICATIONS,
                HealthItem.BACKGROUND_RESTRICTIONS,
                HealthItem.STANDBY_BUCKET,
                HealthItem.PRIVATE_DNS,
            ),
            state.problems,
        )
        assertFalse(state.healthy)
    }

    @Test
    fun `an unreadable setting is null and not an action item`() {
        // The point of the distinction: "unknown" must not nag the user about something the app
        // cannot even see, and must not be reported as "false" either.
        val state = read(FakeProbe(alwaysOn = null, lockdown = null, standbyBucket = null))
        assertNull(state.alwaysOn)
        assertNull(state.lockdown)
        assertNull(state.standbyBucket)
        assertEquals(emptyList<HealthItem>(), state.problems)
        assertTrue(state.healthy)
    }

    @Test
    fun `a probe that throws degrades to the documented fallback instead of crashing`() {
        val state = read(
            FakeProbe(
                throwOn = setOf(
                    "vpnPermission",
                    "alwaysOn",
                    "lockdown",
                    "ignoringBatteryOptimizations",
                    "notificationsAllowed",
                    "backgroundRestricted",
                    "standbyBucket",
                    "privateDnsStrict",
                ),
            ),
        )
        // Consent is unknown, so the safe next step is the consent dialog.
        assertFalse(state.vpnPermission)
        assertNull(state.alwaysOn)
        assertNull(state.lockdown)
        assertFalse(state.ignoringBatteryOptimizations)
        // These two would nag if a failed read became "false"; they fall back to the quiet answer.
        assertTrue(state.notificationsAllowed)
        assertFalse(state.backgroundRestricted)
        assertNull(state.standbyBucket)
        assertFalse(state.privateDnsStrict)
        // ... and the checklist is still usable rather than empty-or-crashed.
        assertTrue(state.problems.contains(HealthItem.VPN_PERMISSION))
        assertTrue(state.problems.contains(HealthItem.BATTERY_OPTIMIZATIONS))
        assertFalse(state.problems.contains(HealthItem.NOTIFICATIONS))
    }

    @Test
    fun `a low standby bucket is a problem and the workpiece bucket is not`() {
        // The bucket scale is ordered by how much the app is favoured: EXEMPTED/ACTIVE are the good
        // answers, RARE/RESTRICTED/NEVER are the ones that defer the self-check to about once a day.
        for (bucket in listOf(40, 45, 50)) {
            assertTrue(
                "bucket $bucket should be flagged",
                HealthState(standbyBucket = bucket).problems.contains(HealthItem.STANDBY_BUCKET),
            )
        }
        for (bucket in listOf(5, 10, 20, 30, 35)) {
            assertFalse(
                "bucket $bucket should not be flagged",
                HealthState(standbyBucket = bucket).problems.contains(HealthItem.STANDBY_BUCKET),
            )
        }
    }

    @Test
    fun `revocation is reported from the persisted flag not from consent`() {
        // `vpnPermission` can be true again (the user re-granted) while the recorded revocation is
        // what explains why the last run ended; both are shown independently. The healthy probe has
        // always-on and lockdown on, so the revocation is the only stated problem.
        val state = read(
            FakeProbe(vpnPermission = true, alwaysOn = true, lockdown = true, standbyBucket = 10),
            revoked = true,
        )
        assertTrue(state.revokedBySystem)
        assertEquals(listOf(HealthItem.REVOKED_BY_SYSTEM), state.problems)
    }
}
