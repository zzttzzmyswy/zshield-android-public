package top.zztweb.zshield.ui.health

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import top.zztweb.zshield.health.HealthItem
import top.zztweb.zshield.health.HealthState
import top.zztweb.zshield.ui.health.HealthRows.Group
import top.zztweb.zshield.ui.health.HealthRows.Status

class HealthRowsTest {

    private val healthy = HealthState(
        vpnPermission = true,
        alwaysOn = true,
        lockdown = true,
        ignoringBatteryOptimizations = true,
        notificationsAllowed = true,
        backgroundRestricted = false,
        standbyBucket = 5,
        privateDnsStrict = false,
        revokedBySystem = false,
    )

    @Test
    fun `healthy state lists every item except revoked, all OK`() {
        val rows = HealthRows.rows(healthy)
        assertEquals(HealthItem.entries.size - 1, rows.size)
        assertTrue(rows.none { it.item == HealthItem.REVOKED_BY_SYSTEM })
        assertTrue(rows.all { it.status == Status.OK })
        assertTrue(HealthRows.attention(healthy).isEmpty())
    }

    @Test
    fun `every health item has a group`() {
        HealthItem.entries.forEach { HealthRows.groupOf(it) }
    }

    @Test
    fun `revoked shows first as a required problem`() {
        val rows = HealthRows.rows(healthy.copy(revokedBySystem = true))
        assertEquals(HealthRows.Row(HealthItem.REVOKED_BY_SYSTEM, Group.REQUIRED, Status.PROBLEM), rows.first())
    }

    @Test
    fun `unreadable settings are unknown, not problems`() {
        val state = healthy.copy(alwaysOn = null, lockdown = null, standbyBucket = null)
        val byItem = HealthRows.rows(state).associateBy { it.item }
        assertEquals(Status.UNKNOWN, byItem.getValue(HealthItem.ALWAYS_ON).status)
        assertEquals(Status.UNKNOWN, byItem.getValue(HealthItem.LOCKDOWN).status)
        assertEquals(Status.UNKNOWN, byItem.getValue(HealthItem.STANDBY_BUCKET).status)
        assertTrue(HealthRows.attention(state).isEmpty())
    }

    @Test
    fun `optional problems do not ask for home attention`() {
        val state = healthy.copy(lockdown = false, privateDnsStrict = true, notificationsAllowed = false)
        val byItem = HealthRows.rows(state).associateBy { it.item }
        assertEquals(Status.PROBLEM, byItem.getValue(HealthItem.LOCKDOWN).status)
        assertEquals(Status.PROBLEM, byItem.getValue(HealthItem.PRIVATE_DNS).status)
        assertEquals(Status.PROBLEM, byItem.getValue(HealthItem.NOTIFICATIONS).status)
        assertTrue(HealthRows.attention(state).isEmpty())
    }

    @Test
    fun `keep-alive problems ask for home attention`() {
        val state = healthy.copy(ignoringBatteryOptimizations = false, alwaysOn = false, backgroundRestricted = true)
        assertEquals(
            setOf(HealthItem.BATTERY_OPTIMIZATIONS, HealthItem.ALWAYS_ON, HealthItem.BACKGROUND_RESTRICTIONS),
            HealthRows.attention(state).toSet(),
        )
    }

    @Test
    fun `lockdown is unknown while always-on is unreadable`() {
        val state = healthy.copy(alwaysOn = null, lockdown = false)
        val byItem = HealthRows.rows(state).associateBy { it.item }
        assertEquals(Status.UNKNOWN, byItem.getValue(HealthItem.LOCKDOWN).status)
        assertTrue(HealthItem.LOCKDOWN !in HealthRows.problems(state))
    }

    @Test
    fun `lockdown off with always-on readable is an optional problem`() {
        val state = healthy.copy(alwaysOn = true, lockdown = false)
        assertEquals(listOf(HealthItem.LOCKDOWN), HealthRows.problems(state))
        assertTrue(HealthRows.attention(state).isEmpty())
    }

    @Test
    fun `default state before the first refresh is not healthy`() {
        // The page refreshes on resume; until then the defaults say "no VPN permission", which must
        // surface as a required problem rather than a reassuring all-green list.
        val rows = HealthRows.rows(HealthState()).associateBy { it.item }
        assertEquals(Status.PROBLEM, rows.getValue(HealthItem.VPN_PERMISSION).status)
    }
}
