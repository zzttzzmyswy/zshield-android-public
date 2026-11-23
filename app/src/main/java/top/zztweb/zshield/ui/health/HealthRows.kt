package top.zztweb.zshield.ui.health

import top.zztweb.zshield.health.HealthItem
import top.zztweb.zshield.health.HealthState

/**
 * How the self-check page groups and judges [HealthState], kept free of Android and Compose so the
 * grouping rules are unit-tested on the JVM.
 *
 * The groups encode one product decision: only [Group.REQUIRED] and [Group.KEEP_ALIVE] decide
 * whether the home screen should ask for attention. [Group.OPTIONAL] items (lockdown, strict
 * Private DNS, notifications) are worth explaining, but none of them stops protection from running:
 * a user who leaves lockdown off or silences the notification is not "broken", and a permanent home
 * banner for it would be noise. (Strict Private DNS already has its own home banner.)
 */
object HealthRows {

    enum class Group { REQUIRED, KEEP_ALIVE, OPTIONAL }

    /** Per-row verdict. [UNKNOWN] is the `null` read: shown, never counted as a problem. */
    enum class Status { OK, PROBLEM, UNKNOWN }

    data class Row(val item: HealthItem, val group: Group, val status: Status)

    /** Page order: what stops protection, then what lets the system kill it, then the extras. */
    private val layout: List<Pair<HealthItem, Group>> = listOf(
        HealthItem.REVOKED_BY_SYSTEM to Group.REQUIRED,
        HealthItem.VPN_PERMISSION to Group.REQUIRED,
        HealthItem.BATTERY_OPTIMIZATIONS to Group.KEEP_ALIVE,
        HealthItem.ALWAYS_ON to Group.KEEP_ALIVE,
        HealthItem.BACKGROUND_RESTRICTIONS to Group.KEEP_ALIVE,
        HealthItem.STANDBY_BUCKET to Group.KEEP_ALIVE,
        HealthItem.LOCKDOWN to Group.OPTIONAL,
        HealthItem.PRIVATE_DNS to Group.OPTIONAL,
        HealthItem.NOTIFICATIONS to Group.OPTIONAL,
    )

    fun groupOf(item: HealthItem): Group = layout.first { it.first == item }.second

    /**
     * Every row the page draws. "Revoked by the system" is only a row while it is true: when the
     * VPN was never taken away there is nothing to say about it, and a permanently green
     * "not revoked" line would only lengthen the list.
     */
    fun rows(state: HealthState): List<Row> {
        val problems = state.problems.toSet()
        return layout.mapNotNull { (item, group) ->
            val status = when {
                unreadable(item, state) -> Status.UNKNOWN
                item in problems -> Status.PROBLEM
                else -> Status.OK
            }
            if (item == HealthItem.REVOKED_BY_SYSTEM && status != Status.PROBLEM) null else Row(item, group, status)
        }
    }

    /** Items the page marks as problems — the count every entry point shows. */
    fun problems(state: HealthState): List<HealthItem> =
        rows(state).filter { it.status == Status.PROBLEM }.map { it.item }

    /** Problems that justify a home-screen banner; optional items deliberately excluded. */
    fun attention(state: HealthState): List<HealthItem> =
        problems(state).filter { groupOf(it) != Group.OPTIONAL }

    /**
     * True when a `null` read means the page cannot judge this item.
     *
     * Lockdown is a sub-option of always-on and is guarded by the same platform restriction, so when
     * always-on cannot be read a "lockdown off" answer is not evidence of anything: on the API 36
     * emulator the always-on key throws while the lockdown key reads as absent, which would otherwise
     * show a confident "off" next to an "unknown" parent.
     */
    private fun unreadable(item: HealthItem, state: HealthState): Boolean = when (item) {
        HealthItem.ALWAYS_ON -> state.alwaysOn == null
        HealthItem.LOCKDOWN -> state.lockdown == null || state.alwaysOn == null
        HealthItem.STANDBY_BUCKET -> state.standbyBucket == null
        else -> false
    }
}
