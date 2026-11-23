package top.zztweb.zshield.vpn

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * The automatic-recovery decision table (M4a task card acceptance §1).
 *
 * Two properties carry the milestone and are asserted exhaustively rather than by example:
 *
 * 1. **`protectionWanted == false` always means "do nothing"**, whatever the trigger, the consent
 *    state or the always-on setting. A recovery path that starts filtering after the user paused it
 *    is the worst failure this feature can have.
 * 2. **`protectionWanted == true` with a missing tunnel and live consent always recovers**, except
 *    when the system owns the tunnel (always-on VPN) — the one case where starting would race the
 *    platform.
 */
class RecoveryPolicyTest {

    private fun input(
        wanted: Boolean = true,
        permission: Boolean = true,
        running: Boolean = false,
        alwaysOn: Boolean? = false,
        trigger: RecoveryTrigger = RecoveryTrigger.BOOT,
    ) = RecoveryInput(wanted, permission, running, alwaysOn, trigger)

    @Test
    fun `a user who turned protection off is never resurrected`() {
        // Every trigger, every combination of the other inputs: "no" stays "no".
        for (trigger in RecoveryTrigger.entries) {
            for (permission in listOf(true, false)) {
                for (alwaysOn in listOf(true, false, null)) {
                    for (running in listOf(true, false)) {
                        val outcome = RecoveryPolicy.decide(
                            input(
                                wanted = false,
                                permission = permission,
                                running = running,
                                alwaysOn = alwaysOn,
                                trigger = trigger,
                            ),
                        )
                        assertEquals(
                            "wanted=false must not recover (trigger=$trigger permission=$permission " +
                                "alwaysOn=$alwaysOn running=$running)",
                            RecoveryOutcome.USER_TURNED_OFF,
                            outcome,
                        )
                    }
                }
            }
        }
    }

    @Test
    fun `a wanted tunnel that is gone recovers on every trigger`() {
        for (trigger in RecoveryTrigger.entries) {
            assertEquals(
                "trigger=$trigger",
                RecoveryOutcome.RECOVER,
                RecoveryPolicy.decide(input(trigger = trigger)),
            )
        }
    }

    @Test
    fun `an always-on VPN is left to the system`() {
        // The platform starts an always-on VPN itself, including at boot; a second establish would
        // race the interface the user's traffic is on.
        for (trigger in RecoveryTrigger.entries) {
            assertEquals(
                "trigger=$trigger",
                RecoveryOutcome.MANAGED_BY_SYSTEM,
                RecoveryPolicy.decide(input(alwaysOn = true, trigger = trigger)),
            )
        }
    }

    @Test
    fun `an unreadable always-on setting does not block recovery`() {
        // `null` means "the platform would not tell us". Refusing to recover on `null` would leave
        // the app permanently off on builds that hide the key, which is worse than one redundant
        // start the service serialises anyway.
        assertEquals(RecoveryOutcome.RECOVER, RecoveryPolicy.decide(input(alwaysOn = null)))
        assertEquals(RecoveryOutcome.RECOVER, RecoveryPolicy.decide(input(alwaysOn = false)))
    }

    @Test
    fun `a live tunnel is not established twice`() {
        for (trigger in RecoveryTrigger.entries) {
            assertEquals(
                "trigger=$trigger",
                RecoveryOutcome.ALREADY_RUNNING,
                RecoveryPolicy.decide(input(running = true, trigger = trigger)),
            )
        }
    }

    @Test
    fun `missing consent is reported instead of attempted`() {
        assertEquals(
            RecoveryOutcome.NO_VPN_PERMISSION,
            RecoveryPolicy.decide(input(permission = false)),
        )
    }

    @Test
    fun `the outcome order is intent first, then running, then consent, then the system`() {
        // "Wanted but running with no consent" is a live tunnel whose consent was just revoked: the
        // truthful answer is that it is already running (the service handles the revocation), not
        // that recovery should start.
        assertEquals(
            RecoveryOutcome.ALREADY_RUNNING,
            RecoveryPolicy.decide(input(permission = false, running = true)),
        )
        // Consent beats always-on: with no consent there is nothing the system could start either.
        assertEquals(
            RecoveryOutcome.NO_VPN_PERMISSION,
            RecoveryPolicy.decide(input(permission = false, alwaysOn = true)),
        )
    }
}
