package top.zztweb.zshield.ui.health

import android.content.ActivityNotFoundException
import android.content.Context
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.LifecycleResumeEffect
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import top.zztweb.zshield.R
import top.zztweb.zshield.health.HealthItem
import top.zztweb.zshield.health.ProtectionHealth
import top.zztweb.zshield.ui.components.GroupCard
import top.zztweb.zshield.ui.components.MaxContentWidth
import top.zztweb.zshield.ui.components.PageMargin
import top.zztweb.zshield.ui.components.SectionHeader
import top.zztweb.zshield.ui.health.HealthRows.Group
import top.zztweb.zshield.ui.health.HealthRows.Status
import top.zztweb.zshield.ui.theme.AppIcons
import top.zztweb.zshield.ui.theme.LocalStatusColors

/**
 * The protection self-check: every system setting that decides whether protection can start and
 * keep running, each with its verdict and a direct way to the page that fixes it.
 *
 * It reads [ProtectionHealth] when the page resumes — which is also what makes it re-check after the
 * user comes back from a settings page — and never on a timer (`docs/KEEPALIVE.md` §4).
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HealthScreen(onBack: () -> Unit, startProtection: () -> Unit) {
    val context = LocalContext.current
    val state by ProtectionHealth.state.collectAsStateWithLifecycle()
    LifecycleResumeEffect(Unit) {
        ProtectionHealth.refresh(context)
        onPauseOrDispose { }
    }
    BackHandler(onBack = onBack)

    val rows = HealthRows.rows(state)
    val scrollBehavior = TopAppBarDefaults.pinnedScrollBehavior()

    fun onRow(row: HealthRows.Row) {
        when {
            // The consent dialog cannot be reached through a settings Intent; starting protection
            // is what shows it (and clears the "revoked" mark, see AppSettings.setProtectionWanted).
            row.status == Status.PROBLEM &&
                (row.item == HealthItem.VPN_PERMISSION || row.item == HealthItem.REVOKED_BY_SYSTEM) ->
                startProtection()
            // Once exempt, the "ignore battery optimizations" request finishes without showing
            // anything; the app details page is where the user can see or undo the exemption.
            row.status != Status.PROBLEM && row.item == HealthItem.BATTERY_OPTIMIZATIONS ->
                openSettings(context, HealthItem.BACKGROUND_RESTRICTIONS)
            else -> openSettings(context, row.item)
        }
    }

    Scaffold(
        modifier = Modifier.nestedScroll(scrollBehavior.nestedScrollConnection),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.ui_health_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = stringResource(R.string.ui_back))
                    }
                },
                actions = {
                    IconButton(onClick = { ProtectionHealth.refresh(context) }) {
                        Icon(Icons.Filled.Refresh, contentDescription = stringResource(R.string.ui_health_recheck))
                    }
                },
                scrollBehavior = scrollBehavior,
            )
        },
    ) { inner ->
        Box(Modifier.fillMaxSize().padding(inner), contentAlignment = Alignment.TopCenter) {
            Column(
                Modifier
                    .widthIn(max = MaxContentWidth)
                    .fillMaxWidth()
                    .verticalScroll(rememberScrollState())
                    .padding(bottom = 24.dp),
            ) {
                SummaryCard(rows)
                Group.entries.forEach { group ->
                    val inGroup = rows.filter { it.group == group }
                    if (inGroup.isEmpty()) return@forEach
                    SectionHeader(stringResource(group.title()))
                    GroupCard {
                        inGroup.forEachIndexed { index, row ->
                            if (index > 0) RowDivider()
                            CheckRow(row = row, onClick = { onRow(row) })
                        }
                    }
                }
                Text(
                    stringResource(R.string.ui_health_footer),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(horizontal = PageMargin + 4.dp, vertical = 16.dp),
                )
            }
        }
    }
}

/** Overall verdict: required problems > keep-alive problems > only optional ones > all good. */
@Composable
private fun SummaryCard(rows: List<HealthRows.Row>) {
    val colors = MaterialTheme.colorScheme
    val status = LocalStatusColors.current
    val problems = rows.filter { it.status == Status.PROBLEM }
    val required = problems.count { it.group == Group.REQUIRED }
    val attention = problems.count { it.group != Group.OPTIONAL }
    val optional = problems.size - attention

    val (title, body) = when {
        required > 0 -> stringResource(R.string.ui_health_summary_required) to
            stringResource(R.string.ui_health_summary_required_body)
        attention > 0 -> stringResource(R.string.ui_health_summary_attention, attention) to
            stringResource(R.string.ui_health_summary_attention_body)
        optional > 0 -> stringResource(R.string.ui_health_summary_optional) to
            stringResource(R.string.ui_health_summary_optional_body, optional)
        else -> stringResource(R.string.ui_health_summary_ok) to
            stringResource(R.string.ui_health_summary_ok_body)
    }
    val (badgeBg, badgeFg, icon) = when {
        required > 0 -> Triple(colors.errorContainer, colors.onErrorContainer, Icons.Filled.Warning)
        attention > 0 -> Triple(status.warningContainer, status.onWarningContainer, Icons.Filled.Warning)
        else -> Triple(status.goodContainer, status.onGoodContainer, AppIcons.ShieldCheck)
    }

    Surface(
        shape = RoundedCornerShape(24.dp),
        color = colors.surfaceContainerLow,
        modifier = Modifier.fillMaxWidth().padding(horizontal = PageMargin, vertical = 4.dp),
    ) {
        Row(Modifier.padding(horizontal = 20.dp, vertical = 20.dp), verticalAlignment = Alignment.CenterVertically) {
            Surface(shape = CircleShape, color = badgeBg, contentColor = badgeFg, modifier = Modifier.size(52.dp)) {
                Icon(icon, contentDescription = null, modifier = Modifier.padding(13.dp))
            }
            Spacer(Modifier.width(16.dp))
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text(title, style = MaterialTheme.typography.titleMedium)
                Text(body, style = MaterialTheme.typography.bodyMedium, color = colors.onSurfaceVariant)
            }
        }
    }
}

/**
 * One check. The status mark pairs colour with a glyph and a spoken state, so the verdict is never
 * colour-only; a problem row also gets an explicit action button, the others stay tappable so the
 * user can still reach the setting (to undo it, or to look at an unreadable one).
 */
@Composable
private fun CheckRow(row: HealthRows.Row, onClick: () -> Unit) {
    val colors = MaterialTheme.colorScheme
    val text = row.item.text()
    val stateLabel = stringResource(
        when (row.status) {
            Status.OK -> R.string.ui_health_status_ok
            Status.PROBLEM -> R.string.ui_health_status_problem
            Status.UNKNOWN -> R.string.ui_health_status_unknown
        },
    )
    val body = when (row.status) {
        Status.OK -> stringResource(text.ok)
        Status.PROBLEM -> stringResource(text.problem)
        Status.UNKNOWN -> stringResource(R.string.ui_health_unknown_body)
    }
    val problem = row.status == Status.PROBLEM

    Row(
        Modifier
            .fillMaxWidth()
            .then(if (problem) Modifier else Modifier.clickable(role = Role.Button, onClick = onClick))
            .semantics(mergeDescendants = !problem) { stateDescription = stateLabel }
            .padding(start = 16.dp, end = 12.dp, top = 14.dp, bottom = 14.dp),
        verticalAlignment = Alignment.Top,
    ) {
        StatusMark(row)
        Spacer(Modifier.width(14.dp))
        Column(Modifier.weight(1f).padding(top = 3.dp)) {
            Text(stringResource(text.title), style = MaterialTheme.typography.titleSmall, color = colors.onSurface)
            Spacer(Modifier.height(2.dp))
            Text(body, style = MaterialTheme.typography.bodyMedium, color = colors.onSurfaceVariant)
            if (problem) {
                Spacer(Modifier.height(10.dp))
                FilledTonalButton(onClick = onClick) { Text(stringResource(text.action)) }
            }
        }
        if (!problem) {
            Icon(
                Icons.AutoMirrored.Filled.KeyboardArrowRight,
                contentDescription = null,
                tint = colors.onSurfaceVariant,
                modifier = Modifier.padding(start = 8.dp).offset(y = 8.dp),
            )
        }
    }
}

/** 28 dp disc: check on the "good" container, "!" on warning/error, "?" when unreadable. */
@Composable
private fun StatusMark(row: HealthRows.Row) {
    val colors = MaterialTheme.colorScheme
    val status = LocalStatusColors.current
    val (bg, fg) = when (row.status) {
        Status.OK -> status.goodContainer to status.onGoodContainer
        Status.UNKNOWN -> colors.surfaceContainerHighest to colors.onSurfaceVariant
        Status.PROBLEM -> when (row.group) {
            Group.REQUIRED -> colors.errorContainer to colors.onErrorContainer
            Group.KEEP_ALIVE -> status.warningContainer to status.onWarningContainer
            Group.OPTIONAL -> colors.surfaceContainerHighest to colors.onSurface
        }
    }
    Surface(shape = CircleShape, color = bg, contentColor = fg, modifier = Modifier.size(28.dp)) {
        Box(contentAlignment = Alignment.Center) {
            when (row.status) {
                Status.OK -> Icon(Icons.Filled.Check, contentDescription = null, modifier = Modifier.size(16.dp))
                Status.PROBLEM -> Text("!", style = MaterialTheme.typography.labelLarge)
                Status.UNKNOWN -> Text("?", style = MaterialTheme.typography.labelLarge)
            }
        }
    }
}

@Composable
private fun RowDivider() {
    HorizontalDivider(
        Modifier.padding(start = 58.dp, end = 16.dp),
        color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f),
    )
}

private fun Group.title(): Int = when (this) {
    Group.REQUIRED -> R.string.ui_health_section_required
    Group.KEEP_ALIVE -> R.string.ui_health_section_keep_alive
    Group.OPTIONAL -> R.string.ui_health_section_optional
}

/** The item's display name; shared with the home banner so both say the same thing. */
fun healthItemTitle(item: HealthItem): Int = item.text().title

/** String resources for one item: its name, both verdict lines and the fix button. */
private class ItemText(val title: Int, val ok: Int, val problem: Int, val action: Int)

private fun HealthItem.text(): ItemText = when (this) {
    HealthItem.REVOKED_BY_SYSTEM -> ItemText(
        R.string.ui_health_revoked, R.string.ui_health_revoked_problem,
        R.string.ui_health_revoked_problem, R.string.ui_health_turn_on,
    )
    HealthItem.VPN_PERMISSION -> ItemText(
        R.string.ui_health_vpn, R.string.ui_health_vpn_ok, R.string.ui_health_vpn_problem, R.string.ui_health_turn_on,
    )
    HealthItem.BATTERY_OPTIMIZATIONS -> ItemText(
        R.string.ui_health_battery, R.string.ui_health_battery_ok,
        R.string.ui_health_battery_problem, R.string.ui_health_allow_background,
    )
    HealthItem.ALWAYS_ON -> ItemText(
        R.string.ui_health_always_on, R.string.ui_health_always_on_ok,
        R.string.ui_health_always_on_problem, R.string.ui_health_open_settings,
    )
    HealthItem.BACKGROUND_RESTRICTIONS -> ItemText(
        R.string.ui_health_background, R.string.ui_health_background_ok,
        R.string.ui_health_background_problem, R.string.ui_health_open_settings,
    )
    HealthItem.STANDBY_BUCKET -> ItemText(
        R.string.ui_health_standby, R.string.ui_health_standby_ok,
        R.string.ui_health_standby_problem, R.string.ui_health_open_settings,
    )
    HealthItem.LOCKDOWN -> ItemText(
        R.string.ui_health_lockdown, R.string.ui_health_lockdown_ok,
        R.string.ui_health_lockdown_problem, R.string.ui_health_open_settings,
    )
    HealthItem.PRIVATE_DNS -> ItemText(
        R.string.ui_health_private_dns, R.string.ui_health_private_dns_ok,
        R.string.ui_health_private_dns_problem, R.string.ui_health_open_settings,
    )
    HealthItem.NOTIFICATIONS -> ItemText(
        R.string.ui_health_notifications, R.string.ui_health_notifications_ok,
        R.string.ui_health_notifications_problem, R.string.ui_health_open_settings,
    )
}

/** The item's own settings page, or the settings root when this build has none (KEEPALIVE §4.2). */
private fun openSettings(context: Context, item: HealthItem) {
    val intent = ProtectionHealth.intentFor(item, context) ?: ProtectionHealth.settingsRoot()
    try {
        context.startActivity(intent)
    } catch (_: ActivityNotFoundException) {
        context.startActivity(ProtectionHealth.settingsRoot())
    }
}
