package top.zztweb.zshield.ui.home

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.compose.LifecycleResumeEffect
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import top.zztweb.zshield.health.ProtectionHealth
import top.zztweb.zshield.ui.health.HealthRows
import top.zztweb.zshield.ui.health.healthItemTitle
import top.zztweb.zshield.R
import top.zztweb.zshield.filters.FilterRepository
import top.zztweb.zshield.settings.AppSettings
import top.zztweb.zshield.settings.TunnelMode
import top.zztweb.zshield.ui.Format
import top.zztweb.zshield.ui.components.Banner
import top.zztweb.zshield.ui.components.MaxContentWidth
import top.zztweb.zshield.ui.components.PageMargin
import top.zztweb.zshield.ui.theme.AppIcons
import top.zztweb.zshield.ui.theme.LocalStatusColors
import top.zztweb.zshield.vpn.VpnState
import top.zztweb.zshield.vpn.VpnStats
import top.zztweb.zshield.vpn.ZShieldVpnController

@Composable
fun HomeScreen(
    contentPadding: PaddingValues,
    consentDenied: Boolean,
    onToggle: () -> Unit,
    onOpenFilters: () -> Unit,
    onOpenLog: () -> Unit,
    onOpenHealth: () -> Unit,
) {
    val state by ZShieldVpnController.state.collectAsStateWithLifecycle()
    val stats by ZShieldVpnController.stats.collectAsStateWithLifecycle()
    val privateDns by ZShieldVpnController.privateDns.collectAsStateWithLifecycle()
    val settings by AppSettings.state.collectAsStateWithLifecycle()
    val lists by FilterRepository.lists.collectAsStateWithLifecycle()
    val health by ProtectionHealth.state.collectAsStateWithLifecycle()
    val context = LocalContext.current
    LifecycleResumeEffect(Unit) {
        ProtectionHealth.refresh(context)
        onPauseOrDispose { }
    }
    // Only nag once the user has asked for protection: before that, "no VPN permission" is simply
    // the first-run state, and the shield itself is the call to action.
    val attention = if (settings.protectionWanted) HealthRows.attention(health) else emptyList()
    // The banner keeps its last content while it animates out, instead of flashing "0 items".
    var shownAttention by remember { mutableStateOf(attention) }
    if (attention.isNotEmpty()) shownAttention = attention

    val enabledLists = lists.filter { it.enabled }
    val ruleTotal = enabledLists.sumOf { it.ruleCount }
    val downloaded = enabledLists.any { it.hasContent }

    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.TopCenter) {
        Column(
            modifier = Modifier
                .widthIn(max = MaxContentWidth)
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(bottom = contentPadding.calculateBottomPadding())
                .statusBarsPadding(),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Header()
            Spacer(Modifier.height(8.dp))
            ProtectionToggle(state = state, onToggle = onToggle)
            Spacer(Modifier.height(16.dp))
            StatusText(state = state, mode = settings.mode)
            Spacer(Modifier.height(24.dp))

            Column(
                Modifier.padding(horizontal = PageMargin),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                val current = state
                if (current is VpnState.Error) {
                    Banner(
                        icon = Icons.Filled.Warning,
                        title = stringResource(R.string.ui_home_error_title),
                        body = current.message,
                        container = MaterialTheme.colorScheme.errorContainer,
                        content = MaterialTheme.colorScheme.onErrorContainer,
                    )
                } else if (consentDenied && current == VpnState.Stopped) {
                    Banner(
                        icon = Icons.Filled.Warning,
                        title = stringResource(R.string.ui_home_consent_title),
                        body = stringResource(R.string.ui_home_consent_body),
                        container = LocalStatusColors.current.warningContainer,
                        content = LocalStatusColors.current.onWarningContainer,
                    )
                }
                AnimatedVisibility(visible = attention.isNotEmpty() && current !is VpnState.Error) {
                    Banner(
                        icon = Icons.Filled.Warning,
                        title = stringResource(R.string.ui_home_health_title, shownAttention.size),
                        body = stringResource(
                            R.string.ui_home_health_body,
                            shownAttention.map { stringResource(healthItemTitle(it)) }.joinToString("、"),
                        ),
                        container = LocalStatusColors.current.warningContainer,
                        content = LocalStatusColors.current.onWarningContainer,
                        onClick = onOpenHealth,
                    )
                }
                AnimatedVisibility(visible = privateDns.isStrict) {
                    Banner(
                        icon = AppIcons.Dns,
                        title = stringResource(R.string.ui_home_private_dns_title),
                        body = stringResource(R.string.ui_home_private_dns_body, privateDns.serverName ?: ""),
                        container = LocalStatusColors.current.warningContainer,
                        content = LocalStatusColors.current.onWarningContainer,
                    )
                }
                StatsCard(state = state, stats = stats, onOpenLog = onOpenLog)
                RulesCard(
                    enabledCount = enabledLists.size,
                    ruleTotal = ruleTotal,
                    downloaded = downloaded,
                    onClick = onOpenFilters,
                )
            }
            Spacer(Modifier.height(24.dp))
        }
    }
}

@Composable
private fun Header() {
    Row(
        Modifier
            .fillMaxWidth()
            .padding(horizontal = PageMargin + 4.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(
            AppIcons.Shield,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.primary,
            modifier = Modifier.size(22.dp),
        )
        Spacer(Modifier.width(8.dp))
        Text(stringResource(R.string.app_name), style = MaterialTheme.typography.titleLarge)
    }
}

/** The one-tap switch: a large shield whose colour and glyph carry the state together. */
@Composable
private fun ProtectionToggle(state: VpnState, onToggle: () -> Unit) {
    val colors = MaterialTheme.colorScheme
    val on = state == VpnState.Running
    val starting = state == VpnState.Starting
    val error = state is VpnState.Error

    val halo by animateColorAsState(
        when {
            on -> colors.primaryContainer
            error -> colors.errorContainer.copy(alpha = 0.6f)
            else -> colors.surfaceContainerHigh
        },
        tween(400), label = "halo",
    )
    val core by animateColorAsState(
        when {
            on -> colors.primary
            error -> colors.errorContainer
            else -> colors.surfaceContainerHighest
        },
        tween(400), label = "core",
    )
    val glyph by animateColorAsState(
        when {
            on -> colors.onPrimary
            error -> colors.onErrorContainer
            starting -> colors.primary
            else -> colors.onSurfaceVariant
        },
        tween(400), label = "glyph",
    )
    val haloScale by animateFloatAsState(if (on) 1f else 0.92f, tween(500), label = "haloScale")

    val stateLabel = stringResource(if (on) R.string.ui_state_on_short else R.string.ui_state_off_short)
    Box(
        modifier = Modifier
            .size(188.dp)
            .semantics { stateDescription = stateLabel },
        contentAlignment = Alignment.Center,
    ) {
        Box(
            Modifier
                .size(188.dp)
                .scale(haloScale)
                .clip(CircleShape)
                .background(halo),
        )
        if (starting) {
            CircularProgressIndicator(
                modifier = Modifier.size(152.dp),
                strokeWidth = 4.dp,
                color = colors.primary,
                trackColor = Color.Transparent,
            )
        }
        Box(
            modifier = Modifier
                .size(136.dp)
                .clip(CircleShape)
                .background(core)
                .toggleable(
                    value = on || starting,
                    role = Role.Switch,
                    onValueChange = { onToggle() },
                ),
            contentAlignment = Alignment.Center,
        ) {
            Icon(
                imageVector = when {
                    on -> AppIcons.ShieldCheck
                    error -> Icons.Filled.Warning
                    starting -> AppIcons.Shield
                    else -> AppIcons.ShieldOutline
                },
                contentDescription = stringResource(R.string.ui_home_toggle_description),
                tint = glyph,
                modifier = Modifier.size(64.dp),
            )
        }
    }
}

@Composable
private fun StatusText(state: VpnState, mode: TunnelMode) {
    val title = when (state) {
        VpnState.Running -> R.string.ui_state_on
        VpnState.Starting -> R.string.ui_state_starting
        is VpnState.Error -> R.string.ui_state_error
        VpnState.Stopped -> R.string.ui_state_off
    }
    val modeLabel = stringResource(
        if (mode == TunnelMode.FULL) R.string.ui_mode_full else R.string.ui_mode_dns_only,
    )
    val hint = when (state) {
        VpnState.Running -> stringResource(R.string.ui_home_hint_on, modeLabel)
        VpnState.Starting -> stringResource(R.string.ui_home_hint_starting)
        else -> stringResource(R.string.ui_home_hint_off)
    }
    Text(
        stringResource(title),
        style = MaterialTheme.typography.headlineSmall,
        color = if (state == VpnState.Running) LocalStatusColors.current.good else MaterialTheme.colorScheme.onSurface,
    )
    Spacer(Modifier.height(4.dp))
    Text(
        hint,
        style = MaterialTheme.typography.bodyMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        textAlign = TextAlign.Center,
        modifier = Modifier.padding(horizontal = 32.dp),
    )
}

/** Totals for this run (or the last one, while stopped). Hidden until there is anything to show. */
@Composable
private fun StatsCard(state: VpnState, stats: VpnStats, onOpenLog: () -> Unit) {
    val blocked = stats.dnsBlocked + stats.blockedConnections + stats.httpBlocked
    val hasData = stats.dnsQueries > 0 || blocked > 0 || stats.bytesDown > 0
    val running = state == VpnState.Running
    if (!running && !hasData) return

    Surface(
        shape = RoundedCornerShape(24.dp),
        color = MaterialTheme.colorScheme.surfaceContainerLow,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(Modifier.padding(20.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    stringResource(if (running) R.string.ui_stats_this_run else R.string.ui_stats_last_run),
                    style = MaterialTheme.typography.labelLarge,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.weight(1f),
                )
                Text(
                    stringResource(R.string.ui_stats_open_log),
                    style = MaterialTheme.typography.labelLarge,
                    color = MaterialTheme.colorScheme.primary,
                    modifier = Modifier
                        .clip(RoundedCornerShape(8.dp))
                        .clickable(onClick = onOpenLog)
                        .padding(horizontal = 8.dp, vertical = 4.dp),
                )
            }
            Spacer(Modifier.height(8.dp))
            Row(verticalAlignment = Alignment.Bottom) {
                Text(
                    Format.compact(blocked),
                    style = MaterialTheme.typography.displaySmall,
                    color = MaterialTheme.colorScheme.onSurface,
                )
                Spacer(Modifier.width(8.dp))
                Text(
                    stringResource(R.string.ui_stats_blocked_unit),
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(bottom = 6.dp),
                )
            }
            val rate = Format.percent(stats.dnsBlocked, stats.dnsQueries)
            Text(
                if (rate != null) {
                    stringResource(R.string.ui_stats_rate, rate, Format.grouped(stats.dnsQueries))
                } else {
                    stringResource(R.string.ui_stats_no_queries)
                },
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(16.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                MiniStat(AppIcons.Dns, stringResource(R.string.ui_stats_dns), Format.compact(stats.dnsBlocked), Modifier.weight(1f))
                MiniStat(AppIcons.Block, stringResource(R.string.ui_stats_conn), Format.compact(stats.blockedConnections), Modifier.weight(1f))
            }
            Spacer(Modifier.height(12.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                MiniStat(AppIcons.Language, stringResource(R.string.ui_stats_http), Format.compact(stats.httpBlocked), Modifier.weight(1f))
                MiniStat(
                    AppIcons.SwapVert,
                    stringResource(R.string.ui_stats_traffic),
                    Format.bytes(stats.bytesUp + stats.bytesDown),
                    Modifier.weight(1f),
                )
            }
        }
    }
}

@Composable
private fun MiniStat(icon: ImageVector, label: String, value: String, modifier: Modifier = Modifier) {
    Surface(
        shape = RoundedCornerShape(16.dp),
        color = MaterialTheme.colorScheme.surfaceContainerHigh,
        modifier = modifier,
    ) {
        Column(Modifier.padding(horizontal = 14.dp, vertical = 12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    icon,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.size(16.dp),
                )
                Spacer(Modifier.width(6.dp))
                Text(
                    label,
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            Spacer(Modifier.height(4.dp))
            Text(value, style = MaterialTheme.typography.titleLarge, maxLines = 1)
        }
    }
}

@Composable
private fun RulesCard(enabledCount: Int, ruleTotal: Long, downloaded: Boolean, onClick: () -> Unit) {
    Surface(
        shape = RoundedCornerShape(24.dp),
        color = MaterialTheme.colorScheme.surfaceContainerLow,
        onClick = onClick,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Row(Modifier.padding(20.dp), verticalAlignment = Alignment.CenterVertically) {
            Surface(
                shape = RoundedCornerShape(14.dp),
                color = MaterialTheme.colorScheme.secondaryContainer,
                contentColor = MaterialTheme.colorScheme.onSecondaryContainer,
                modifier = Modifier.size(44.dp),
            ) {
                Icon(AppIcons.FilterAlt, contentDescription = null, modifier = Modifier.padding(11.dp))
            }
            Spacer(Modifier.width(16.dp))
            Column(Modifier.weight(1f)) {
                Text(stringResource(R.string.ui_home_rules_title), style = MaterialTheme.typography.titleMedium)
                Text(
                    if (enabledCount == 0) {
                        stringResource(R.string.ui_home_rules_none)
                    } else if (!downloaded) {
                        stringResource(R.string.ui_home_rules_downloading, enabledCount)
                    } else {
                        stringResource(R.string.ui_home_rules_body, enabledCount, Format.grouped(ruleTotal))
                    },
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Icon(
                Icons.AutoMirrored.Filled.KeyboardArrowRight,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}
