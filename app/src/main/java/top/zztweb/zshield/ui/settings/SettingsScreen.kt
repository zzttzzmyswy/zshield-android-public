package top.zztweb.zshield.ui.settings

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.ListItem
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.compose.LifecycleResumeEffect
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import top.zztweb.zshield.BuildConfig
import top.zztweb.zshield.R
import top.zztweb.zshield.filters.FilterRepository
import top.zztweb.zshield.health.ProtectionHealth
import top.zztweb.zshield.https.CertManager
import top.zztweb.zshield.settings.AppSettings
import top.zztweb.zshield.settings.TunnelMode
import top.zztweb.zshield.ui.Format
import top.zztweb.zshield.ui.components.GroupCard
import top.zztweb.zshield.ui.components.MaxContentWidth
import top.zztweb.zshield.ui.components.SectionHeader
import top.zztweb.zshield.ui.health.HealthRows
import top.zztweb.zshield.ui.https.HttpsStatus
import top.zztweb.zshield.vpn.VpnState
import top.zztweb.zshield.vpn.ZShieldVpnController

/** Choices offered for the periodic filter update (hours). */
private val IntervalChoices = listOf(6, 12, 24, 72, 168)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    contentPadding: PaddingValues,
    onOpenExcludedApps: () -> Unit,
    onOpenHttps: () -> Unit,
    onOpenHealth: () -> Unit,
    onSettingChanged: () -> Unit,
    onOpenDiagnostics: () -> Unit,
) {
    val settings by AppSettings.state.collectAsStateWithLifecycle()
    // Auto-update settings live in the filter state file and have no flow; mirror them locally.
    var intervalHours by remember { mutableIntStateOf(FilterRepository.autoUpdateHours()) }
    var unmeteredOnly by remember { mutableStateOf(FilterRepository.autoUpdateUnmeteredOnly()) }
    var showInterval by rememberSaveable { mutableStateOf(false) }
    val scrollBehavior = TopAppBarDefaults.pinnedScrollBehavior()
    val ca by CertManager.state.collectAsStateWithLifecycle()
    val vpnState by ZShieldVpnController.state.collectAsStateWithLifecycle()
    val stats by ZShieldVpnController.stats.collectAsStateWithLifecycle()
    val context = LocalContext.current
    val health by ProtectionHealth.state.collectAsStateWithLifecycle()
    LifecycleResumeEffect(Unit) {
        ProtectionHealth.refresh(context)
        onPauseOrDispose { }
    }
    val healthProblems = HealthRows.problems(health).size
    val healthAttention = HealthRows.attention(health).size
    val httpsStatus = HttpsStatus.of(
        enabled = settings.httpsFiltering,
        fullMode = settings.mode == TunnelMode.FULL,
        certGenerated = ca is CertManager.CaState.Ready,
        certInstalled = (ca as? CertManager.CaState.Ready)?.installed == true,
        coreDecrypting = vpnState == VpnState.Running && stats.httpsFiltering,
    )

    Scaffold(
        modifier = Modifier
            .padding(bottom = contentPadding.calculateBottomPadding())
            .nestedScroll(scrollBehavior.nestedScrollConnection),
        topBar = { TopAppBar(title = { Text(stringResource(R.string.ui_tab_settings)) }, scrollBehavior = scrollBehavior) },
        contentWindowInsets = TopAppBarDefaults.windowInsets,
    ) { inner ->
        Box(Modifier.fillMaxSize().padding(top = inner.calculateTopPadding()), contentAlignment = Alignment.TopCenter) {
            Column(
                Modifier
                    .widthIn(max = MaxContentWidth)
                    .fillMaxWidth()
                    .verticalScroll(rememberScrollState())
                    .padding(bottom = 24.dp),
            ) {
                SectionHeader(stringResource(R.string.ui_settings_section_mode))
                GroupCard {
                    ModeRow(
                        title = stringResource(R.string.ui_mode_full),
                        body = stringResource(R.string.ui_mode_full_body),
                        selected = settings.mode == TunnelMode.FULL,
                        onSelect = {
                            if (settings.mode != TunnelMode.FULL) {
                                AppSettings.setMode(TunnelMode.FULL); onSettingChanged()
                            }
                        },
                    )
                    ModeRow(
                        title = stringResource(R.string.ui_mode_dns_only),
                        body = stringResource(R.string.ui_mode_dns_only_body),
                        selected = settings.mode == TunnelMode.DNS_ONLY,
                        onSelect = {
                            if (settings.mode != TunnelMode.DNS_ONLY) {
                                AppSettings.setMode(TunnelMode.DNS_ONLY); onSettingChanged()
                            }
                        },
                    )
                }

                SectionHeader(stringResource(R.string.ui_settings_section_https))
                GroupCard {
                    NavRow(
                        title = stringResource(R.string.ui_https_switch),
                        body = stringResource(httpsStatus.summary),
                        onClick = onOpenHttps,
                    )
                }

                SectionHeader(stringResource(R.string.ui_settings_section_health))
                GroupCard {
                    NavRow(
                        title = stringResource(R.string.ui_health_title),
                        body = when {
                            healthAttention > 0 -> stringResource(R.string.ui_settings_health_attention, healthAttention)
                            healthProblems > 0 -> stringResource(R.string.ui_settings_health_optional, healthProblems)
                            else -> stringResource(R.string.ui_settings_health_ok)
                        },
                        onClick = onOpenHealth,
                    )
                }

                SectionHeader(stringResource(R.string.ui_settings_section_tunnel))
                GroupCard {
                    SwitchRow(
                        title = stringResource(R.string.ui_settings_quic),
                        body = stringResource(R.string.ui_settings_quic_body),
                        checked = settings.blockQuic,
                        enabled = settings.mode == TunnelMode.FULL,
                        onChange = { AppSettings.setBlockQuic(it); onSettingChanged() },
                    )
                    Divider()
                    SwitchRow(
                        title = stringResource(R.string.ui_settings_encdns),
                        body = stringResource(R.string.ui_settings_encdns_body),
                        checked = settings.blockEncryptedDnsBypass,
                        enabled = settings.mode == TunnelMode.FULL,
                        onChange = { AppSettings.setBlockEncryptedDnsBypass(it); onSettingChanged() },
                    )
                    Divider()
                    NavRow(
                        title = stringResource(R.string.ui_settings_excluded),
                        body = stringResource(R.string.ui_settings_excluded_body, settings.excludedApps.size),
                        onClick = onOpenExcludedApps,
                    )
                }

                SectionHeader(stringResource(R.string.ui_settings_section_update))
                GroupCard {
                    NavRow(
                        title = stringResource(R.string.ui_settings_interval),
                        body = stringResource(R.string.ui_settings_interval_body, Format.interval(intervalHours)),
                        onClick = { showInterval = true },
                    )
                    Divider()
                    SwitchRow(
                        title = stringResource(R.string.ui_settings_unmetered),
                        body = stringResource(R.string.ui_settings_unmetered_body),
                        checked = unmeteredOnly,
                        enabled = true,
                        onChange = {
                            unmeteredOnly = it
                            FilterRepository.setAutoUpdate(intervalHours, it)
                        },
                    )
                }

                SectionHeader(stringResource(R.string.ui_settings_section_about))
                GroupCard {
                    ListItem(
                        headlineContent = { Text(stringResource(R.string.ui_settings_version)) },
                        supportingContent = { Text("${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE})") },
                        colors = ListItemDefaults.colors(containerColor = Color.Transparent),
                    )
                    Divider()
                    NavRow(
                        title = stringResource(R.string.ui_settings_diagnostics),
                        body = stringResource(R.string.ui_settings_diagnostics_body),
                        onClick = onOpenDiagnostics,
                    )
                }
                Text(
                    stringResource(R.string.ui_settings_privacy_note),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(horizontal = 32.dp, vertical = 16.dp),
                )
            }
        }
    }

    if (showInterval) {
        AlertDialog(
            onDismissRequest = { showInterval = false },
            title = { Text(stringResource(R.string.ui_settings_interval)) },
            text = {
                Column {
                    IntervalChoices.forEach { hours ->
                        IntervalRow(hours == intervalHours, Format.interval(hours)) {
                            intervalHours = hours
                            FilterRepository.setAutoUpdate(hours, unmeteredOnly)
                            showInterval = false
                        }
                    }
                }
            },
            confirmButton = { TextButton(onClick = { showInterval = false }) { Text(stringResource(R.string.ui_cancel)) } },
        )
    }
}

@Composable
private fun IntervalRow(selected: Boolean, label: String, onClick: () -> Unit) {
    ListItem(
        headlineContent = { Text(label) },
        leadingContent = { RadioButton(selected = selected, onClick = null) },
        colors = ListItemDefaults.colors(containerColor = Color.Transparent),
        modifier = Modifier.selectable(selected = selected, role = Role.RadioButton, onClick = onClick),
    )
}

@Composable
private fun Divider() {
    HorizontalDivider(
        Modifier.padding(horizontal = 16.dp),
        color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f),
    )
}

@Composable
private fun ModeRow(title: String, body: String, selected: Boolean, onSelect: () -> Unit) {
    ListItem(
        headlineContent = { Text(title) },
        supportingContent = { Text(body) },
        leadingContent = { RadioButton(selected = selected, onClick = null) },
        colors = ListItemDefaults.colors(containerColor = Color.Transparent),
        modifier = Modifier.selectable(selected = selected, role = Role.RadioButton, onClick = onSelect),
    )
}

@Composable
private fun SwitchRow(title: String, body: String, checked: Boolean, enabled: Boolean, onChange: (Boolean) -> Unit) {
    ListItem(
        headlineContent = { Text(title) },
        supportingContent = { Text(body) },
        trailingContent = { Switch(checked = checked, onCheckedChange = null, enabled = enabled) },
        colors = ListItemDefaults.colors(containerColor = Color.Transparent),
        modifier = Modifier.toggleable(value = checked, enabled = enabled, role = Role.Switch, onValueChange = onChange),
    )
}

@Composable
private fun NavRow(title: String, body: String, onClick: () -> Unit) {
    ListItem(
        headlineContent = { Text(title) },
        supportingContent = { Text(body) },
        trailingContent = { Icon(Icons.AutoMirrored.Filled.KeyboardArrowRight, contentDescription = null) },
        colors = ListItemDefaults.colors(containerColor = Color.Transparent),
        modifier = Modifier.clickable(onClick = onClick),
    )
}
