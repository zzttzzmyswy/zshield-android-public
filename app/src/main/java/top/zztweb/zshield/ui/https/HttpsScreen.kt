package top.zztweb.zshield.ui.https

import android.content.Context
import android.widget.Toast
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
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalResources
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.LifecycleResumeEffect
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import top.zztweb.zshield.R
import top.zztweb.zshield.https.BypassEntry
import top.zztweb.zshield.https.CertManager
import top.zztweb.zshield.settings.AppSettings
import top.zztweb.zshield.settings.TunnelMode
import top.zztweb.zshield.ui.Format
import top.zztweb.zshield.ui.components.GroupCard
import top.zztweb.zshield.ui.components.MaxContentWidth
import top.zztweb.zshield.ui.components.PageMargin
import top.zztweb.zshield.ui.components.SectionHeader
import top.zztweb.zshield.ui.settings.installedBrowsers
import top.zztweb.zshield.ui.theme.LocalStatusColors
import top.zztweb.zshield.ui.theme.MonoStyle
import top.zztweb.zshield.vpn.VpnState
import top.zztweb.zshield.vpn.ZShieldVpnController

/** At most this many auto-bypass rows are drawn; the header still shows the full count. */
private const val MAX_BYPASS_ROWS = 50

/**
 * HTTPS filtering: the switch, the root certificate's setup and state, which applications and hosts
 * are decrypted, and the live auto-bypass table.
 *
 * Every tunnel-affecting change goes through [syncTunnel], which rebuilds the tunnel only when what
 * the core is doing differs from what it should be doing — so toggling the switch while the
 * certificate is missing does not drop the user's connections for nothing.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HttpsScreen(
    onBack: () -> Unit,
    onOpenApps: () -> Unit,
    onOpenHosts: () -> Unit,
    restartIfRunning: () -> Unit,
) {
    val context = LocalContext.current
    val resources = LocalResources.current
    val scope = rememberCoroutineScope()
    val settings by AppSettings.state.collectAsStateWithLifecycle()
    val ca by CertManager.state.collectAsStateWithLifecycle()
    val vpnState by ZShieldVpnController.state.collectAsStateWithLifecycle()
    val stats by ZShieldVpnController.stats.collectAsStateWithLifecycle()
    var busy by remember { mutableStateOf(false) }
    var confirmRegenerate by rememberSaveable { mutableStateOf(false) }

    val builtInApps by produceState(initialValue = -1) {
        value = withContext(Dispatchers.IO) { installedBrowsers(context).size }
    }
    val builtInHosts by produceState(initialValue = -1) {
        value = withContext(Dispatchers.IO) {
            runCatching {
                context.assets.open("https/excluded-hosts.txt").bufferedReader().use {
                    HttpsText.countListEntries(it.readText())
                }
            }.getOrDefault(0)
        }
    }

    val running = vpnState == VpnState.Running
    val ready = ca as? CertManager.CaState.Ready
    val status = HttpsStatus.of(
        enabled = settings.httpsFiltering,
        fullMode = settings.mode == TunnelMode.FULL,
        certGenerated = ready != null,
        certInstalled = ready?.installed == true,
        coreDecrypting = running && stats.httpsFiltering,
    )

    /** Rebuild the tunnel iff the core's decrypting state differs from what the settings ask for. */
    fun syncTunnel() {
        if (ZShieldVpnController.state.value != VpnState.Running) return
        val want = HttpsStatus.shouldDecrypt(
            enabled = AppSettings.current.httpsFiltering,
            fullMode = AppSettings.current.mode == TunnelMode.FULL,
            certInstalled = (CertManager.current as? CertManager.CaState.Ready)?.installed == true,
        )
        if (want != ZShieldVpnController.stats.value.httpsFiltering) restartIfRunning()
    }

    // Android has no callback for "a certificate was installed": re-read the store whenever the
    // page comes back from the system settings, and rebuild the tunnel only if that changed.
    // Syncing unconditionally here would race a rebuild already in flight (coming back from the
    // app picker): the new engine reports zeroed stats until its first poll, which reads as "not
    // decrypting" and would trigger a second rebuild.
    LifecycleResumeEffect(Unit) {
        val before = (CertManager.current as? CertManager.CaState.Ready)?.installed
        CertManager.refreshInstalled()
        val after = (CertManager.current as? CertManager.CaState.Ready)?.installed
        if (before != after) syncTunnel()
        onPauseOrDispose { }
    }

    fun generateAndExport() {
        if (busy) return
        busy = true
        scope.launch {
            val result = CertManager.generate().mapCatching { CertManager.exportToDownloads().getOrThrow() }
            busy = false
            result
                .onSuccess {
                    val name = (CertManager.current as? CertManager.CaState.Ready)
                        ?.let { CertManager.exportFileName(it.fingerprintSha256) }.orEmpty()
                    toast(context, resources.getString(R.string.ui_https_saved, name))
                }
                .onFailure { toast(context, resources.getString(R.string.https_error, it.message ?: "?")) }
            syncTunnel()
        }
    }

    fun exportAgain() {
        if (busy) return
        busy = true
        scope.launch {
            val result = CertManager.exportToDownloads()
            busy = false
            val name = ready?.let { CertManager.exportFileName(it.fingerprintSha256) }.orEmpty()
            result
                .onSuccess { toast(context, resources.getString(R.string.ui_https_saved, name)) }
                .onFailure { toast(context, resources.getString(R.string.https_error, it.message ?: "?")) }
        }
    }

    BackHandler(onBack = onBack)
    val scrollBehavior = TopAppBarDefaults.pinnedScrollBehavior()

    Scaffold(
        modifier = Modifier.nestedScroll(scrollBehavior.nestedScrollConnection),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.ui_https_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = stringResource(R.string.ui_back))
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
                MasterCard(
                    status = status,
                    checked = settings.httpsFiltering,
                    intercepted = stats.httpsIntercepted,
                    passthrough = stats.httpsPassthrough,
                    bypassed = stats.httpsBypassEntries,
                    onChange = {
                        AppSettings.setHttpsFiltering(it)
                        syncTunnel()
                    },
                )
                Text(
                    stringResource(R.string.ui_https_intro),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(start = PageMargin + 4.dp, end = PageMargin + 4.dp, top = 10.dp),
                )

                SectionHeader(stringResource(R.string.ui_https_section_cert))
                when {
                    ready == null -> SetupSteps(
                        certDone = false,
                        fileName = null,
                        busy = busy,
                        onGenerate = ::generateAndExport,
                        onExportAgain = {},
                        onOpenSettings = {},
                    )
                    !ready.installed -> SetupSteps(
                        certDone = true,
                        fileName = CertManager.exportFileName(ready.fingerprintSha256),
                        busy = busy,
                        onGenerate = {},
                        onExportAgain = ::exportAgain,
                        onOpenSettings = { CertManager.openInstallSettings(context) },
                    )
                    else -> InstalledCard(
                        ready = ready,
                        busy = busy,
                        onExportAgain = ::exportAgain,
                        onRegenerate = { confirmRegenerate = true },
                    )
                }

                SectionHeader(stringResource(R.string.ui_https_section_scope))
                GroupCard {
                    NavRow(
                        title = stringResource(R.string.ui_https_apps),
                        body = if (builtInApps < 0) {
                            "…"
                        } else {
                            stringResource(R.string.ui_https_apps_body, builtInApps, settings.httpsUserApps.size)
                        },
                        onClick = onOpenApps,
                    )
                    RowDivider()
                    NavRow(
                        title = stringResource(R.string.ui_https_hosts),
                        body = if (builtInHosts < 0) {
                            "…"
                        } else {
                            stringResource(R.string.ui_https_hosts_body, builtInHosts, settings.httpsExcludedHosts.size)
                        },
                        onClick = onOpenHosts,
                    )
                }

                if (status == HttpsStatus.ACTIVE) {
                    BypassSection(entriesVersion = stats.httpsBypassEntries)
                }
            }
        }
    }

    if (confirmRegenerate) {
        AlertDialog(
            onDismissRequest = { confirmRegenerate = false },
            icon = { Icon(Icons.Filled.Warning, contentDescription = null) },
            title = { Text(stringResource(R.string.ui_https_regenerate_title)) },
            text = { Text(stringResource(R.string.ui_https_regenerate_body)) },
            confirmButton = {
                TextButton(onClick = { confirmRegenerate = false; generateAndExport() }) {
                    Text(stringResource(R.string.ui_https_regenerate))
                }
            },
            dismissButton = {
                TextButton(onClick = { confirmRegenerate = false }) { Text(stringResource(R.string.ui_cancel)) }
            },
        )
    }
}

/** The switch, its status line, and — while decrypting — three live counters. */
@Composable
private fun MasterCard(
    status: HttpsStatus,
    checked: Boolean,
    intercepted: Long,
    passthrough: Long,
    bypassed: Long,
    onChange: (Boolean) -> Unit,
) {
    val colors = MaterialTheme.colorScheme
    val statusColors = LocalStatusColors.current
    val active = status == HttpsStatus.ACTIVE
    val (badgeBg, badgeFg) = when {
        active -> statusColors.goodContainer to statusColors.onGoodContainer
        status.needsAction -> statusColors.warningContainer to statusColors.onWarningContainer
        else -> colors.surfaceContainerHighest to colors.onSurfaceVariant
    }
    val statusInk = when {
        active -> statusColors.good
        status.needsAction -> statusColors.warning
        else -> colors.onSurfaceVariant
    }
    Surface(
        shape = RoundedCornerShape(24.dp),
        color = colors.surfaceContainerLow,
        modifier = Modifier.fillMaxWidth().padding(horizontal = PageMargin, vertical = 4.dp),
    ) {
        Column {
            Row(
                Modifier
                    .toggleable(value = checked, role = Role.Switch, onValueChange = onChange)
                    .padding(horizontal = 20.dp, vertical = 18.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Surface(shape = CircleShape, color = badgeBg, contentColor = badgeFg, modifier = Modifier.size(44.dp)) {
                    Icon(
                        if (status.needsAction) Icons.Filled.Warning else Icons.Filled.Lock,
                        contentDescription = null,
                        modifier = Modifier.padding(11.dp),
                    )
                }
                Spacer(Modifier.width(16.dp))
                Column(Modifier.weight(1f)) {
                    Text(stringResource(R.string.ui_https_enable), style = MaterialTheme.typography.titleMedium)
                    Spacer(Modifier.height(2.dp))
                    Text(stringResource(status.summary), style = MaterialTheme.typography.bodyMedium, color = statusInk)
                }
                Spacer(Modifier.width(12.dp))
                Switch(checked = checked, onCheckedChange = null)
            }
            if (active) {
                Row(
                    Modifier.padding(start = 16.dp, end = 16.dp, bottom = 16.dp),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Counter(stringResource(R.string.ui_https_stat_decrypted), intercepted, Modifier.weight(1f))
                    Counter(stringResource(R.string.ui_https_stat_passthrough), passthrough, Modifier.weight(1f))
                    Counter(stringResource(R.string.ui_https_stat_bypassed), bypassed, Modifier.weight(1f))
                }
            }
        }
    }
}

@Composable
private fun Counter(label: String, value: Long, modifier: Modifier = Modifier) {
    Surface(shape = RoundedCornerShape(16.dp), color = MaterialTheme.colorScheme.surfaceContainerHigh, modifier = modifier) {
        Column(Modifier.padding(horizontal = 14.dp, vertical = 10.dp)) {
            Text(
                label,
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Spacer(Modifier.height(2.dp))
            Text(Format.compact(value), style = MaterialTheme.typography.titleLarge, maxLines = 1)
        }
    }
}

/**
 * The two-step setup: (1) generate and save to Downloads, (2) install from the system settings.
 * Android 11+ does not let an app install a CA itself, so step 2 can only point the way.
 */
@Composable
private fun SetupSteps(
    certDone: Boolean,
    fileName: String?,
    busy: Boolean,
    onGenerate: () -> Unit,
    onExportAgain: () -> Unit,
    onOpenSettings: () -> Unit,
) {
    GroupCard {
        Step(
            number = 1,
            done = certDone,
            current = !certDone,
            title = stringResource(if (certDone) R.string.ui_https_step1_done else R.string.ui_https_step1),
            body = if (certDone && fileName != null) {
                stringResource(R.string.ui_https_step1_done_body, fileName)
            } else {
                stringResource(R.string.ui_https_step1_body)
            },
        ) {
            if (!certDone) {
                Button(onClick = onGenerate, enabled = !busy) {
                    if (busy) {
                        CircularProgressIndicator(Modifier.size(16.dp), strokeWidth = 2.dp, color = MaterialTheme.colorScheme.onPrimary)
                        Spacer(Modifier.width(8.dp))
                    }
                    Text(stringResource(R.string.ui_https_generate))
                }
            } else {
                // Text buttons carry a 12 dp inset; shift it so the label lines up with the text.
                TextButton(onClick = onExportAgain, enabled = !busy, modifier = Modifier.offset(x = (-12).dp)) {
                    Text(stringResource(R.string.ui_https_save_again))
                }
            }
        }
        Step(
            number = 2,
            done = false,
            current = certDone,
            title = stringResource(R.string.ui_https_step2),
            body = stringResource(R.string.ui_https_step2_body, fileName ?: "ZShield-CA-….crt"),
            last = true,
        ) {
            if (certDone) {
                Button(onClick = onOpenSettings) { Text(stringResource(R.string.ui_https_open_settings)) }
            }
        }
    }
}

/** One numbered step with a connector line to the next; the action sits under the text. */
@Composable
private fun Step(
    number: Int,
    done: Boolean,
    current: Boolean,
    title: String,
    body: String,
    last: Boolean = false,
    action: @Composable () -> Unit,
) {
    val colors = MaterialTheme.colorScheme
    val good = LocalStatusColors.current
    val (circleBg, circleFg) = when {
        done -> good.goodContainer to good.onGoodContainer
        current -> colors.primary to colors.onPrimary
        else -> colors.surfaceContainerHighest to colors.onSurfaceVariant
    }
    Row(Modifier.fillMaxWidth().padding(start = 16.dp, end = 16.dp, top = 14.dp, bottom = if (last) 14.dp else 4.dp)) {
        Surface(shape = CircleShape, color = circleBg, contentColor = circleFg, modifier = Modifier.size(28.dp)) {
            Box(contentAlignment = Alignment.Center) {
                if (done) {
                    Icon(Icons.Filled.Check, contentDescription = null, modifier = Modifier.size(16.dp))
                } else {
                    Text("$number", style = MaterialTheme.typography.labelLarge)
                }
            }
        }
        Spacer(Modifier.width(14.dp))
        Column(Modifier.weight(1f).padding(top = 3.dp)) {
            Text(
                title,
                style = MaterialTheme.typography.titleSmall,
                color = if (done || current) colors.onSurface else colors.onSurfaceVariant,
            )
            Spacer(Modifier.height(2.dp))
            Text(body, style = MaterialTheme.typography.bodyMedium, color = colors.onSurfaceVariant)
            Box(Modifier.padding(top = 6.dp)) { action() }
        }
    }
}

/** The installed certificate: state, expiry and fingerprint, with the two maintenance actions. */
@Composable
private fun InstalledCard(
    ready: CertManager.CaState.Ready,
    busy: Boolean,
    onExportAgain: () -> Unit,
    onRegenerate: () -> Unit,
) {
    val good = LocalStatusColors.current
    GroupCard {
        ListItem(
            headlineContent = { Text(stringResource(R.string.ui_https_installed)) },
            supportingContent = {
                Text(stringResource(R.string.ui_https_installed_body, CertManager.expiryText(ready.notAfterMs)))
            },
            leadingContent = { Icon(Icons.Filled.CheckCircle, contentDescription = null, tint = good.good) },
            colors = ListItemDefaults.colors(containerColor = Color.Transparent),
        )
        Column(Modifier.padding(start = 56.dp, end = 16.dp)) {
            Text(
                stringResource(R.string.ui_https_fingerprint),
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(2.dp))
            Text(
                HttpsText.fingerprint(ready.fingerprintSha256),
                style = MonoStyle,
                color = MaterialTheme.colorScheme.onSurface,
            )
        }
        Row(Modifier.padding(start = 44.dp, end = 8.dp, top = 4.dp, bottom = 4.dp)) {
            TextButton(onClick = onExportAgain, enabled = !busy) { Text(stringResource(R.string.ui_https_save_again)) }
            TextButton(onClick = onRegenerate, enabled = !busy) { Text(stringResource(R.string.ui_https_regenerate)) }
        }
    }
}

/**
 * The auto-bypass table, pulled from the core when the page opens and whenever the live entry count
 * changes ([entriesVersion]). Pull-based like the request log: nothing is serialized unless this
 * page is showing.
 */
@Composable
private fun BypassSection(entriesVersion: Long) {
    val context = LocalContext.current
    val resources = LocalResources.current
    var refresh by remember { mutableStateOf(0) }
    var entries by remember { mutableStateOf<List<BypassEntry>>(emptyList()) }
    LaunchedEffect(entriesVersion, refresh) {
        entries = withContext(Dispatchers.IO) { ZShieldVpnController.httpsBypass() }
            .sortedByDescending { it.expiresAtMs }
    }
    val labels = remember { HashMap<Int, String>() }

    Row(
        Modifier.fillMaxWidth().padding(end = PageMargin - 4.dp),
        verticalAlignment = Alignment.Bottom,
    ) {
        SectionHeader(stringResource(R.string.ui_https_section_bypass, entries.size), Modifier.weight(1f))
        if (entries.isNotEmpty()) {
            // Bottom-aligned with the header, whose text sits 8 dp above its bottom edge; the offset
            // puts the button label on the same line.
            TextButton(modifier = Modifier.offset(y = 6.dp), onClick = {
                ZShieldVpnController.clearHttpsBypass()
                refresh++
                toast(context, resources.getString(R.string.ui_https_bypass_cleared))
            }) { Text(stringResource(R.string.ui_https_bypass_clear)) }
        }
    }
    Text(
        stringResource(R.string.ui_https_bypass_hint),
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier.padding(start = PageMargin + 4.dp, end = PageMargin + 4.dp, bottom = 8.dp),
    )
    GroupCard {
        if (entries.isEmpty()) {
            ListItem(
                headlineContent = {
                    Text(stringResource(R.string.ui_https_bypass_empty), color = MaterialTheme.colorScheme.onSurfaceVariant)
                },
                colors = ListItemDefaults.colors(containerColor = Color.Transparent),
            )
            return@GroupCard
        }
        val now = System.currentTimeMillis()
        entries.take(MAX_BYPASS_ROWS).forEachIndexed { index, entry ->
            if (index > 0) RowDivider()
            val app = labels.getOrPut(entry.uid) { appLabelForUid(context, entry.uid) }
            ListItem(
                headlineContent = { Text(entry.host, maxLines = 1, overflow = TextOverflow.Ellipsis) },
                supportingContent = {
                    Text(
                        stringResource(
                            R.string.ui_https_bypass_row,
                            app,
                            stringResource(HttpsText.reason(entry.reason)),
                            HttpsText.hoursLeft(now, entry.expiresAtMs),
                        ),
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                },
                colors = ListItemDefaults.colors(containerColor = Color.Transparent),
            )
        }
    }
}

/** The app name for a uid; a shared uid shows its first package, an unknown one shows the number. */
private fun appLabelForUid(context: Context, uid: Int): String {
    val pm = context.packageManager
    val pkg = pm.getPackagesForUid(uid)?.firstOrNull() ?: return "uid $uid"
    return runCatching { pm.getApplicationInfo(pkg, 0).loadLabel(pm).toString() }.getOrDefault(pkg)
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

@Composable
private fun RowDivider() {
    HorizontalDivider(
        Modifier.padding(horizontal = 16.dp),
        color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f),
    )
}

private fun toast(context: Context, text: String) {
    Toast.makeText(context, text, Toast.LENGTH_LONG).show()
}
