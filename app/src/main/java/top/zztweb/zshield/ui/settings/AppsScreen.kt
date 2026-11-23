package top.zztweb.zshield.ui.settings

import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Canvas
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Clear
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.Checkbox
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.ListItem
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.core.graphics.createBitmap
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import top.zztweb.zshield.R
import top.zztweb.zshield.https.HttpsApps
import top.zztweb.zshield.settings.AppSettings
import top.zztweb.zshield.ui.components.EmptyState
import top.zztweb.zshield.ui.components.MaxContentWidth
import top.zztweb.zshield.ui.components.PageMargin
import top.zztweb.zshield.ui.theme.AppIcons

/** One launchable app on the device. */
private data class AppEntry(val packageName: String, val label: String)

/**
 * Apps whose traffic bypasses the tunnel. Each tap is persisted immediately; the tunnel is rebuilt
 * once, when the page is left, and only if the set actually changed ([onBack]'s argument).
 */
@Composable
fun AppsScreen(onBack: (changed: Boolean) -> Unit) {
    AppPickerScreen(
        title = stringResource(R.string.ui_settings_excluded),
        hint = stringResource(R.string.ui_apps_hint),
        initial = remember { AppSettings.current.excludedApps.toSet() },
        onSelectionChange = { AppSettings.setExcludedApps(it.toList()) },
        onBack = onBack,
    )
}

/**
 * Applications the HTTPS filter decrypts in addition to the built-in browser list. Installed
 * built-in browsers are shown ticked and locked, so the user sees the whole decrypted set in one
 * place and does not tick a browser that is already covered.
 */
@Composable
fun HttpsAppsScreen(onBack: (changed: Boolean) -> Unit) {
    val context = LocalContext.current
    val builtIn by produceState(initialValue = emptySet<String>()) {
        value = withContext(Dispatchers.IO) { installedBrowsers(context) }
    }
    AppPickerScreen(
        title = stringResource(R.string.ui_https_apps),
        hint = stringResource(R.string.ui_https_apps_hint),
        initial = remember { AppSettings.current.httpsUserApps.toSet() },
        locked = builtIn,
        lockedLabel = stringResource(R.string.ui_https_apps_builtin),
        onSelectionChange = { AppSettings.setHttpsUserApps(it.toList()) },
        onBack = onBack,
    )
}

/** Built-in browser packages that are installed, by package name. */
internal fun installedBrowsers(context: android.content.Context): Set<String> {
    val pm = context.packageManager
    return HttpsApps.browserPackages(context).filterTo(LinkedHashSet()) { name ->
        runCatching { pm.getPackageUid(name, 0) }.isSuccess
    }
}

/**
 * A searchable, tickable list of launchable apps. Each tap is handed to [onSelectionChange]
 * immediately; [onBack] reports whether the set differs from [initial], so the caller rebuilds the
 * tunnel once rather than on every tap.
 *
 * @param locked packages shown ticked and not toggleable (e.g. the built-in browser list), listed
 *   first with [lockedLabel] in place of the package name.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AppPickerScreen(
    title: String,
    hint: String,
    initial: Set<String>,
    onSelectionChange: (Set<String>) -> Unit,
    onBack: (changed: Boolean) -> Unit,
    locked: Set<String> = emptySet(),
    lockedLabel: String? = null,
) {
    val context = LocalContext.current
    var selected by remember { mutableStateOf(initial) }
    var query by rememberSaveable { mutableStateOf("") }

    val apps by produceState<List<AppEntry>?>(initialValue = null) {
        value = withContext(Dispatchers.IO) { loadLaunchableApps(context.packageManager, context.packageName) }
    }

    // Written on every tap after the first, including a tap that returns to [initial]: comparing
    // against [initial] instead would leave the last-but-one set on disk.
    var touched by remember { mutableStateOf(false) }
    LaunchedEffect(selected) {
        if (touched) onSelectionChange(selected)
    }

    val leave = { onBack(selected != initial) }
    BackHandler(onBack = leave)

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(title) },
                navigationIcon = {
                    IconButton(onClick = leave) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = stringResource(R.string.ui_back))
                    }
                },
            )
        },
    ) { inner ->
        Box(Modifier.fillMaxSize().padding(inner), contentAlignment = Alignment.TopCenter) {
            Column(Modifier.widthIn(max = MaxContentWidth).fillMaxSize()) {
                Text(
                    hint,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(horizontal = PageMargin),
                )
                OutlinedTextField(
                    value = query,
                    onValueChange = { query = it },
                    singleLine = true,
                    leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
                    trailingIcon = {
                        if (query.isNotEmpty()) {
                            IconButton(onClick = { query = "" }) {
                                Icon(Icons.Filled.Clear, contentDescription = stringResource(R.string.ui_clear))
                            }
                        }
                    },
                    placeholder = { Text(stringResource(R.string.ui_apps_search)) },
                    shape = RoundedCornerShape(28.dp),
                    modifier = Modifier.fillMaxWidth().padding(horizontal = PageMargin, vertical = 12.dp),
                )
                val list = apps
                if (list == null) {
                    LinearProgressIndicator(Modifier.fillMaxWidth().padding(horizontal = PageMargin))
                    return@Column
                }
                // Locked first, then ticked (snapshot at entry, so rows do not jump while tapping),
                // then by name.
                val ordered = remember(list, locked) {
                    list.sortedWith(
                        compareBy<AppEntry>(
                            { it.packageName !in locked },
                            { it.packageName !in initial },
                            { it.label.lowercase() },
                        ),
                    )
                }
                val needle = query.trim().lowercase()
                val shown = if (needle.isEmpty()) ordered else ordered.filter {
                    it.label.lowercase().contains(needle) || it.packageName.lowercase().contains(needle)
                }
                if (shown.isEmpty()) {
                    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                        EmptyState(AppIcons.Apps, stringResource(R.string.ui_apps_none_title), stringResource(R.string.ui_apps_none_body))
                    }
                    return@Column
                }
                LazyColumn(contentPadding = PaddingValues(bottom = 16.dp)) {
                    items(shown, key = { it.packageName }) { app ->
                        val isLocked = app.packageName in locked
                        val checked = isLocked || app.packageName in selected
                        ListItem(
                            headlineContent = { Text(app.label, maxLines = 1, overflow = TextOverflow.Ellipsis) },
                            supportingContent = {
                                Text(
                                    if (isLocked && lockedLabel != null) lockedLabel else app.packageName,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis,
                                    color = if (isLocked) MaterialTheme.colorScheme.primary else Color.Unspecified,
                                )
                            },
                            leadingContent = { AppIcon(app.packageName) },
                            trailingContent = { Checkbox(checked = checked, onCheckedChange = null, enabled = !isLocked) },
                            colors = ListItemDefaults.colors(containerColor = Color.Transparent),
                            modifier = Modifier.toggleable(
                                value = checked,
                                enabled = !isLocked,
                                role = Role.Checkbox,
                                onValueChange = { on ->
                                    touched = true
                                    selected = if (on) selected + app.packageName else selected - app.packageName
                                },
                            ),
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun AppIcon(packageName: String) {
    val context = LocalContext.current
    val size = with(LocalDensity.current) { 40.dp.roundToPx() }
    val icon by produceState<ImageBitmap?>(initialValue = null, packageName) {
        value = withContext(Dispatchers.IO) {
            runCatching {
                val drawable = context.packageManager.getApplicationIcon(packageName)
                val bitmap = createBitmap(size, size)
                drawable.setBounds(0, 0, size, size)
                drawable.draw(Canvas(bitmap))
                bitmap.asImageBitmap()
            }.getOrNull()
        }
    }
    val bitmap = icon
    if (bitmap != null) {
        Image(bitmap, contentDescription = null, modifier = Modifier.size(40.dp))
    } else {
        Surface(shape = RoundedCornerShape(12.dp), color = MaterialTheme.colorScheme.surfaceContainerHigh, modifier = Modifier.size(40.dp)) {}
    }
}

private fun loadLaunchableApps(pm: PackageManager, self: String): List<AppEntry> {
    val intent = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
    @Suppress("DEPRECATION") // the flags overload is API 33+; minSdk is 28
    return pm.queryIntentActivities(intent, 0)
        .asSequence()
        .map { it.activityInfo.applicationInfo }
        .filter { it.packageName != self }
        .distinctBy { it.packageName }
        .map { info ->
            AppEntry(
                packageName = info.packageName,
                label = info.loadLabel(pm).toString(),
            )
        }
        .toList()
}
