package top.zztweb.zshield.ui.filters

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.combinedClickable
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
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.ListItem
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import kotlinx.coroutines.launch
import top.zztweb.zshield.R
import top.zztweb.zshield.filters.CompileState
import top.zztweb.zshield.filters.FilterListState
import top.zztweb.zshield.filters.FilterRepository
import top.zztweb.zshield.filters.ListStatus
import top.zztweb.zshield.ui.Format
import top.zztweb.zshield.ui.components.GroupCard
import top.zztweb.zshield.ui.components.MaxContentWidth
import top.zztweb.zshield.ui.components.PageMargin
import top.zztweb.zshield.ui.components.SectionHeader
import top.zztweb.zshield.ui.theme.AppIcons

/** Display order of catalog categories; custom lists always come last. */
private val CategoryOrder = listOf("ads", "privacy", "security", "annoyance", "regional", "dns")

private fun categoryLabel(category: String): Int = when (category) {
    "ads" -> R.string.ui_cat_ads
    "privacy" -> R.string.ui_cat_privacy
    "security" -> R.string.ui_cat_security
    "annoyance" -> R.string.ui_cat_annoyance
    "regional" -> R.string.ui_cat_regional
    "dns" -> R.string.ui_cat_dns
    else -> R.string.ui_cat_other
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun FiltersScreen(
    contentPadding: PaddingValues,
    onOpenUserRules: () -> Unit,
    onOpenAllowlist: () -> Unit,
) {
    val lists by FilterRepository.lists.collectAsStateWithLifecycle()
    val compile by FilterRepository.compileState.collectAsStateWithLifecycle()
    val userRules by FilterRepository.userRules.collectAsStateWithLifecycle()
    val allowlist by FilterRepository.allowlist.collectAsStateWithLifecycle()
    val scope = rememberCoroutineScope()
    val snackbar = remember { SnackbarHostState() }
    var updating by remember { mutableStateOf(false) }
    var showAdd by rememberSaveable { mutableStateOf(false) }
    var pendingDelete by remember { mutableStateOf<FilterListState?>(null) }
    val scrollBehavior = TopAppBarDefaults.pinnedScrollBehavior()
    val now = remember(lists) { System.currentTimeMillis() }

    val updatedMessage = stringResource(R.string.ui_filters_updated)
    val anyDownloading = lists.any {
        it.status == ListStatus.Downloading || it.status == ListStatus.Queued
    }

    Scaffold(
        modifier = Modifier
            .padding(bottom = contentPadding.calculateBottomPadding())
            .nestedScroll(scrollBehavior.nestedScrollConnection),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.ui_tab_filters)) },
                scrollBehavior = scrollBehavior,
                actions = {
                    if (updating || anyDownloading) {
                        CircularProgressIndicator(Modifier.padding(12.dp).size(24.dp), strokeWidth = 2.5.dp)
                    } else {
                        IconButton(
                            onClick = {
                                updating = true
                                scope.launch {
                                    try {
                                        FilterRepository.updateAll(force = true)
                                        snackbar.showSnackbar(updatedMessage)
                                    } finally {
                                        updating = false
                                    }
                                }
                            },
                        ) {
                            Icon(Icons.Filled.Refresh, contentDescription = stringResource(R.string.ui_filters_update_all))
                        }
                    }
                },
            )
        },
        floatingActionButton = {
            ExtendedFloatingActionButton(
                onClick = { showAdd = true },
                icon = { Icon(Icons.Filled.Add, contentDescription = null) },
                text = { Text(stringResource(R.string.ui_filters_add)) },
            )
        },
        snackbarHost = { SnackbarHost(snackbar) },
        contentWindowInsets = TopAppBarDefaults.windowInsets,
    ) { inner ->
        val builtin = lists.filter { it.builtin }
        val custom = lists.filterNot { it.builtin }
        val grouped = builtin.groupBy { it.category }
        val categories = CategoryOrder.filter { it in grouped } + grouped.keys.filterNot { it in CategoryOrder }

        Box(Modifier.fillMaxSize(), contentAlignment = Alignment.TopCenter) {
            LazyColumn(
                modifier = Modifier.widthIn(max = MaxContentWidth).fillMaxSize(),
                contentPadding = PaddingValues(top = inner.calculateTopPadding(), bottom = 96.dp),
            ) {
                item { CompileSummary(compile = compile, lists = lists) }

                item { SectionHeader(stringResource(R.string.ui_filters_section_custom)) }
                item {
                    GroupCard {
                        NavRow(
                            icon = Icons.Filled.Edit,
                            title = stringResource(R.string.ui_filters_user_rules),
                            body = stringResource(R.string.ui_filters_user_rules_count, Format.ruleLines(userRules)),
                            onClick = onOpenUserRules,
                        )
                        HorizontalDivider(Modifier.padding(start = 56.dp, end = 16.dp), color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f))
                        NavRow(
                            icon = AppIcons.ShieldOutline,
                            title = stringResource(R.string.ui_filters_allowlist),
                            body = stringResource(R.string.ui_filters_allowlist_count, allowlist.size),
                            onClick = onOpenAllowlist,
                        )
                    }
                }

                categories.forEach { category ->
                    val entries = grouped.getValue(category)
                    item(key = "h-$category") {
                        SectionHeader(
                            stringResource(
                                R.string.ui_filters_section_format,
                                stringResource(categoryLabel(category)),
                                entries.count { it.enabled },
                                entries.size,
                            ),
                        )
                    }
                    item(key = "g-$category") {
                        GroupCard {
                            entries.forEachIndexed { index, list ->
                                if (index > 0) {
                                    HorizontalDivider(
                                        Modifier.padding(horizontal = 16.dp),
                                        color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f),
                                    )
                                }
                                FilterRow(list, now, onToggle = { on -> scope.launch { FilterRepository.setEnabled(list.id, on) } }, onDelete = null)
                            }
                        }
                    }
                }

                if (custom.isNotEmpty()) {
                    item { SectionHeader(stringResource(R.string.ui_filters_section_imported)) }
                    item {
                        GroupCard {
                            custom.forEachIndexed { index, list ->
                                if (index > 0) {
                                    HorizontalDivider(
                                        Modifier.padding(horizontal = 16.dp),
                                        color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f),
                                    )
                                }
                                FilterRow(
                                    list, now,
                                    onToggle = { on -> scope.launch { FilterRepository.setEnabled(list.id, on) } },
                                    onDelete = { pendingDelete = list },
                                )
                            }
                        }
                    }
                }
            }
        }
    }

    if (showAdd) {
        AddListDialog(
            onDismiss = { showAdd = false },
            onAddUrl = { url, name ->
                showAdd = false
                scope.launch {
                    val result = FilterRepository.addCustom(url, name)
                    result.exceptionOrNull()?.let { snackbar.showSnackbar(it.message ?: "添加失败") }
                }
            },
            onImportFile = { uri ->
                showAdd = false
                scope.launch {
                    val result = FilterRepository.importFile(uri, null)
                    result.exceptionOrNull()?.let { snackbar.showSnackbar(it.message ?: "导入失败") }
                }
            },
        )
    }

    pendingDelete?.let { list ->
        AlertDialog(
            onDismissRequest = { pendingDelete = null },
            title = { Text(stringResource(R.string.ui_filters_delete_title)) },
            text = { Text(stringResource(R.string.ui_filters_delete_body, list.name)) },
            confirmButton = {
                TextButton(onClick = {
                    pendingDelete = null
                    scope.launch { FilterRepository.remove(list.id) }
                }) { Text(stringResource(R.string.ui_delete)) }
            },
            dismissButton = {
                TextButton(onClick = { pendingDelete = null }) { Text(stringResource(R.string.ui_cancel)) }
            },
        )
    }
}

@Composable
private fun CompileSummary(compile: CompileState, lists: List<FilterListState>) {
    val enabled = lists.filter { it.enabled }
    Surface(
        shape = RoundedCornerShape(24.dp),
        color = MaterialTheme.colorScheme.secondaryContainer,
        contentColor = MaterialTheme.colorScheme.onSecondaryContainer,
        modifier = Modifier.fillMaxWidth().padding(horizontal = PageMargin, vertical = 8.dp),
    ) {
        Column(Modifier.padding(20.dp)) {
            Text(
                stringResource(R.string.ui_filters_summary_rules),
                style = MaterialTheme.typography.labelLarge,
            )
            Spacer(Modifier.height(4.dp))
            Row(verticalAlignment = Alignment.Bottom) {
                Text(
                    Format.grouped(enabled.sumOf { it.ruleCount }),
                    style = MaterialTheme.typography.headlineMedium,
                )
                Spacer(Modifier.width(8.dp))
                Text(
                    stringResource(R.string.ui_filters_summary_lists, enabled.size),
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.padding(bottom = 4.dp),
                )
            }
            Spacer(Modifier.height(8.dp))
            when (compile) {
                CompileState.Running -> {
                    Text(stringResource(R.string.ui_filters_compiling), style = MaterialTheme.typography.bodyMedium)
                    Spacer(Modifier.height(8.dp))
                    LinearProgressIndicator(Modifier.fillMaxWidth())
                }
                is CompileState.Done -> {
                    val s = compile.stats
                    Text(
                        stringResource(
                            R.string.ui_filters_compiled,
                            Format.grouped(s.dnsRules),
                            Format.grouped(s.networkRules),
                            Format.grouped(s.unsupported),
                            Format.duration(s.elapsedMs),
                        ),
                        style = MaterialTheme.typography.bodyMedium,
                    )
                }
                is CompileState.Failed -> Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Filled.Warning, contentDescription = null, tint = MaterialTheme.colorScheme.error, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(6.dp))
                    Text(
                        stringResource(R.string.ui_filters_compile_failed, compile.message),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.error,
                    )
                }
                CompileState.Idle -> {
                    val unsupported = enabled.sumOf { it.unsupportedCount }
                    Text(
                        stringResource(R.string.ui_filters_unsupported, Format.grouped(unsupported)),
                        style = MaterialTheme.typography.bodyMedium,
                    )
                }
            }
        }
    }
}

@Composable
private fun NavRow(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    title: String,
    body: String,
    onClick: () -> Unit,
) {
    ListItem(
        headlineContent = { Text(title) },
        supportingContent = { Text(body) },
        leadingContent = { Icon(icon, contentDescription = null) },
        trailingContent = { Icon(Icons.AutoMirrored.Filled.KeyboardArrowRight, contentDescription = null) },
        colors = ListItemDefaults.colors(containerColor = androidx.compose.ui.graphics.Color.Transparent),
        modifier = Modifier.combinedClickable(onClick = onClick),
    )
}

@Composable
private fun FilterRow(
    list: FilterListState,
    now: Long,
    onToggle: (Boolean) -> Unit,
    onDelete: (() -> Unit)?,
) {
    val status = list.status
    val supporting: String
    val isError: Boolean
    when {
        status == ListStatus.Queued -> { supporting = stringResource(R.string.ui_list_queued); isError = false }
        status == ListStatus.Downloading -> { supporting = stringResource(R.string.ui_list_downloading); isError = false }
        status == ListStatus.Compiling -> { supporting = stringResource(R.string.ui_list_compiling); isError = false }
        status is ListStatus.Error -> { supporting = status.message; isError = true }
        list.error != null && !list.hasContent -> { supporting = list.error; isError = true }
        list.hasContent -> {
            supporting = stringResource(
                R.string.ui_list_meta,
                Format.grouped(list.ruleCount),
                Format.ago(now, list.lastUpdatedMs),
            )
            isError = false
        }
        list.enabled -> { supporting = stringResource(R.string.ui_list_pending); isError = false }
        else -> { supporting = stringResource(R.string.ui_list_not_downloaded); isError = false }
    }
    ListItem(
        headlineContent = { Text(list.name, maxLines = 1, overflow = TextOverflow.Ellipsis) },
        supportingContent = {
            Text(
                supporting,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
                color = if (isError) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant,
            )
        },
        trailingContent = {
            Row(verticalAlignment = Alignment.CenterVertically) {
                if (onDelete != null) {
                    IconButton(onClick = onDelete) {
                        Icon(Icons.Filled.Delete, contentDescription = stringResource(R.string.ui_delete))
                    }
                }
                Switch(checked = list.enabled, onCheckedChange = onToggle)
            }
        },
        colors = ListItemDefaults.colors(containerColor = androidx.compose.ui.graphics.Color.Transparent),
        modifier = Modifier.combinedClickable(onClick = { onToggle(!list.enabled) }),
    )
}

@Composable
private fun AddListDialog(
    onDismiss: () -> Unit,
    onAddUrl: (String, String?) -> Unit,
    onImportFile: (Uri) -> Unit,
) {
    var url by rememberSaveable { mutableStateOf("") }
    var name by rememberSaveable { mutableStateOf("") }
    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) onImportFile(uri)
    }
    val valid = url.trim().let { it.startsWith("https://") || it.startsWith("http://") }
    AlertDialog(
        onDismissRequest = onDismiss,
        icon = { Icon(AppIcons.Link, contentDescription = null) },
        title = { Text(stringResource(R.string.ui_add_title)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                OutlinedTextField(
                    value = url,
                    onValueChange = { url = it },
                    label = { Text(stringResource(R.string.ui_add_url)) },
                    placeholder = { Text("https://…") },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                    supportingText = { Text(stringResource(R.string.ui_add_url_hint)) },
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it },
                    label = { Text(stringResource(R.string.ui_add_name)) },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                TextButton(onClick = { picker.launch(arrayOf("text/*", "application/octet-stream")) }) {
                    Icon(AppIcons.Upload, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(Modifier.width(8.dp))
                    Text(stringResource(R.string.ui_add_from_file))
                }
            }
        },
        confirmButton = {
            TextButton(enabled = valid, onClick = { onAddUrl(url.trim(), name.trim().ifEmpty { null }) }) {
                Text(stringResource(R.string.ui_add_confirm))
            }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.ui_cancel)) } },
    )
}
