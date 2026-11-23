package top.zztweb.zshield.ui.log

import androidx.compose.animation.animateContentSize
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
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.repeatOnLifecycle
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import top.zztweb.zshield.R
import top.zztweb.zshield.core.RequestLogEntry
import top.zztweb.zshield.core.RequestLogEntry.Kind
import top.zztweb.zshield.core.RequestLogEntry.Outcome
import top.zztweb.zshield.ui.Format
import top.zztweb.zshield.ui.TunnelClock
import top.zztweb.zshield.ui.components.EmptyState
import top.zztweb.zshield.ui.components.MaxContentWidth
import top.zztweb.zshield.ui.components.PageMargin
import top.zztweb.zshield.ui.theme.AppIcons
import top.zztweb.zshield.ui.theme.MonoStyle
import top.zztweb.zshield.vpn.VpnState
import top.zztweb.zshield.vpn.ZShieldVpnController

private enum class LogFilter(val label: Int) {
    ALL(R.string.ui_log_all),
    BLOCKED(R.string.ui_log_blocked),
    ALLOWED(R.string.ui_log_allowed),
}

/** How often the open log screen asks the core for new entries. Nothing is polled when closed. */
private const val LOG_POLL_MS = 1_500L

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun LogScreen(contentPadding: PaddingValues) {
    val state by ZShieldVpnController.state.collectAsStateWithLifecycle()
    var entries by remember { mutableStateOf<List<RequestLogEntry>>(emptyList()) }
    var filter by rememberSaveable { mutableStateOf(LogFilter.ALL) }
    var expanded by rememberSaveable { mutableStateOf(-1L) }
    val lifecycle = LocalLifecycleOwner.current.lifecycle
    val scrollBehavior = TopAppBarDefaults.pinnedScrollBehavior()
    val listState = rememberLazyListState()

    // Pull-based: only while this screen is resumed and a tunnel runs (docs/DESIGN.md decision 10).
    LaunchedEffect(state == VpnState.Running) {
        if (state != VpnState.Running) {
            // The core drops its ring buffer when the tunnel stops (privacy: nothing about what the
            // user browsed outlives the session). The entries this screen had already polled are a
            // copy, so they have to go too — otherwise stopping the VPN leaves the previous session's
            // hosts on screen, which is exactly what the "no history" promise says cannot happen.
            entries = emptyList()
            return@LaunchedEffect
        }
        entries = emptyList()
        lifecycle.repeatOnLifecycle(Lifecycle.State.RESUMED) {
            while (true) {
                val since = entries.lastOrNull()?.id ?: 0L
                val fresh = withContext(Dispatchers.IO) { ZShieldVpnController.recentRequests(since) }
                if (fresh.isNotEmpty()) {
                    entries = (entries + fresh).takeLast(RequestLogEntry.CAPACITY)
                }
                delay(LOG_POLL_MS)
            }
        }
    }

    val shown = remember(entries, filter) {
        val newestFirst = entries.asReversed()
        when (filter) {
            LogFilter.ALL -> newestFirst
            LogFilter.BLOCKED -> newestFirst.filter { it.outcome == Outcome.BLOCKED || it.outcome == Outcome.REDIRECTED }
            // A cache hit is not a block, so it belongs in the "allowed" bucket; the alternative
            // (hiding it from both chips) would make the two counts not add up to the total.
            LogFilter.ALLOWED -> newestFirst.filter {
                it.outcome == Outcome.ALLOWED || it.outcome == Outcome.EXCEPTION || it.outcome == Outcome.CACHED
            }
        }
    }
    // New rows are inserted at the top; keep following them while the user is reading the head of
    // the list, but never yank the view away from an older row they scrolled to.
    LaunchedEffect(shown.firstOrNull()?.id) {
        if (listState.firstVisibleItemIndex <= 1) listState.scrollToItem(0)
    }
    val blockedCount = entries.count { it.outcome == Outcome.BLOCKED || it.outcome == Outcome.REDIRECTED }

    Scaffold(
        modifier = Modifier
            .padding(bottom = contentPadding.calculateBottomPadding())
            .nestedScroll(scrollBehavior.nestedScrollConnection),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.ui_tab_log)) },
                scrollBehavior = scrollBehavior,
            )
        },
        contentWindowInsets = TopAppBarDefaults.windowInsets,
    ) { inner ->
        Box(Modifier.fillMaxSize().padding(top = inner.calculateTopPadding()), contentAlignment = Alignment.TopCenter) {
            Column(Modifier.widthIn(max = MaxContentWidth).fillMaxSize()) {
                LazyRow(
                    modifier = Modifier.padding(bottom = 4.dp),
                    contentPadding = PaddingValues(horizontal = PageMargin),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    items(LogFilter.entries) { option ->
                        val count = when (option) {
                            LogFilter.ALL -> entries.size
                            LogFilter.BLOCKED -> blockedCount
                            LogFilter.ALLOWED -> entries.size - blockedCount
                        }
                        FilterChip(
                            selected = filter == option,
                            onClick = { filter = option },
                            label = { Text("${stringResource(option.label)} $count") },
                            leadingIcon = if (filter == option) {
                                { Icon(Icons.Filled.Check, contentDescription = null, modifier = Modifier.size(18.dp)) }
                            } else {
                                null
                            },
                        )
                    }
                }
                when {
                    state != VpnState.Running && entries.isEmpty() -> Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                        EmptyState(
                            icon = AppIcons.ShieldOutline,
                            title = stringResource(R.string.ui_log_off_title),
                            body = stringResource(R.string.ui_log_off_body),
                        )
                    }
                    shown.isEmpty() -> Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                        val filtered = entries.isNotEmpty()
                        EmptyState(
                            icon = AppIcons.ReceiptLong,
                            title = stringResource(if (filtered) R.string.ui_log_no_match_title else R.string.ui_log_empty_title),
                            body = stringResource(if (filtered) R.string.ui_log_no_match_body else R.string.ui_log_empty_body),
                        )
                    }
                    else -> LazyColumn(state = listState, contentPadding = PaddingValues(top = 4.dp, bottom = 16.dp)) {
                        items(shown, key = { it.id }) { entry ->
                            LogRow(
                                entry = entry,
                                expanded = expanded == entry.id,
                                onClick = { expanded = if (expanded == entry.id) -1L else entry.id },
                            )
                            HorizontalDivider(
                                Modifier.padding(start = 64.dp, end = PageMargin),
                                color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f),
                            )
                        }
                    }
                }
            }
        }
    }
}

private data class OutcomeStyle(val icon: ImageVector, val label: Int, val container: Color, val content: Color)

@Composable
private fun outcomeStyle(outcome: Outcome): OutcomeStyle {
    val c = MaterialTheme.colorScheme
    return when (outcome) {
        Outcome.BLOCKED -> OutcomeStyle(AppIcons.Block, R.string.ui_outcome_blocked, c.errorContainer, c.onErrorContainer)
        Outcome.REDIRECTED -> OutcomeStyle(AppIcons.SwapVert, R.string.ui_outcome_redirected, c.tertiaryContainer, c.onTertiaryContainer)
        Outcome.EXCEPTION -> OutcomeStyle(AppIcons.ShieldOutline, R.string.ui_outcome_exception, c.secondaryContainer, c.onSecondaryContainer)
        Outcome.ALLOWED -> OutcomeStyle(Icons.Filled.Check, R.string.ui_outcome_allowed, c.surfaceContainerHigh, c.onSurfaceVariant)
        // A DNS cache hit was passed through like an allowed request; it renders the same way rather
        // than inventing a visual treatment the redesign will own.
        Outcome.CACHED -> OutcomeStyle(Icons.Filled.Check, R.string.ui_outcome_allowed, c.surfaceContainerHigh, c.onSurfaceVariant)
    }
}

@Composable
private fun LogRow(entry: RequestLogEntry, expanded: Boolean, onClick: () -> Unit) {
    val style = outcomeStyle(entry.outcome)
    val started = TunnelClock.startedAtMs
    val time = if (started != null) Format.clock(started + entry.timeMs) else Format.sinceStart(entry.timeMs)
    Row(
        Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .animateContentSize()
            .padding(horizontal = PageMargin, vertical = 12.dp),
    ) {
        Surface(
            shape = RoundedCornerShape(12.dp),
            color = style.container,
            contentColor = style.content,
            modifier = Modifier.size(36.dp),
        ) {
            Icon(style.icon, contentDescription = stringResource(style.label), modifier = Modifier.padding(8.dp))
        }
        Spacer(Modifier.width(12.dp))
        Column(Modifier.weight(1f)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    entry.host.ifEmpty { "—" },
                    style = MaterialTheme.typography.titleSmall,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f),
                )
                Spacer(Modifier.width(8.dp))
                Text(
                    time,
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Spacer(Modifier.height(2.dp))
            Text(
                // MYS-2742: an HTTP entry has a URL; a DNS/connection one has no URL, so the second
                // line carries what that kind actually names (its query type, reason, or CNAME step).
                // The visual layout is unchanged — this is the minimum needed for a non-HTTP line to
                // say something instead of rendering an empty row.
                entryDetail(entry),
                style = MonoStyle,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = if (expanded) 12 else 1,
                overflow = TextOverflow.Ellipsis,
            )
            Spacer(Modifier.height(4.dp))
            val meta = buildList {
                add(stringResource(style.label))
                if (entry.method.isNotEmpty()) add(entry.method)
                if (entry.resourceType.isNotEmpty()) add(Format.requestKind(entry.resourceType))
                if (entry.qtype.isNotEmpty()) add(entry.qtype)
                if (entry.thirdParty) add(stringResource(R.string.ui_log_third_party))
            }.joinToString(" · ")
            Text(meta, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            val rule = entry.rule
            val exception = entry.exceptionRule
            if (rule != null && (expanded || entry.outcome != Outcome.ALLOWED)) {
                RuleChip(stringResource(R.string.ui_log_rule), rule, expanded)
            }
            if (exception != null && expanded) {
                RuleChip(stringResource(R.string.ui_log_exception_rule), exception, expanded)
            }
        }
    }
}

/**
 * The second line of a row: the URL for an HTTP entry, and the kind-specific detail otherwise.
 *
 * MYS-2742 added DNS and connection entries, which have no URL. Rendering them with the old
 * `entry.url` would leave an empty line, so each kind names what it actually has. This is a
 * data-adaptation detail only — the visual design of the page is unchanged.
 */
private fun entryDetail(entry: RequestLogEntry): String = when (entry.kind) {
    Kind.HTTP -> entry.url
    Kind.DNS -> entry.cname?.let { "CNAME → $it" } ?: entry.qtype
    Kind.CONNECTION -> entry.reason.orEmpty()
}

@Composable
private fun RuleChip(label: String, rule: String, expanded: Boolean) {
    Spacer(Modifier.height(6.dp))
    Surface(
        shape = RoundedCornerShape(8.dp),
        color = MaterialTheme.colorScheme.surfaceContainerHigh,
    ) {
        Text(
            "$label  $rule",
            style = MonoStyle,
            maxLines = if (expanded) 6 else 1,
            overflow = TextOverflow.Ellipsis,
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
        )
    }
}
