package top.zztweb.zshield.ui.filters

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import top.zztweb.zshield.R
import top.zztweb.zshield.filters.FilterRepository
import top.zztweb.zshield.settings.AppSettings
import top.zztweb.zshield.ui.Format
import top.zztweb.zshield.ui.components.MaxContentWidth
import top.zztweb.zshield.ui.components.PageMargin
import top.zztweb.zshield.ui.theme.MonoStyle

/** The plain-text lists the editor serves. [HTTPS_EXCLUDED_HOSTS] lives in `AppSettings`. */
enum class RulesKind(val title: Int, val hint: Int, val placeholder: String) {
    USER_RULES(R.string.ui_filters_user_rules, R.string.ui_editor_rules_hint, "||ads.example.com^\n@@||cdn.example.com^"),
    ALLOWLIST(R.string.ui_filters_allowlist, R.string.ui_editor_allow_hint, "example.com"),
    HTTPS_EXCLUDED_HOSTS(R.string.ui_https_hosts, R.string.ui_editor_https_hosts_hint, "bank.example.com"),
}

/**
 * Plain-text editor for the user's own rules or the allowlist. Saving hands the text to the
 * repository, which persists it and schedules the (debounced) recompile and hot swap.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun RulesEditorScreen(kind: RulesKind, onBack: () -> Unit) {
    val initial = remember(kind) {
        when (kind) {
            RulesKind.USER_RULES -> FilterRepository.userRules.value
            RulesKind.ALLOWLIST -> FilterRepository.allowlist.value.joinToString("\n")
            RulesKind.HTTPS_EXCLUDED_HOSTS -> AppSettings.current.httpsExcludedHosts.joinToString("\n")
        }
    }
    var text by rememberSaveable(kind) { mutableStateOf(initial) }
    var confirmDiscard by rememberSaveable { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    val dirty = text != initial

    fun save() {
        scope.launch {
            when (kind) {
                RulesKind.USER_RULES -> FilterRepository.setUserRules(text)
                RulesKind.ALLOWLIST -> FilterRepository.setAllowlist(text.lines())
                RulesKind.HTTPS_EXCLUDED_HOSTS -> AppSettings.setHttpsExcludedHosts(text.lines())
            }
            onBack()
        }
    }

    BackHandler { if (dirty) confirmDiscard = true else onBack() }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(kind.title)) },
                navigationIcon = {
                    IconButton(onClick = { if (dirty) confirmDiscard = true else onBack() }) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = stringResource(R.string.ui_back))
                    }
                },
                actions = {
                    TextButton(enabled = dirty, onClick = ::save) { Text(stringResource(R.string.ui_save)) }
                },
            )
        },
    ) { inner ->
        Box(Modifier.fillMaxSize().padding(inner).imePadding(), contentAlignment = Alignment.TopCenter) {
            Column(Modifier.widthIn(max = MaxContentWidth).fillMaxSize().padding(horizontal = PageMargin)) {
                Text(
                    stringResource(kind.hint),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(bottom = 12.dp),
                )
                OutlinedTextField(
                    value = text,
                    onValueChange = { text = it },
                    textStyle = MonoStyle.copy(color = MaterialTheme.colorScheme.onSurface),
                    placeholder = {
                        Text(kind.placeholder, style = MonoStyle)
                    },
                    supportingText = {
                        Text(
                            if (kind == RulesKind.USER_RULES) {
                                stringResource(R.string.ui_filters_user_rules_count, Format.ruleLines(text))
                            } else {
                                stringResource(R.string.ui_filters_allowlist_count, text.lines().count { it.isNotBlank() })
                            },
                        )
                    },
                    modifier = Modifier.fillMaxWidth().weight(1f).padding(bottom = 16.dp),
                )
            }
        }
    }

    if (confirmDiscard) {
        AlertDialog(
            onDismissRequest = { confirmDiscard = false },
            title = { Text(stringResource(R.string.ui_editor_discard_title)) },
            confirmButton = {
                TextButton(onClick = { confirmDiscard = false; save() }) { Text(stringResource(R.string.ui_save)) }
            },
            dismissButton = {
                TextButton(onClick = { confirmDiscard = false; onBack() }) { Text(stringResource(R.string.ui_discard)) }
            },
        )
    }
}
