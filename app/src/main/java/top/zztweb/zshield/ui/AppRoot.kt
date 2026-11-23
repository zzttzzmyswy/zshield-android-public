package top.zztweb.zshield.ui

import androidx.activity.compose.BackHandler
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInHorizontally
import androidx.compose.animation.slideOutHorizontally
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.outlined.Home
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import top.zztweb.zshield.R
import top.zztweb.zshield.ui.filters.FiltersScreen
import top.zztweb.zshield.ui.filters.RulesEditorScreen
import top.zztweb.zshield.ui.filters.RulesKind
import top.zztweb.zshield.ui.health.HealthScreen
import top.zztweb.zshield.ui.home.HomeScreen
import top.zztweb.zshield.ui.log.LogScreen
import top.zztweb.zshield.settings.AppSettings
import top.zztweb.zshield.ui.https.HttpsScreen
import top.zztweb.zshield.ui.settings.AppsScreen
import top.zztweb.zshield.ui.settings.HttpsAppsScreen
import top.zztweb.zshield.vpn.ZShieldVpnController
import top.zztweb.zshield.ui.settings.SettingsScreen
import top.zztweb.zshield.ui.theme.AppIcons

/** Top-level destinations; every setting is at most two levels below one of these. */
enum class Tab(val label: Int, val selectedIcon: () -> ImageVector, val icon: () -> ImageVector) {
    HOME(R.string.ui_tab_home, { Icons.Filled.Home }, { Icons.Outlined.Home }),
    FILTERS(R.string.ui_tab_filters, { AppIcons.FilterAlt }, { AppIcons.FilterAlt }),
    LOG(R.string.ui_tab_log, { AppIcons.ReceiptLong }, { AppIcons.ReceiptLong }),
    SETTINGS(R.string.ui_tab_settings, { Icons.Filled.Settings }, { Icons.Outlined.Settings }),
}

/**
 * Pages below a tab. Stored by name so the back stack survives configuration changes; [parent] is
 * where Back goes (`null` = the tabs), which keeps every page within three levels of a tab.
 */
enum class SubPage(val parent: SubPage? = null) {
    USER_RULES, ALLOWLIST, EXCLUDED_APPS, HTTPS, HEALTH,
    HTTPS_APPS(parent = HTTPS), HTTPS_HOSTS(parent = HTTPS),
}

@Composable
fun AppRoot(actions: AppActions, consentDenied: Boolean) {
    var tab by rememberSaveable { mutableStateOf(Tab.HOME) }
    var subPage by rememberSaveable { mutableStateOf<SubPage?>(null) }

    BackHandler(enabled = subPage == null && tab != Tab.HOME) { tab = Tab.HOME }

    AnimatedContent(
        targetState = subPage,
        transitionSpec = {
            val deeper = targetState != null && (initialState == null || targetState?.parent == initialState)
            if (deeper) {
                (slideInHorizontally { it / 4 } + fadeIn()) togetherWith fadeOut()
            } else {
                fadeIn() togetherWith (slideOutHorizontally { it / 4 } + fadeOut())
            }
        },
        label = "subpage",
    ) { page ->
        when (page) {
            null -> TabsScaffold(
                tab = tab,
                onTab = { tab = it },
                actions = actions,
                consentDenied = consentDenied,
                openSubPage = { subPage = it },
            )
            SubPage.USER_RULES -> RulesEditorScreen(RulesKind.USER_RULES, onBack = { subPage = null })
            SubPage.ALLOWLIST -> RulesEditorScreen(RulesKind.ALLOWLIST, onBack = { subPage = null })
            SubPage.EXCLUDED_APPS -> AppsScreen(
                onBack = { changed ->
                    subPage = null
                    if (changed) actions.restartIfRunning()
                },
            )
            SubPage.HTTPS -> HttpsScreen(
                onBack = { subPage = null },
                onOpenApps = { subPage = SubPage.HTTPS_APPS },
                onOpenHosts = { subPage = SubPage.HTTPS_HOSTS },
                restartIfRunning = actions.restartIfRunning,
            )
            SubPage.HEALTH -> HealthScreen(
                onBack = { subPage = null },
                startProtection = actions.startProtection,
            )
            SubPage.HTTPS_APPS -> HttpsAppsScreen(
                onBack = { changed ->
                    subPage = SubPage.HTTPS
                    if (changed) restartIfDecrypting(actions)
                },
            )
            SubPage.HTTPS_HOSTS -> {
                val before = remember { AppSettings.current.httpsExcludedHosts }
                RulesEditorScreen(
                    RulesKind.HTTPS_EXCLUDED_HOSTS,
                    onBack = {
                        subPage = SubPage.HTTPS
                        if (AppSettings.current.httpsExcludedHosts != before) restartIfDecrypting(actions)
                    },
                )
            }
        }
    }
}

@Composable
private fun TabsScaffold(
    tab: Tab,
    onTab: (Tab) -> Unit,
    actions: AppActions,
    consentDenied: Boolean,
    openSubPage: (SubPage) -> Unit,
) {
    Scaffold(
        bottomBar = {
            NavigationBar(containerColor = MaterialTheme.colorScheme.surfaceContainer) {
                Tab.entries.forEach { entry ->
                    val selected = entry == tab
                    NavigationBarItem(
                        selected = selected,
                        onClick = { onTab(entry) },
                        icon = {
                            Icon(
                                if (selected) entry.selectedIcon() else entry.icon(),
                                contentDescription = null,
                            )
                        },
                        label = { Text(stringResource(entry.label)) },
                    )
                }
            }
        },
    ) { padding ->
        Box(Modifier.fillMaxSize()) {
            when (tab) {
                Tab.HOME -> HomeScreen(
                    contentPadding = padding,
                    consentDenied = consentDenied,
                    onToggle = actions.toggleProtection,
                    onOpenFilters = { onTab(Tab.FILTERS) },
                    onOpenLog = { onTab(Tab.LOG) },
                    onOpenHealth = { openSubPage(SubPage.HEALTH) },
                )
                Tab.FILTERS -> FiltersScreen(
                    contentPadding = padding,
                    onOpenUserRules = { openSubPage(SubPage.USER_RULES) },
                    onOpenAllowlist = { openSubPage(SubPage.ALLOWLIST) },
                )
                Tab.LOG -> LogScreen(contentPadding = padding)
                Tab.SETTINGS -> SettingsScreen(
                    contentPadding = padding,
                    onOpenExcludedApps = { openSubPage(SubPage.EXCLUDED_APPS) },
                    onOpenHttps = { openSubPage(SubPage.HTTPS) },
                    onOpenHealth = { openSubPage(SubPage.HEALTH) },
                    onSettingChanged = actions.restartIfRunning,
                    onOpenDiagnostics = actions.openDiagnostics,
                )
            }
        }
    }
}

/**
 * Which apps and hosts are decrypted is read when the tunnel is built, so a change needs a rebuild
 * — but only while the core is actually decrypting; otherwise the next start picks it up.
 */
private fun restartIfDecrypting(actions: AppActions) {
    if (ZShieldVpnController.stats.value.httpsFiltering) actions.restartIfRunning()
}
