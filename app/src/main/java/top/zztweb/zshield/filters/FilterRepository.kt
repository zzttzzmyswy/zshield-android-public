package top.zztweb.zshield.filters

import android.content.Context
import android.net.Uri
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.json.JSONObject
import top.zztweb.zshield.BuildConfig
import top.zztweb.zshield.core.Native
import java.io.File
import java.security.MessageDigest

/**
 * The subscription system's single entry point (interface fixed by the M1 task card, §3).
 *
 * Responsibilities:
 * - own the built-in catalog and the persisted [FilterState];
 * - download, validate and install list bodies ([ListUpdater]);
 * - compile the enabled set into `dns.bin` / `engine.bin` through `Native.compile`, debounced so a
 *   burst of toggles produces one compile (task card §3: 防抖 ≥ 1 s);
 * - hot-swap the running tunnel's rules through `Native.reload` without restarting it;
 * - expose everything the UI needs as `StateFlow`s.
 *
 * Threading: every `suspend` function runs its blocking work on [Dispatchers.IO]; state updates are
 * serialized by [mutationLock] so a quick sequence of toggles cannot interleave into a half-applied
 * state file. The compile debounce runs on a single-threaded coroutine scope inside [scope].
 */
object FilterRepository {

    /**
     * Minimum quiet period between a change and the compile it triggers.
     *
     * The task card sets the floor at ≥ 1 s; this is exactly that floor. It exists to coalesce a
     * burst of toggles into one compile, not to delay a single edit more than necessary — the
     * acceptance criterion for a rule change taking effect is 5 s, and a compile of the default set
     * already takes ~4 s of it.
     */
    const val COMPILE_DEBOUNCE_MS = 1_000L

    /**
     * How many lists 「全部更新」 downloads at once (MYS-2742 补充要求 3).
     *
     * Three is the task card's number and a deliberate compromise: enough that one slow origin cannot
     * hold up the rest of the round, few enough that a phone on a mobile link is not running eleven
     * HTTP downloads and 3× the memory of one body at the same time (`ListSanity` reads a whole body
     * before validating it). Raising it is a one-line change if measurements ever justify it.
     */
    const val DOWNLOAD_CONCURRENCY = 3

    /** How long `setEnabled` waits for the compile it scheduled, so callers see a settled state. */
    internal var compileWaitTimeoutMs: Long = 120_000L

    /**
     * The quiet period before a scheduled compile actually runs.
     *
     * [COMPILE_DEBOUNCE_MS] in production; tests set it to `0` so a toggle-then-compile sequence does
     * not have to wait a real second per assertion.
     */
    internal var compileDebounceMs: Long = COMPILE_DEBOUNCE_MS

    /**
     * The JNI calls the repository makes, behind seams.
     *
     * `FilterRepository` is the only place that calls `Native.compile` / `Native.reload`, and both
     * are process-wide JNI calls into `libzshield.so` — unavailable in a JVM unit test (`object
     * Native` loads the library in its initialiser). These seams let the download-and-compile
     * behaviour MYS-2742 §修复① introduces be tested without a device, the same way
     * [initializeForTest] already substitutes the transport.
     */
    internal var compileFunction: (String) -> String? = { Native.compile(it) }
    internal var lastErrorFunction: () -> String? = { Native.lastError() }
    internal var reloadFunction: (Long, String) -> Boolean = { handle, dir -> Native.reload(handle, dir) }

    private lateinit var appContext: Context
    private lateinit var store: FilterStore
    private lateinit var compilationCache: CompilationCache
    private lateinit var updater: ListUpdater

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val mutationLock = Mutex()

    /**
     * Held for the duration of an update pass.
     *
     * Two passes can genuinely overlap in a normal install: the periodic `JobService` fires (its job
     * is persisted, so the system may run it at any moment) while `Application.onCreate` is still
     * doing the first-launch download. Both would then write the same `<id>.txt.part` file, and the
     * loser's `rename` fails — which is exactly the "cannot rename ... .part" failure seen on the
     * Pixel 5 before this lock existed. Serialising the passes also keeps the compile debounce from
     * being triggered twice for the same content.
     */
    private val updateLock = Mutex()

    /**
     * Serialises the "download what is missing" pass (MYS-2742 §修复①).
     *
     * Single so two callers can never fetch the same list at once, and **independent of
     * [updateLock]** since the review of PR #14: holding `updateLock` here meant a list the user had
     * just enabled waited for a whole 「全部更新」 round (~25 MB, all mirrors) before its download
     * even started, which is precisely the "stuck at 等待下载" the issue is about. Downloads of
     * *different* lists are safe to run together — [downloadOne] writes a per-attempt `.part` file
     * and renames atomically — so the only thing that has to be serialised is the same list twice.
     */
    private val fetchLock = Mutex()

    private val mutableLists = MutableStateFlow<List<FilterListState>>(emptyList())
    private val mutableUserRules = MutableStateFlow("")
    private val mutableAllowlist = MutableStateFlow<List<String>>(emptyList())
    private val mutableCompileState = MutableStateFlow<CompileState>(CompileState.Idle)

    /** All lists, built-in and user-added, in catalog order then insertion order. */
    val lists: StateFlow<List<FilterListState>> = mutableLists.asStateFlow()

    /** The user's custom rules, verbatim. */
    val userRules: StateFlow<String> = mutableUserRules.asStateFlow()

    /** Domains the user always wants resolved, in the order they were added. */
    val allowlist: StateFlow<List<String>> = mutableAllowlist.asStateFlow()

    /** Progress and result of the most recent compile. */
    val compileState: StateFlow<CompileState> = mutableCompileState.asStateFlow()

    /** Absolute path of the directory holding `dns.bin` / `engine.bin`, or `""` before init. */
    @Volatile
    var compiledDir: String = ""
        private set

    private var catalog: List<CatalogEntry> = emptyList()
    private var initialized = false
    private var pendingCompile: Job? = null

    /** The debounced download pass a toggle scheduled (MYS-2742 §修复①). */
    private var pendingFetch: Job? = null

    /**
     * List ids a download is currently running for.
     *
     * The toggle lane ([fetchMissingEnabled]) and a 「全部更新」 round ([updateAll]) can now run at the
     * same time by design, and both may pick the same list. Claiming the id here makes the loser skip
     * it instead of fetching the same URL twice and racing on the body file.
     */
    private val inFlight: MutableSet<String> = java.util.Collections.synchronizedSet(mutableSetOf())

    /**
     * Set by the VPN service while a tunnel is running: the id of the native handle whose rules a
     * finished compile should hot-swap. `0` means "not running, nothing to reload".
     */
    @Volatile
    private var activeHandle: Long = 0L

    // ---------------------------------------------------------------------------------------
    // Lifecycle
    // ---------------------------------------------------------------------------------------

    /**
     * Load the catalog and persisted state. Safe to call more than once; later calls are no-ops.
     *
     * Kept explicit rather than done in an `init` block because it touches the filesystem and the
     * asset manager, neither of which is available (or desirable) in a unit test.
     */
    fun initialize(context: Context) {
        if (initialized) return
        appContext = context.applicationContext
        store = FilterStore(appContext)
        compilationCache = CompilationCache(store, "${BuildConfig.VERSION_CODE}:${BuildConfig.VERSION_NAME}")
        updater = ListUpdater(store, HttpUrlConnectionTransport())
        store.ensureDirectories()
        catalog = loadCatalog(appContext)
        val state = store.readState()
        mutableLists.value = reconcile(catalog, state)
        mutableUserRules.value = state.userRules
        mutableAllowlist.value = state.allowlist
        compiledDir = store.compiledDir.absolutePath
        initialized = true
        // Fetch missing bodies, then reuse verified artifacts or compile changed inputs. All file
        // hashing/compilation runs off the caller's thread: Application/VPN startup must not block.
        scope.launch {
            fetchMissingEnabled()
            scheduleCompile(andWait = false, reuseVerifiedArtifacts = true)
        }
    }

    /** True once [initialize] has run. */
    val isInitialized: Boolean get() = initialized

    /**
     * Test seam: install a repository over an explicit store, catalog and transport.
     *
     * [context] is nullable because the paths a list toggle exercises — download, compile, status —
     * touch no `Context`: only [importFile] and [setAutoUpdate] do, and their tests can pass one.
     * That keeps the MYS-2742 download tests on the JVM, with no Robolectric dependency.
     */
    internal fun initializeForTest(
        context: Context?,
        store: FilterStore,
        entries: List<CatalogEntry>,
        transport: FilterTransport,
        log: (String) -> Unit = { message -> android.util.Log.i("ZShield", message) },
        budgetMs: Long = ListUpdater.DEFAULT_BUDGET_MS,
    ) {
        context?.let { appContext = it.applicationContext }
        this.store = store
        compilationCache = CompilationCache(store, "test-build")
        this.updater = ListUpdater(store, transport, budgetMs = budgetMs, log = log)
        store.ensureDirectories()
        catalog = entries
        val state = store.readState()
        mutableLists.value = reconcile(catalog, state)
        mutableUserRules.value = state.userRules
        mutableAllowlist.value = state.allowlist
        compiledDir = store.compiledDir.absolutePath
        initialized = true
    }

    /**
     * Fetch the lists that are enabled but have no body yet.
     *
     * This is what makes "首次启动按默认启用集下载" true: on a fresh install every default-enabled
     * catalog entry has state but no file, so this downloads exactly those. A list that already has
     * a body is left alone — the periodic job owns refreshing it, and a failed download must not be
     * retried on every app start.
     *
     * Since MYS-2742 the same pass also runs right after a toggle, which is what makes a newly
     * enabled or newly added list download instead of waiting for the next app start. It holds
     * [fetchLock] only, **not** [updateLock]: a list the user just turned on must not queue behind a
     * 「全部更新」 round that is already running (review of PR #14, item 3). Concurrent passes are
     * harmless because [downloadOne] claims each list id before touching it, so the same list is
     * never fetched twice — the loser simply skips it.
     */
    private suspend fun fetchMissingEnabled() {
        fetchLock.withLock {
            val missing = mutableLists.value.filter { it.enabled && !it.hasContent }
            if (missing.isEmpty()) return
            // `force = true`: every list here is known to have no body, so the `! Expires:`
            // interval is irrelevant — a list whose download failed an hour ago still needs its
            // body, and honouring its interval would leave it at 「等待下载」 until tomorrow.
            downloadAll(missing, force = true)
        }
    }

    /**
     * Run the toggle-and-download sequence for one list (MYS-2742 §修复①).
     *
     * The reported bug: enabling a list, or adding a subscription, only wrote state and scheduled a
     * compile, so a list with no body stayed at `ui_list_pending`「等待下载」 until the next app start
     * (or until the user pressed 全部更新). The download now happens as part of the action:
     *
     * 1. [writeState] applies the change — this is what makes the toggle visible at once;
     * 2. **[scheduleFetch]** starts the download of every enabled list without a body, debounced by
     *    [COMPILE_DEBOUNCE_MS] exactly like the compile. That debounce is what makes a burst one
     *    round: three toggles inside a second cancel each other's pending pass and the survivor fetches
     *    all three lists once (task card: 连续快速勾选多个列表时合并成一轮下载).
     *
     * A failed download leaves the error on the list (`ListStatus.Error` + `FilterListState.error`),
     * which is what the filters screen renders as the reason — silence would look like the old bug.
     */
    private suspend fun mutateAndFetch(block: (FilterState) -> FilterState) {
        writeState(block)
        if (!initialized) return
        scheduleFetch(andWait = false)
    }

    /**
     * Debounce the "download what is missing, then compile" pass.
     *
     * The download comes first and the compile after it, in one job: compiling before the body lands
     * would publish a rule set that does not contain the list the user just enabled, and the list
     * would carry a rule count of zero until the next compile for no visible reason.
     *
     * The job runs on [scope] (IO), never on the caller's dispatcher — [setEnabled] is called from a
     * Compose `rememberCoroutineScope()`, i.e. the main thread (review of PR #14, item 1).
     */
    private suspend fun scheduleFetch(andWait: Boolean) {
        val job = synchronized(this) {
            pendingFetch?.cancel()
            scope.launch {
                delay(compileDebounceMs)
                fetchMissingEnabled()
                scheduleCompile(andWait = true)
            }.also { pendingFetch = it }
        }
        if (andWait) {
            withContext(Dispatchers.IO) { job.join() }
        }
    }

    /**
     * Download [targets], at most [limit] at a time, and apply each outcome as it lands.
     *
     * Two things changed here in response to the PR #14 review:
     *
     * - **the whole loop runs on [Dispatchers.IO]** (item 1). The previous version inherited the
     *   caller's dispatcher, and the only production caller is 「全部更新」 from
     *   `rememberCoroutineScope()` — the main thread — where every `HttpURLConnection` call threw
     *   `NetworkOnMainThreadException` in ~50 ms. Network *and* disk work now happen on IO no matter
     *   who asks.
     * - **lists are downloaded concurrently, up to [limit]** (item 5): serial downloading meant one
     *   slow origin held up every list behind it, and the tail of a 「全部更新」 round showed
     *   「等待下载」 for minutes even though nothing was wrong.
     *
     * A list already being downloaded by another pass is skipped rather than fetched twice; that is
     * what keeps the toggle lane and a running round from colliding on the same file.
     */
    private suspend fun downloadAll(
        targets: List<FilterListState>,
        force: Boolean,
        limit: Int = DOWNLOAD_CONCURRENCY,
    ) {
        if (targets.isEmpty()) return
        val gate = Semaphore(limit.coerceAtLeast(1))
        // A list with **no body at all** goes first (MYS-2742 补充要求 1). It is the one the user just
        // turned on and is watching; a list being refreshed already works with its old copy. Ordering
        // matters less than it did (three run at once, and the toggle lane is independent), but a
        // 「全部更新」 round still starts here rather than at whatever the catalog lists first.
        val ordered = targets.sortedBy { if (it.hasContent) 1 else 0 }
        // A list another pass is already fetching keeps that pass's status: showing 「排队中」 over a
        // running download would be a step backwards, and the owner will settle it either way.
        for (list in ordered) {
            if (list.id !in inFlight) setStatus(list.id, ListStatus.Queued)
        }
        coroutineScope {
            // Slots are taken here, in priority order, before each worker starts: acquiring inside
            // `async` would let the IO threads race for permits and undo the ordering above.
            ordered.map { list ->
                gate.acquire()
                async(Dispatchers.IO) {
                    try {
                        downloadOne(list.id, force)
                    } finally {
                        gate.release()
                    }
                }
            }.awaitAll()
        }
    }

    /**
     * Download one list, claiming its id for the duration so no two passes fetch it at once.
     *
     * @return whether this call actually performed the download (`false` when another pass holds it).
     */
    private suspend fun downloadOne(id: String, force: Boolean): Boolean = withContext(Dispatchers.IO) {
        if (!inFlight.add(id)) return@withContext false
        try {
            // Re-read inside the claim: the list may have been disabled or removed between being
            // queued and getting a slot.
            val list = mutableLists.value.firstOrNull { it.id == id } ?: return@withContext false
            setStatus(id, ListStatus.Downloading)
            val outcome = runCatching { updater.update(list, force = force) }
                .getOrElse { error ->
                    UpdateOutcome.Failed(
                        list.copy(error = error.message ?: "下载失败"),
                        error.message ?: "下载失败",
                    )
                }
            applyOutcome(outcome)
            // Nothing to do and nothing to report: the list is not due, so it must not keep a
            // 「正在下载」 badge after the pass it was queued for has moved on.
            if (outcome is UpdateOutcome.NotDue) setStatus(id, ListStatus.Idle)
            true
        } finally {
            inFlight.remove(id)
        }
    }

    /**
     * Force a compile + hot-swap now, bypassing the debounce.
     *
     * Used by the debug screen; also the entry point a future "apply" button in the real UI will
     * call. `suspend` because the compile is seconds of work and the caller usually wants to know
     * when it landed.
     */
    suspend fun reloadNow(): CompileStats? = compileNow()

    /** Called by the VPN service once a tunnel is up: later compiles hot-swap its rules. */
    fun attachTunnel(handle: Long) {
        activeHandle = handle
    }

    /** Called by the VPN service when the tunnel goes away. */
    fun detachTunnel() {
        activeHandle = 0L
    }

    // ---------------------------------------------------------------------------------------
    // Public API (fixed by the task card)
    // ---------------------------------------------------------------------------------------

    /**
     * Enable or disable one list, then schedule a debounced recompile.
     *
     * Enabling a list that has no body also downloads it (MYS-2742 §修复①): the previous behaviour
     * only wrote state, so the list sat at 「等待下载」 until the next app start. See
     * [mutateAndFetch].
     */
    suspend fun setEnabled(id: String, enabled: Boolean) {
        mutateAndFetch { state ->
            val current = mutableLists.value.firstOrNull { it.id == id }
                ?: return@mutateAndFetch state
            state.withList(current.copy(enabled = enabled))
        }
    }

    /**
     * Add a subscription by URL. Re-adding a known URL returns the existing id.
     *
     * A newly added list — and a known one that somehow has no body — is downloaded immediately, for
     * the same reason as [setEnabled]: "added" must mean "usable", not "waiting".
     */
    suspend fun addCustom(url: String, name: String?): Result<String> = runCatching {
        val trimmed = url.trim()
        require(trimmed.isNotEmpty()) { "URL 不能为空" }
        require(trimmed.startsWith("https://") || trimmed.startsWith("http://")) {
            "只支持 http(s) 地址：$trimmed"
        }
        val id = customId(trimmed)
        mutateAndFetch { state ->
            if (state.lists.any { it.id == id }) {
                return@mutateAndFetch state
            }
            val entry = FilterListState(
                id = id,
                name = name?.trim()?.takeIf { it.isNotEmpty() } ?: hostOf(trimmed),
                category = "ads",
                url = trimmed,
                builtin = false,
                enabled = true,
            )
            state.withList(entry)
        }
        id
    }

    /** Import a local file as a list. The body is copied into the app's own storage. */
    suspend fun importFile(uri: Uri, name: String?): Result<String> = runCatching {
        val bytes = withContext(Dispatchers.IO) {
            appContext.contentResolver.openInputStream(uri)?.use { it.readBytes() }
                ?: throw IllegalArgumentException("无法读取所选文件")
        }
        val verdict = ListSanity.check(bytes)
        if (verdict is ListSanity.Verdict.Rejected) throw IllegalArgumentException(verdict.reason)

        val id = customId("file:${uri}")
        val displayName = name?.trim()?.takeIf { it.isNotEmpty() }
            ?: uri.lastPathSegment?.substringAfterLast('/')?.takeIf { it.isNotEmpty() }
            ?: "本地规则"
        store.writeAtomically(store.listFile(id), bytes)
        mutate { state ->
            val existing = state.lists.firstOrNull { it.id == id }
            val entry = (existing ?: FilterListState(
                id = id,
                name = displayName,
                category = "ads",
                url = uri.toString(),
                builtin = false,
                enabled = true,
            )).copy(
                name = displayName,
                fileName = store.listFile(id).name,
                lastUpdatedMs = System.currentTimeMillis(),
                lastCheckedMs = System.currentTimeMillis(),
                bytes = bytes.size.toLong(),
                error = null,
            )
            state.withList(entry)
        }
        id
    }

    /** Remove a user-added list. Built-in entries cannot be removed (they can be disabled). */
    suspend fun remove(id: String) {
        mutate { state ->
            val current = state.lists.firstOrNull { it.id == id }
            if (current == null || current.builtin) return@mutate state
            store.deleteList(id)
            state.withoutList(id)
        }
    }

    /** Replace the user's custom rules. */
    suspend fun setUserRules(text: String) {
        android.util.Log.i("ZShield", "user rules changed, compile scheduled")
        mutate { state -> state.copy(userRules = text) }
    }

    /** Replace the user's allowlist. Blank and duplicate entries are dropped. */
    suspend fun setAllowlist(domains: List<String>) {
        val cleaned = domains
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .distinct()
        mutate { state -> state.copy(allowlist = cleaned) }
    }

    /**
     * Update every list that has content or is enabled.
     *
     * @param force ignore each list's `! Expires:` interval ("全部更新" in the UI).
     */
    suspend fun updateAll(force: Boolean) {
        if (!initialized) return
        // Runs on IO regardless of the caller's dispatcher: the only production caller is a Compose
        // button, i.e. the main thread, where blocking on sockets used to throw
        // `NetworkOnMainThreadException` for every list (review of PR #14, item 1).
        val performed = withContext(Dispatchers.IO) {
            // The target list is taken *inside* the lock. Taking it outside would capture state from
            // before a concurrent pass ran, so a queued job would re-download lists the pass in front
            // of it had just refreshed (`isDue` would still see the old `lastCheckedMs`).
            updateLock.withLock {
                val targets = mutableLists.value.filter { it.enabled }
                if (targets.isEmpty()) return@withLock false
                downloadAll(targets, force)
                true
            }
        }
        // Android can run the periodic job during startup. A 304/not-due pass must not
        // cancel startup reuse and force an identical compile; changed bytes still miss
        // the verified cache. Explicit manual updates retain their forced-compile behavior.
        if (performed) scheduleCompile(andWait = true, reuseVerifiedArtifacts = !force)
    }

    /** Configure periodic updates. The caller is responsible for rescheduling the job. */
    fun setAutoUpdate(intervalHours: Int, unmeteredOnly: Boolean) {
        if (!initialized) return
        val state = store.readState().copy(
            autoUpdateHours = intervalHours.coerceIn(
                FilterState.MIN_INTERVAL_HOURS,
                FilterState.MAX_INTERVAL_HOURS,
            ),
            autoUpdateUnmeteredOnly = unmeteredOnly,
        )
        store.writeState(state)
        AutoUpdateScheduler.schedule(appContext, state.autoUpdateHours, state.autoUpdateUnmeteredOnly)
    }

    /** Current periodic-update settings. */
    fun autoUpdateHours(): Int = if (initialized) store.readState().autoUpdateHours else FilterState.DEFAULT_INTERVAL_HOURS

    /** Whether periodic updates are restricted to unmetered networks. */
    fun autoUpdateUnmeteredOnly(): Boolean = if (initialized) store.readState().autoUpdateUnmeteredOnly else false

    // ---------------------------------------------------------------------------------------
    // Compilation
    // ---------------------------------------------------------------------------------------

    /**
     * Debounce a compile.
     *
     * Every state change calls this; only the last call in a quiet period actually compiles, which
     * is what keeps "toggle five lists" to one compile instead of five. When [andWait] is set the
     * caller needs the result before returning (a manual update, or a test).
     */
    private suspend fun scheduleCompile(andWait: Boolean, reuseVerifiedArtifacts: Boolean = false) {
        val job = synchronized(this) {
            pendingCompile?.cancel()
            scope.launch {
                delay(compileDebounceMs)
                compileNow(reuseVerifiedArtifacts)
            }.also { pendingCompile = it }
        }
        if (andWait) {
            withContext(Dispatchers.IO) { job.join() }
        }
    }

    /**
     * Compile right now, ignoring the debounce.
     *
     * Called from [scheduleCompile] after the quiet period, and from the debug screen's "立即编译".
     * Returns the statistics, or `null` when the compile failed (the reason is in [compileState]).
     */
    suspend fun compileNow(reuseVerifiedArtifacts: Boolean = false): CompileStats? {
        if (!initialized) return null
        mutableCompileState.value = CompileState.Running
        val snapshot = mutableLists.value
        // Only lists that actually have a body are compiled (`runCompile` skips the rest), so only
        // those get a "compiling" badge: mark them all and a list whose download just failed flips
        // from its error to 「编译中」 and never back, which reads as a stuck screen (MYS-2742 §修复①).
        val compiled = snapshot.filter { it.enabled && it.hasContent }
        // A list that is downloading right now keeps its 「正在下载」 badge: marking it `Compiling`
        // here would later settle it to `Idle` while its download is still running.
        for (list in compiled) {
            if (list.id !in inFlight) setStatus(list.id, ListStatus.Compiling)
        }

        val result = withContext(Dispatchers.IO) {
            runCatching { runCompile(compiled, reuseVerifiedArtifacts) }
        }
        return result.fold(
            onSuccess = { stats ->
                mutableCompileState.value = CompileState.Done(stats)
                // Distribute the per-list counts so the UI can show "此列表 N 条规则".
                //
                // **A compile never clears a download error** (review of PR #14, item 2). A list can
                // legitimately have a body *and* a failed re-download — the old copy keeps working
                // while the refresh failed — and wiping `error` here made that failure invisible
                // until the next update. The error belongs to the download, so only a download that
                // succeeds may clear it; that happens in [applyOutcome].
                //
                // The status is also left alone for a list that is mid-download (a download may have
                // started while this compile ran): only a list still sitting in `Compiling` settles,
                // and a list that carries a download error settles back into that error rather than
                // into `Idle`, which would hide the message behind a plain 「N 条规则」 row.
                mutableLists.update { lists ->
                    lists.map { list ->
                        val perList = stats.perList[list.id] ?: return@map list
                        val settled = when {
                            list.status != ListStatus.Compiling -> list.status
                            list.error != null -> ListStatus.Error(list.error)
                            else -> ListStatus.Idle
                        }
                        list.copy(
                            ruleCount = perList.dnsRules,
                            unsupportedCount = perList.unsupported,
                            status = settled,
                        )
                    }
                }
                persist()
                reloadIfTunnelRunning()
                stats
            },
            onFailure = { error ->
                val message = error.message ?: error::class.java.simpleName
                mutableCompileState.value = CompileState.Failed(message)
                for (list in compiled) {
                    if (list.id !in inFlight) setStatus(list.id, ListStatus.Error(message))
                }
                null
            },
        )
    }

    private fun runCompile(enabled: List<FilterListState>, reuseVerifiedArtifacts: Boolean): CompileStats {
        val request = JSONObject()
        val listArray = org.json.JSONArray()
        for (list in enabled) {
            val file = list.fileName?.let { File(store.listsDir, it) } ?: continue
            if (!file.isFile) continue
            listArray.put(
                JSONObject()
                    .put("id", list.id)
                    .put("path", file.absolutePath)
            )
        }
        request.put("lists", listArray)
        request.put("userRules", mutableUserRules.value)
        request.put("allowlist", org.json.JSONArray(mutableAllowlist.value))
        request.put("outputDir", store.compiledDir.absolutePath)
        // Rule attribution in the request log costs ~35 MB of engine memory and doubles engine.bin
        // (`docs/PERF.md` §11), so it is a setting rather than always-on.
        request.put("debugRules", ruleAttributionEnabled())

        // `Native.compile` is `String?`: `null` means the JVM could not produce the result string at
        // all, which is a compile failure as far as the caller is concerned (MYS-2716 §2).
        val json = compilationCache.run(request.toString(), reuseVerifiedArtifacts, compileFunction)
            ?: throw IllegalStateException(
                lastErrorFunction()?.ifBlank { null } ?: "编译失败（核心未返回结果）",
            )
        val errorValue = JSONObject(json).optString("error", "")
        if (errorValue.isNotEmpty()) throw IllegalStateException(errorValue)
        return CompileStats.fromJson(json)
    }

    /**
     * Whether `engine.bin` should record the source text of each rule.
     *
     * **Off**: measured PSS with it on is 184 MB, over the 150 MB budget (`docs/PERF.md` §11.3);
     * off brings the engine from 74.6 MB to 39.5 MB and the artifact with it. It costs no filtering —
     * only `matchedRule`/`exceptionRule` in the request log become absent, which the log renders as
     * "no rule text" rather than guessing. Turn it on only when diagnosing a specific block, and
     * remember the compile takes the same ~5 s either way.
     */
    private fun ruleAttributionEnabled(): Boolean = false

    /**
     * Hot-swap the running tunnel's rules, if there is one.
     *
     * This is the only path that carries compiled artifacts into a *live* tunnel, and it covers two
     * different situations that used to look alike:
     *
     * - the tunnel already has rules and gets a new set (the M1 hot-reload case);
     * - the tunnel started **before the first compile finished**, so it has no `engine.bin` at all.
     *   `Native.reload` installs the freshly compiled artifact into the running tunnel's pipeline
     *   slots, which is what makes `httpEngineLoaded` true and HTTPS decryption start without the
     *   user restarting the VPN (MYS-2716 §1).
     */
    private fun reloadIfTunnelRunning() {
        val handle = activeHandle
        if (handle == 0L) return
        val ok = reloadFunction(handle, store.compiledDir.absolutePath)
        android.util.Log.i("ZShield", "hot reload finished: ok=$ok")
        if (!ok) {
            val reason = lastErrorFunction()?.ifBlank { null } ?: "热替换失败"
            mutableCompileState.value = CompileState.Failed("规则已编译但热替换失败：$reason")
        }
    }

    // ---------------------------------------------------------------------------------------
    // Internals
    // ---------------------------------------------------------------------------------------

    /**
     * Apply a change, then compile and hot-swap.
     *
     * Every caller that only edits state (custom rules, allowlist, removing a list) needs exactly
     * this. The two list-toggling actions need the same thing *after* a download, so the write is
     * split out as [writeState] and they compose it themselves (MYS-2742 §修复①).
     */
    private suspend fun mutate(block: (FilterState) -> FilterState) {
        writeState(block)
        scheduleCompile(andWait = true)
    }

    /** Apply a change to the persisted document and the in-memory flows. Compiles nothing. */
    private suspend fun writeState(block: (FilterState) -> FilterState) {
        mutationLock.withLock {
            val current = synchronized(stateIoLock) { store.readState() }
            val next = block(current)
            if (next == current) return@withLock
            synchronized(stateIoLock) { store.writeState(next) }
            // Carry the live, non-persisted state across the rebuild. `reconcile` can only see the
            // document, so a plain replacement would reset every *other* list's in-flight status to
            // `Idle` — enabling one list would visibly cancel another's 「正在下载」 badge (and its
            // error) while its download was still running.
            val live = mutableLists.value.associateBy { it.id }
            mutableLists.update { _ ->
                reconcile(catalog, next).map { reconciled ->
                    val previous = live[reconciled.id] ?: return@map reconciled
                    reconciled.copy(status = previous.status, error = previous.error)
                }
            }
            mutableUserRules.value = next.userRules
            mutableAllowlist.value = next.allowlist
        }
    }

    /** Persist the current in-memory list state (used after a compile writes per-list counts). */
    private fun persist() {
        runCatching {
            synchronized(stateIoLock) {
                val current = store.readState()
                store.writeState(current.copy(lists = mutableLists.value))
            }
        }
    }

    /**
     * Serialises read-modify-write cycles on `state.json`.
     *
     * Downloads now run concurrently ([downloadAll]) and each one persists its outcome, so two
     * workers finishing at the same instant would otherwise both read the old document and the second
     * write would drop the first list's `etag`/`lastUpdatedMs`. Same class of bug the per-attempt
     * `.part` name fixed for body files. A plain `synchronized` block, not a coroutine [Mutex],
     * because the callers are non-suspending helpers running on IO threads; the critical section is a
     * few hundred bytes of file I/O.
     */
    private val stateIoLock = Any()

    /**
     * Update one list's live status.
     *
     * The status lives on `FilterListState` (as the task card's fixed interface requires), while only
     * the durable part of an error — its message — is written to the persisted document.
     *
     * Only [ListStatus.Idle] clears [FilterListState.error], and that transition is driven by a
     * download succeeding ([applyOutcome]) or an import — never by a compile. Moving through
     * `Queued`/`Downloading`/`Compiling` leaves the last error in place so the reason survives until
     * it is genuinely resolved.
     */
    private fun setStatus(id: String, status: ListStatus) {
        // `update` (compare-and-set) rather than a read-modify-write of `.value`: since downloads run
        // concurrently, several workers settle at the same instant and a plain assignment would drop
        // one another's status, leaving a list stuck at 「正在下载」.
        mutableLists.update { lists ->
            lists.map { list ->
                if (list.id != id) return@map list
                list.copy(
                    status = status,
                    error = when (status) {
                        is ListStatus.Error -> status.message
                        ListStatus.Idle -> null
                        ListStatus.Queued, ListStatus.Downloading, ListStatus.Compiling -> list.error
                    },
                )
            }
        }
    }

    private fun applyOutcome(outcome: UpdateOutcome) {
        when (outcome) {
            is UpdateOutcome.Updated -> {
                // Logged per list so `adb logcat | grep ZShield` answers "which lists downloaded,
                // from where, how big" without needing a debuggable build (task card §4 asks for
                // exactly this table in the delivery report).
                android.util.Log.i(
                    "ZShield",
                    "list ${outcome.state.id}: updated from ${outcome.state.url} " +
                        "(${outcome.state.bytes} B, ${outcome.metadata.title ?: "no title"}, " +
                        "expires=${outcome.metadata.expiresHours ?: "unset"}h)",
                )
                replaceState(outcome.state)
                setStatus(outcome.state.id, ListStatus.Idle)
            }
            is UpdateOutcome.NotModified -> {
                android.util.Log.i("ZShield", "list ${outcome.state.id}: not modified")
                replaceState(outcome.state)
                setStatus(outcome.state.id, ListStatus.Idle)
            }
            is UpdateOutcome.NotDue -> Unit
            is UpdateOutcome.Failed -> {
                android.util.Log.w("ZShield", "list ${outcome.state.id}: update failed: ${outcome.message}")
                replaceState(outcome.state)
                setStatus(outcome.state.id, ListStatus.Error(outcome.message))
            }
        }
    }

    /**
     * Write one list's durable outcome and merge it into the live list.
     *
     * Only the durable half comes from [state]; `status` and the compile-produced counts stay as the
     * live value has them. That matters now that downloads run concurrently: the outcome was built
     * from a snapshot taken when the download started, so blindly replacing the whole entry would
     * roll back a compile that finished in the meantime and re-show 「排队中」 over a settled list.
     */
    private fun replaceState(state: FilterListState) {
        synchronized(stateIoLock) {
            val current = store.readState()
            store.writeState(current.withList(state))
        }
        mutableLists.update { lists ->
            lists.map { live ->
                if (live.id != state.id) {
                    live
                } else {
                    state.copy(
                        status = live.status,
                        ruleCount = live.ruleCount,
                        unsupportedCount = live.unsupportedCount,
                    )
                }
            }
        }
    }

    /**
     * Merge the catalog with persisted state.
     *
     * A catalog entry that has no persisted state gets its `defaultEnabled` flag; one that does keeps
     * whatever the user chose. Persisted entries that are no longer in the catalog are kept only if
     * they are user-added (`builtin == false`), because a removed catalog entry must not silently
     * keep downloading from a URL nobody maintains any more.
     */
    fun reconcile(catalog: List<CatalogEntry>, state: FilterState): List<FilterListState> {
        val persisted = state.lists.associateBy { it.id }
        val result = ArrayList<FilterListState>(catalog.size + state.lists.size)
        for (entry in catalog) {
            val existing = persisted[entry.id]
            result.add(
                if (existing == null) {
                    FilterListState(
                        id = entry.id,
                        name = entry.name,
                        category = entry.category,
                        url = entry.url,
                        mirrors = entry.mirrors,
                        homepage = entry.homepage,
                        enabled = entry.defaultEnabled,
                        builtin = true,
                    )
                } else {
                    existing.copy(
                        name = entry.name,
                        category = entry.category,
                        url = existing.url.ifEmpty { entry.url },
                        mirrors = entry.mirrors,
                        homepage = entry.homepage,
                        builtin = true,
                    )
                }
            )
        }
        for (list in state.lists) {
            if (result.any { it.id == list.id }) continue
            if (!list.builtin) result.add(list)
        }
        return result
    }

    private fun loadCatalog(context: Context): List<CatalogEntry> = try {
        val json = context.assets.open(CATALOG_ASSET).use { it.readBytes().toString(Charsets.UTF_8) }
        CatalogEntry.parseAll(json)
    } catch (error: Exception) {
        // A broken catalog asset is a build mistake, not a runtime condition; log loudly and carry
        // on with whatever the user already has rather than crashing the app.
        android.util.Log.e("ZShield", "cannot load filter catalog", error)
        emptyList()
    }

    private fun customId(url: String): String {
        val digest = MessageDigest.getInstance("SHA-1").digest(url.toByteArray(Charsets.UTF_8))
        val hex = digest.take(8).joinToString("") { "%02x".format(it) }
        return if (url.startsWith("file:")) "file-$hex" else "custom-$hex"
    }

    private fun hostOf(url: String): String =
        runCatching { java.net.URI(url).host }.getOrNull()?.takeIf { it.isNotEmpty() } ?: url

    const val CATALOG_ASSET = "filters/catalog.json"

    // ---------------------------------------------------------------------------------------
    // Test seams
    // ---------------------------------------------------------------------------------------

    internal fun resetForTest() {
        pendingCompile?.cancel()
        pendingCompile = null
        pendingFetch?.cancel()
        pendingFetch = null
        inFlight.clear()
        initialized = false
        compiledDir = ""
        activeHandle = 0L
        catalog = emptyList()
        mutableLists.value = emptyList()
        mutableUserRules.value = ""
        mutableAllowlist.value = emptyList()
        mutableCompileState.value = CompileState.Idle
    }

    internal fun setCompileStateForTest(state: CompileState) {
        mutableCompileState.value = state
    }

    internal fun updateListsForTest(lists: List<FilterListState>) {
        mutableLists.value = lists
    }

    internal fun compiledDirForTest(): File = store.compiledDir

    internal fun storeForTest(): FilterStore = store
}
