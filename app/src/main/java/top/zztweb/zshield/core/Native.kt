package top.zztweb.zshield.core

/**
 * The single JNI entry point into `libzshield.so` (see `docs/JNI.md`).
 *
 * Every method is a plain JNI call: failures never surface as exceptions, they set a thread-safe
 * "last error" slot that [lastError] reads, and the call returns `0` / `""` instead. That keeps the
 * Kotlin control plane free of try/catch around JNI and stops a Rust panic from killing the app.
 *
 * # Every `String` result is nullable
 *
 * `String?`, not `String` (MYS-2716 §2). The Rust side guarantees a **valid JSON document** on every
 * path it can control — `{}` for statistics with no engine, `[]` for an empty list, `{"error": …}`
 * for a failed compile — but it cannot guarantee a `jstring` exists at all: `NewStringUTF` fails
 * when the JVM has a pending exception or is out of memory, and then the only honest return is
 * `null`. Declaring the return non-null made that one unpreventable case a `NullPointerException`
 * crash of the whole process (the reported `ZShieldVpnController.kt:254` crash), which is exactly the
 * trade this file must not make: a statistics read is never worth taking the app down.
 *
 * So: parse through a helper that treats `null` as "no document", and never write
 * `Native.statsJson(h).length` or pass the value to `JSONObject(...)` directly.
 */
object Native {

    init {
        System.loadLibrary("zshield")
    }

    /** Core version string, from `version.properties` via the Rust build, or `null` on a JVM failure. */
    external fun version(): String?

    /**
     * Hands the app [android.content.Context] to the Rust core so TLS certificate validation can
     * use the Android system trust store (`rustls-platform-verifier`). Must be called once before
     * the first DoH query; repeated calls are no-ops.
     */
    external fun init(context: android.content.Context)

    /**
     * Starts the DNS engine on an already-established TUN file descriptor.
     *
     * @param tunFd file descriptor detached from the `VpnService` interface; ownership transfers to
     *   the core, which closes it when the engine stops. Must not be used by Kotlin afterwards.
     * @param configJson see [NativeConfig] and `docs/JNI.md`.
     * @return a non-zero engine handle, or `0` on failure (reason via [lastError]).
     */
    external fun start(tunFd: Int, configJson: String): Long

    /** Stops the engine and closes its TUN descriptor. Unknown handles set [lastError]. */
    external fun stop(handle: Long)

    /** Return unused allocator pages when the UI is hidden; all live engines stay installed. */
    external fun trimMemory()

    /**
     * JSON counter snapshot for [handle]. Always contains at least `dnsQueries`, `dnsBlocked`,
     * `dnsErrors` and `upstreamLatencyMsP50`; see [NativeStats].
     *
     * `{}` for an unknown handle, `null` only when the JVM could not allocate the string.
     */
    external fun statsJson(handle: Long): String?

    /**
     * Compiles the enabled filter lists into the artifacts the tunnel loads at start.
     *
     * Runs synchronously; call it from a background thread (a full default list set takes a few
     * seconds). The request and the result are documented in `docs/JNI.md`; the result is a
     * [top.zztweb.zshield.core.CompileStats] JSON document, or `{"error": "..."}` on failure.
     */
    external fun compile(requestJson: String): String?

    /**
     * Hot-replaces the running engine's rule set with the artifacts in [compiledDir].
     *
     * In-flight DNS queries keep the rules they started with; the DNS cache is cleared because
     * every entry in it was a decision made by the previous rules. Returns `false` and sets
     * [lastError] on failure, leaving the old rules in force — the tunnel is never interrupted.
     */
    external fun reload(handle: Long, compiledDir: String): Boolean

    /**
     * The recent-request log as a JSON array, oldest first, filtered to entries with `id > sinceId`
     * (pass `0` for everything the ring buffer holds).
     *
     * The buffer holds the last [top.zztweb.zshield.core.RequestLogEntry.CAPACITY] requests; ids
     * keep increasing across a wrap, so a caller that remembers the last id it saw can poll with it
     * and get exactly the new entries. Serialization happens inside this call and nowhere else —
     * there is no push, so nothing runs while no one is asking (`docs/DESIGN.md` decision 10).
     *
     * An unknown handle returns `[]` and sets [lastError].
     */
    external fun recentRequestsJson(handle: Long, sinceId: Long): String?

    /**
     * Generates the device's root CA (M3a, `docs/JNI.md` §7).
     *
     * Returns `{"certPem": "...", "keyPkcs8B64": "...", "fingerprintSha256": "...", "notAfterMs": N}`
     * or `{"error": "..."}`. The private key leaves the core **once**, for
     * [top.zztweb.zshield.https.CertManager] to wrap with an Android-Keystore key; it is never part
     * of `configJson` and never logged.
     */
    external fun generateCa(): String?

    /**
     * Installs the CA the control plane stored, before every [start].
     *
     * @param certPem the certificate exactly as it was exported (PEM).
     * @param keyPkcs8 the PKCS#8 DER key, decrypted from `ca.key.enc`.
     * @return `false` (with [lastError] set) when the material is unusable; the previously loaded CA
     *   then stays in force, which is the safer failure — a tunnel with the old CA still filters.
     */
    external fun loadCa(certPem: String, keyPkcs8: ByteArray): Boolean

    /**
     * The live HTTPS auto-bypass table as a JSON array, newest last.
     *
     * One object per `(uid, host)` pair: `{"uid": N, "host": "...", "expiresAtMs": N, "reason":
     * "client_unknown_ca"}`. A pair lands here when the client refused our certificate, and is then
     * passed through for 24 h. An unknown handle returns `[]`.
     */
    external fun httpsBypassJson(handle: Long): String?

    /**
     * Empties the HTTPS auto-bypass table, so every pair is decrypted again on its next connection.
     *
     * Called after the CA is installed or replaced: a pair that failed while the certificate was
     * missing would otherwise stay bypassed for 24 h and HTTPS filtering would appear to do nothing.
     */
    external fun clearHttpsBypass(handle: Long): Boolean

    /**
     * Hot-replaces which connections are decrypted, without rebuilding the tunnel.
     *
     * `policyJson` is `{"enabled": Boolean, "uids": [Int], "excludedHosts": ["..."]}`. Used when the
     * user ticks another application or edits the exclusion list while the tunnel is running.
     * Returns `false` and sets [lastError] when the tunnel has no HTTPS pipeline.
     */
    external fun updateHttpsPolicy(handle: Long, policyJson: String): Boolean

    /** The most recent error message, or `""` when the last call succeeded. */
    external fun lastError(): String?

    /** Stops every engine. Safety net for process teardown. */
    external fun releaseAll()
}
