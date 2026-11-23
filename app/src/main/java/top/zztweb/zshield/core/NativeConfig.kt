package top.zztweb.zshield.core

import org.json.JSONArray
import org.json.JSONObject
import top.zztweb.zshield.settings.TunnelMode

/**
 * The `configJson` contract with the Rust core (`core/src/config.rs`).
 *
 * Field names and value spellings are the single source of truth on the Kotlin side; the Rust
 * struct uses the same names and is documented in `docs/JNI.md`. Serialisation is done by hand
 * (rather than a JSON library) so both sides of the contract are visible next to each other and the
 * app carries no serialisation dependency.
 */
data class NativeConfig(
    /** Upstream resolvers in priority order. Empty means "use the design defaults". */
    val upstreams: List<UpstreamConfig> = defaultUpstreams(),
    /** How a blocked name is answered. */
    val blockResponse: BlockResponse = BlockResponse.ZERO_IP,
    /**
     * Absolute paths of rule files to load, in order. This is the debugging fallback: when
     * [compiledDir] holds a usable artifact the core never parses these.
     */
    val ruleFiles: List<String> = emptyList(),
    /**
     * Directory holding the precompiled artifacts (`dns.bin`, `engine.bin`). Empty means "compile
     * from [ruleFiles] at every start", which is only correct for tests and debugging.
     */
    val compiledDir: String = "",
    /** Virtual DNS addresses routed into the tunnel. */
    val dnsV4: String = "10.111.222.2",
    val dnsV6: String = "fd00:7a73::2",
    val cacheMaxEntries: Int = 4096,
    val cacheMaxTtlSecs: Long = 3600,
    val queryTimeoutMs: Long = 5000,
    val workers: Int = 2,
    /** Tunnel mode; must match the routes [top.zztweb.zshield.vpn.ZShieldVpnService] installs. */
    val mode: TunnelMode = TunnelMode.FULL,
    /** TUN MTU; must match `VpnService.Builder.setMtu`. */
    val mtu: Int = DEFAULT_MTU,
    /** Drop UDP/443 so QUIC clients fall back to TCP/TLS and can be filtered by SNI. */
    val blockQuic: Boolean = true,
    /** Refuse TCP/853 and TLS connections to the hosts in [encryptedDnsHostsFile]. */
    val blockEncryptedDnsBypass: Boolean = true,
    /**
     * Absolute path of the encrypted-DNS host list. The app extracts the bundled asset here on every
     * start, so an updated asset replaces the previous copy.
     */
    val encryptedDnsHostsFile: String = "",
    /** Idle timeout of a forwarded TCP connection, in seconds. */
    val tcpIdleTimeoutSecs: Long = 2 * 60 * 60,
    /** Idle timeout of a UDP flow, in seconds. */
    val udpIdleTimeoutSecs: Long = 60,
    /** Upper bound of live UDP flows. */
    val maxUdpFlows: Int = 1024,
    /** Bytes buffered to read the SNI/`Host` before deciding on a connection. */
    val sniffBytes: Int = 4096,
    /** How long to wait for those bytes, in milliseconds. */
    val sniffTimeoutMs: Long = 3000,
    /**
     * Whether the network underneath the tunnel can carry IPv6.
     *
     * Decided by [top.zztweb.zshield.vpn.Ipv6Availability] from the underlying network's link
     * properties, and it must match the interface the VPN installed: when false there is no `::/0`
     * route and no IPv6 DNS address, so the core must not hand out AAAA records or `ipv6hint`
     * either (MYS-2710). A client that receives an IPv6 address it cannot reach does not retry
     * over IPv4, so the site simply fails to load.
     */
    val ipv6: Boolean = true,
    /**
     * Buffering budget for one plaintext HTTP request head, in bytes (M2b). A head larger than this
     * is relayed verbatim instead of filtered, so an endless header stream stays finite.
     */
    val httpHeadBytes: Int = DEFAULT_HTTP_HEAD_BYTES,
    /**
     * Whether HTTPS connections from [httpsUids] are decrypted (M3a).
     *
     * The VPN service sets this only when the user enabled it *and* the CA is installed: decrypting
     * with a CA the device has not installed produces nothing but handshake failures, so the
     * effective flag is computed where the config is built.
     */
    val httpsFiltering: Boolean = false,
    /**
     * uids whose HTTPS traffic is decrypted: the built-in browsers plus the user's own selections.
     *
     * uids rather than package names because `ConnectivityManager.getConnectionOwnerUid` answers in
     * uids, and converting once in Kotlin keeps the core free of a package-manager callback.
     */
    val httpsUids: List<Int> = emptyList(),
    /** Hostnames never decrypted, on top of [httpsExcludedHostsFile]. */
    val httpsExcludedHosts: List<String> = emptyList(),
    /**
     * Absolute path of the bundled exclusion list, extracted by the app on every start.
     *
     * Same contract as [encryptedDnsHostsFile]: an empty string means "no built-in list", never a
     * reason to refuse to start.
     */
    val httpsExcludedHostsFile: String = "",
) {
    /**
     * Renders the configuration as the JSON document `Native.start` expects.
     *
     * The keys are the Rust field names (camelCase) and enum values are the Rust `snake_case`
     * spellings, so this is the exact inverse of `serde`'s parsing in `core/src/config.rs`.
     */
    fun toJson(): String {
        val root = JSONObject()
        val upstreamArray = JSONArray()
        upstreams.forEach { upstream -> upstreamArray.put(upstream.toJson()) }
        root.put("upstreams", upstreamArray)
        root.put("blockResponse", blockResponse.wireName)
        root.put("ruleFiles", JSONArray(ruleFiles))
        root.put("compiledDir", compiledDir)
        root.put("dnsV4", dnsV4)
        root.put("dnsV6", dnsV6)
        root.put("cacheMaxEntries", cacheMaxEntries)
        root.put("cacheMaxTtlSecs", cacheMaxTtlSecs)
        root.put("queryTimeoutMs", queryTimeoutMs)
        root.put("workers", workers)
        root.put("mode", mode.wireName)
        root.put("mtu", mtu)
        root.put("blockQuic", blockQuic)
        root.put("blockEncryptedDnsBypass", blockEncryptedDnsBypass)
        root.put("encryptedDnsHostsFile", encryptedDnsHostsFile)
        root.put("tcpIdleTimeoutSecs", tcpIdleTimeoutSecs)
        root.put("udpIdleTimeoutSecs", udpIdleTimeoutSecs)
        root.put("maxUdpFlows", maxUdpFlows)
        root.put("sniffBytes", sniffBytes)
        root.put("sniffTimeoutMs", sniffTimeoutMs)
        root.put("ipv6", ipv6)
        root.put("httpHeadBytes", httpHeadBytes)
        root.put("httpsFiltering", httpsFiltering)
        root.put("httpsUids", JSONArray(httpsUids))
        root.put("httpsExcludedHosts", JSONArray(httpsExcludedHosts))
        root.put("httpsExcludedHostsFile", httpsExcludedHostsFile)
        return root.toString()
    }

    companion object {
        /** MTU validated by the core (IPv6 minimum is 1280). */
        const val DEFAULT_MTU = 1500

        /** Plaintext HTTP head budget validated by the core (1024..65536). */
        const val DEFAULT_HTTP_HEAD_BYTES = 8 * 1024

        /** The upstream pair fixed by `docs/DESIGN.md` §5. */
        fun defaultUpstreams(): List<UpstreamConfig> = listOf(
            UpstreamConfig.Doh(
                url = "https://dns.alidns.com/dns-query",
                bootstrap = listOf("223.5.5.5"),
            ),
            UpstreamConfig.Doh(
                url = "https://doh.pub/dns-query",
                bootstrap = listOf("1.12.12.12"),
            ),
        )

        /** Parses a configuration produced by [toJson]. Used by tests and log inspection. */
        fun fromJson(json: String): NativeConfig {
            val root = JSONObject(json)
            val upstreamArray = root.optJSONArray("upstreams") ?: JSONArray()
            val upstreams = buildList {
                for (index in 0 until upstreamArray.length()) {
                    add(UpstreamConfig.fromJson(upstreamArray.getJSONObject(index)))
                }
            }
            val ruleArray = root.optJSONArray("ruleFiles") ?: JSONArray()
            val ruleFiles = buildList {
                for (index in 0 until ruleArray.length()) {
                    add(ruleArray.getString(index))
                }
            }
            return NativeConfig(
                upstreams = upstreams,
                blockResponse = BlockResponse.fromWireName(root.optString("blockResponse")),
                ruleFiles = ruleFiles,
                compiledDir = root.optString("compiledDir", ""),
                dnsV4 = root.optString("dnsV4", "10.111.222.2"),
                dnsV6 = root.optString("dnsV6", "fd00:7a73::2"),
                cacheMaxEntries = root.optInt("cacheMaxEntries", 4096),
                cacheMaxTtlSecs = root.optLong("cacheMaxTtlSecs", 3600L),
                queryTimeoutMs = root.optLong("queryTimeoutMs", 5000L),
                workers = root.optInt("workers", 2),
                mode = TunnelMode.fromWireName(root.optString("mode")),
                mtu = root.optInt("mtu", DEFAULT_MTU),
                blockQuic = root.optBoolean("blockQuic", true),
                blockEncryptedDnsBypass = root.optBoolean("blockEncryptedDnsBypass", true),
                encryptedDnsHostsFile = root.optString("encryptedDnsHostsFile", ""),
                tcpIdleTimeoutSecs = root.optLong("tcpIdleTimeoutSecs", 7200L),
                udpIdleTimeoutSecs = root.optLong("udpIdleTimeoutSecs", 60L),
                maxUdpFlows = root.optInt("maxUdpFlows", 1024),
                sniffBytes = root.optInt("sniffBytes", 4096),
                sniffTimeoutMs = root.optLong("sniffTimeoutMs", 3000L),
                ipv6 = root.optBoolean("ipv6", true),
                httpHeadBytes = root.optInt("httpHeadBytes", DEFAULT_HTTP_HEAD_BYTES),
                httpsFiltering = root.optBoolean("httpsFiltering", false),
                httpsUids = intList(root.optJSONArray("httpsUids")),
                httpsExcludedHosts = stringList(root.optJSONArray("httpsExcludedHosts")),
                httpsExcludedHostsFile = root.optString("httpsExcludedHostsFile", ""),
            )
        }
    }
}

/** Read a JSON array of ints, tolerating absent entries. */
private fun intList(array: JSONArray?): List<Int> {
    if (array == null) return emptyList()
    return buildList {
        for (index in 0 until array.length()) add(array.optInt(index, -1))
    }.filter { it >= 0 }
}

/** Read a JSON array of strings, tolerating absent entries. */
private fun stringList(array: JSONArray?): List<String> {
    if (array == null) return emptyList()
    return buildList {
        for (index in 0 until array.length()) {
            array.optString(index).takeIf { it.isNotBlank() }?.let { add(it) }
        }
    }
}

/** How the core answers a blocked name. */
enum class BlockResponse(val wireName: String) {
    /** `0.0.0.0` / `::` answers; the design default. */
    ZERO_IP("zero_ip"),
    NXDOMAIN("nxdomain"),
    REFUSED("refused"),
    ;

    companion object {
        fun fromWireName(name: String): BlockResponse =
            entries.firstOrNull { it.wireName == name } ?: ZERO_IP
    }
}

/** One upstream resolver. `type` is the serde tag in `core/src/config.rs`. */
sealed class UpstreamConfig {
    abstract fun toJson(): JSONObject

    /**
     * DNS over HTTPS (RFC 8484). [bootstrap] holds IP addresses used to reach [url]'s host without
     * the system resolver, which the tunnel replaces.
     */
    data class Doh(
        val url: String,
        val bootstrap: List<String>,
    ) : UpstreamConfig() {
        override fun toJson(): JSONObject = JSONObject()
            .put("type", "doh")
            .put("url", url)
            .put("bootstrap", JSONArray(bootstrap))
    }

    /** Plaintext UDP; debugging only (no confidentiality, no tamper resistance). */
    data class Udp(val address: String) : UpstreamConfig() {
        override fun toJson(): JSONObject = JSONObject()
            .put("type", "udp")
            .put("address", address)
    }

    companion object {
        fun fromJson(json: JSONObject): UpstreamConfig = when (json.optString("type")) {
            "udp" -> Udp(address = json.getString("address"))
            else -> {
                val array = json.optJSONArray("bootstrap") ?: JSONArray()
                val bootstrap = buildList {
                    for (index in 0 until array.length()) add(array.getString(index))
                }
                Doh(url = json.getString("url"), bootstrap = bootstrap)
            }
        }
    }
}

/** Counter snapshot returned by `Native.statsJson` (see `core/src/dns/engine.rs::Stats`). */
data class NativeStats(
    val dnsQueries: Long = 0,
    val dnsBlocked: Long = 0,
    val dnsErrors: Long = 0,
    val dnsCached: Long = 0,
    val dnsUpstreamQueries: Long = 0,
    val upstreamLatencyMsP50: Long = 0,
    val cacheEntries: Long = 0,
    val rulesBlock: Long = 0,
    val rulesException: Long = 0,
    val rulesUnsupported: Long = 0,
    val tunPacketsIn: Long = 0,
    val tunPacketsOut: Long = 0,
    val tunDropped: Long = 0,
    /** Tunnel mode the core is running in, as reported by the core. */
    val mode: String = "",
    val mtu: Int = 0,
    /** HTTPS/SVCB answers whose `ech` parameter the core removed. */
    val echStripped: Long = 0,
    /** Forwarded TCP connections currently open. */
    val tcpActive: Long = 0,
    /** Forwarded TCP connections opened since start. */
    val tcpTotal: Long = 0,
    /** Live UDP flows in the NAT table. */
    val udpActive: Long = 0,
    val bytesUp: Long = 0,
    val bytesDown: Long = 0,
    /** Connections refused because their SNI/`Host` is filtered. */
    val blockedConnections: Long = 0,
    /** UDP/443 datagrams dropped to force QUIC back to TCP. */
    val quicDropped: Long = 0,
    /** UDP/53 and TCP/53 messages answered by the engine instead of the network. */
    val dnsHijacked: Long = 0,
    /** TCP/853 and DoH-host connections refused. */
    val encryptedDnsDropped: Long = 0,
    /** Plaintext HTTP requests judged since start (M2b). */
    val httpRequests: Long = 0,
    /** Plaintext HTTP requests answered with a synthesized response. */
    val httpBlocked: Long = 0,
    /** Blocked requests answered with a `$redirect` substitute instead of a plain block. */
    val httpRedirected: Long = 0,
    /** Connections whose HTTP filtering stopped part-way (non-HTTP, upgrade, oversized head). */
    val httpDegraded: Long = 0,
    /** Whether an `engine.bin` was loaded; false means hostname-only filtering. */
    val httpEngineLoaded: Boolean = false,
    /** Requests currently held by the recent-request ring buffer (max 500). */
    val requestLogSize: Long = 0,
    /** Whether the core is decrypting HTTPS connections (M3a). */
    val httpsFiltering: Boolean = false,
    /** 443 connections decrypted and filtered. */
    val httpsIntercepted: Long = 0,
    /** 443 connections deliberately not decrypted (not selected, excluded, auto-bypassed). */
    val httpsPassthrough: Long = 0,
    /** Connections that entered the auto-bypass table because the client refused our certificate. */
    val httpsAutoBypassed: Long = 0,
    /** Connections whose upstream certificate failed verification (passed through instead). */
    val httpsUpstreamInvalid: Long = 0,
    /** Client-side TLS handshake failures. */
    val httpsHandshakeFailures: Long = 0,
    /** HTTP/2 requests judged on a decrypted connection. */
    val h2Streams: Long = 0,
    /** Of those, the ones answered locally. */
    val h2Blocked: Long = 0,
    /** Live auto-bypass entries. */
    val httpsBypassEntries: Long = 0,
    /** `$removeheader` rules in force (the modifier adblock-rust does not implement). */
    val httpsRemoveHeaderRules: Long = 0,
) {
    companion object {
        /**
         * Parses the core's JSON; a malformed document yields all-zero counters rather than a crash.
         *
         * `null` — which `Native.statsJson` can return when the JVM cannot allocate the result
         * string — is handled exactly like a blank document. That is the MYS-2716 §2 contract: the
         * caller gets a usable snapshot or defaults, never a `NullPointerException`.
         */
        fun fromJson(json: String?): NativeStats {
            if (json.isNullOrBlank()) return NativeStats()
            val root = runCatching { JSONObject(json) }.getOrNull() ?: return NativeStats()
            return NativeStats(
                dnsQueries = root.optLong("dnsQueries"),
                dnsBlocked = root.optLong("dnsBlocked"),
                dnsErrors = root.optLong("dnsErrors"),
                dnsCached = root.optLong("dnsCached"),
                dnsUpstreamQueries = root.optLong("dnsUpstreamQueries"),
                upstreamLatencyMsP50 = root.optLong("upstreamLatencyMsP50"),
                cacheEntries = root.optLong("cacheEntries"),
                rulesBlock = root.optLong("rulesBlock"),
                rulesException = root.optLong("rulesException"),
                rulesUnsupported = root.optLong("rulesUnsupported"),
                tunPacketsIn = root.optLong("tunPacketsIn"),
                tunPacketsOut = root.optLong("tunPacketsOut"),
                tunDropped = root.optLong("tunDropped"),
                mode = root.optString("mode", ""),
                mtu = root.optInt("mtu", 0),
                echStripped = root.optLong("echStripped"),
                tcpActive = root.optLong("tcpActive"),
                tcpTotal = root.optLong("tcpTotal"),
                udpActive = root.optLong("udpActive"),
                bytesUp = root.optLong("bytesUp"),
                bytesDown = root.optLong("bytesDown"),
                blockedConnections = root.optLong("blockedConnections"),
                quicDropped = root.optLong("quicDropped"),
                dnsHijacked = root.optLong("dnsHijacked"),
                encryptedDnsDropped = root.optLong("encryptedDnsDropped"),
                httpRequests = root.optLong("httpRequests"),
                httpBlocked = root.optLong("httpBlocked"),
                httpRedirected = root.optLong("httpRedirected"),
                httpDegraded = root.optLong("httpDegraded"),
                httpEngineLoaded = root.optBoolean("httpEngineLoaded", false),
                requestLogSize = root.optLong("requestLogSize"),
                httpsFiltering = root.optBoolean("httpsFiltering", false),
                httpsIntercepted = root.optLong("httpsIntercepted"),
                httpsPassthrough = root.optLong("httpsPassthrough"),
                httpsAutoBypassed = root.optLong("httpsAutoBypassed"),
                httpsUpstreamInvalid = root.optLong("httpsUpstreamInvalid"),
                httpsHandshakeFailures = root.optLong("httpsHandshakeFailures"),
                h2Streams = root.optLong("h2Streams"),
                h2Blocked = root.optLong("h2Blocked"),
                httpsBypassEntries = root.optLong("httpsBypassEntries"),
                httpsRemoveHeaderRules = root.optLong("httpsRemoveHeaderRules"),
            )
        }
    }
}
