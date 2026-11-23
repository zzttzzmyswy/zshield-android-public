package top.zztweb.zshield.core

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import top.zztweb.zshield.settings.TunnelMode

/**
 * The Kotlin side of the `configJson` contract (`core/src/config.rs` owns the other side).
 *
 * These tests pin the exact key names and enum spellings: renaming a field on either side without
 * updating the other is what these catch before it becomes a runtime "invalid config JSON".
 */
class NativeConfigTest {

    @Test
    fun `default config matches the design defaults`() {
        val config = NativeConfig()

        assertEquals(2, config.upstreams.size)
        val first = config.upstreams[0] as UpstreamConfig.Doh
        assertEquals("https://dns.alidns.com/dns-query", first.url)
        assertEquals(listOf("223.5.5.5"), first.bootstrap)
        val second = config.upstreams[1] as UpstreamConfig.Doh
        assertEquals("https://doh.pub/dns-query", second.url)
        assertEquals(listOf("1.12.12.12"), second.bootstrap)

        assertEquals(BlockResponse.ZERO_IP, config.blockResponse)
        assertEquals("10.111.222.2", config.dnsV4)
        assertEquals("fd00:7a73::2", config.dnsV6)
        assertEquals(4096, config.cacheMaxEntries)
        assertEquals(3600L, config.cacheMaxTtlSecs)
        assertEquals(5000L, config.queryTimeoutMs)
    }

    @Test
    fun `json uses the exact keys the Rust core parses`() {
        val json = JSONObject(
            NativeConfig(ruleFiles = listOf("/data/a.txt", "/data/b.txt")).toJson(),
        )

        // Field names are the contract; see core/src/config.rs #[serde(rename_all = "camelCase")].
        assertTrue(json.has("upstreams"))
        assertTrue(json.has("blockResponse"))
        assertTrue(json.has("ruleFiles"))
        assertTrue(json.has("dnsV4"))
        assertTrue(json.has("dnsV6"))
        assertTrue(json.has("cacheMaxEntries"))
        assertTrue(json.has("cacheMaxTtlSecs"))
        assertTrue(json.has("queryTimeoutMs"))
        assertTrue(json.has("workers"))

        // Rule files keep their order: load order decides which exception wins.
        val rules = json.getJSONArray("ruleFiles")
        assertEquals(2, rules.length())
        assertEquals("/data/a.txt", rules.getString(0))
        assertEquals("/data/b.txt", rules.getString(1))
    }

    @Test
    fun `block response values use the serde snake_case spelling`() {
        assertEquals("zero_ip", BlockResponse.ZERO_IP.wireName)
        assertEquals("nxdomain", BlockResponse.NXDOMAIN.wireName)
        assertEquals("refused", BlockResponse.REFUSED.wireName)

        fun rendered(response: BlockResponse): String =
            JSONObject(NativeConfig(blockResponse = response).toJson()).getString("blockResponse")

        assertEquals("nxdomain", rendered(BlockResponse.NXDOMAIN))
    }

    @Test
    fun `doh upstream carries type url and bootstrap`() {
        val upstreamJson = UpstreamConfig.Doh(
            url = "https://example.com/dns-query",
            bootstrap = listOf("1.2.3.4"),
        ).toJson()

        assertEquals("doh", upstreamJson.getString("type"))
        assertEquals("https://example.com/dns-query", upstreamJson.getString("url"))
        assertEquals("1.2.3.4", upstreamJson.getJSONArray("bootstrap").getString(0))
    }

    @Test
    fun `udp upstream carries type and address`() {
        val upstreamJson = UpstreamConfig.Udp("1.1.1.1:53").toJson()

        assertEquals("udp", upstreamJson.getString("type"))
        assertEquals("1.1.1.1:53", upstreamJson.getString("address"))
    }

    @Test
    fun `config round trips through json`() {
        val original = NativeConfig(
            upstreams = listOf(
                UpstreamConfig.Doh("https://dns.alidns.com/dns-query", listOf("223.5.5.5", "223.6.6.6")),
                UpstreamConfig.Udp("1.1.1.1:53"),
            ),
            blockResponse = BlockResponse.REFUSED,
            ruleFiles = listOf("/data/x.txt"),
            dnsV4 = "10.9.9.2",
            dnsV6 = "fd00:9::2",
            cacheMaxEntries = 99,
            cacheMaxTtlSecs = 120,
            queryTimeoutMs = 800,
            workers = 4,
        )

        assertEquals(original, NativeConfig.fromJson(original.toJson()))
    }

    @Test
    fun `unknown block response falls back to zero ip`() {
        assertEquals(BlockResponse.ZERO_IP, BlockResponse.fromWireName("something-new"))
        assertEquals(BlockResponse.NXDOMAIN, BlockResponse.fromWireName("nxdomain"))
    }

    @Test
    fun `stats json is parsed into counters`() {
        val json = """
            {"dnsQueries":12,"dnsBlocked":3,"dnsErrors":1,"dnsCached":4,
             "dnsUpstreamQueries":7,"upstreamLatencyMsP50":23,"cacheEntries":5,
             "rulesBlock":9,"rulesException":1,"rulesUnsupported":2,
             "tunPacketsIn":30,"tunPacketsOut":29,"tunDropped":1}
        """.trimIndent()

        val stats = NativeStats.fromJson(json)

        assertEquals(12L, stats.dnsQueries)
        assertEquals(3L, stats.dnsBlocked)
        assertEquals(1L, stats.dnsErrors)
        assertEquals(4L, stats.dnsCached)
        assertEquals(7L, stats.dnsUpstreamQueries)
        assertEquals(23L, stats.upstreamLatencyMsP50)
        assertEquals(5L, stats.cacheEntries)
        assertEquals(9L, stats.rulesBlock)
        assertEquals(1L, stats.rulesException)
        assertEquals(2L, stats.rulesUnsupported)
        assertEquals(30L, stats.tunPacketsIn)
        assertEquals(29L, stats.tunPacketsOut)
        assertEquals(1L, stats.tunDropped)
    }

    @Test
    fun `malformed stats json yields zero counters instead of throwing`() {
        assertEquals(NativeStats(), NativeStats.fromJson(""))
        assertEquals(NativeStats(), NativeStats.fromJson("not json"))
        // Missing fields default to zero rather than aborting the UI update.
        assertEquals(NativeStats(dnsQueries = 5), NativeStats.fromJson("""{"dnsQueries":5}"""))
    }

    /**
     * MYS-2716 §2: `Native.statsJson` is `String?`, and `null` is the one return the Rust side
     * cannot prevent (a JVM allocation failure). Treating it as "no document" is what keeps the
     * stats poller alive instead of crashing the process — the reported
     * `ZShieldVpnController.kt:254` crash was exactly this value reaching a non-null parameter.
     */
    @Test
    fun `a null stats document yields defaults instead of throwing`() {
        assertEquals(NativeStats(), NativeStats.fromJson(null as String?))
        // And it is not confused with a real snapshot: a valid document still parses.
        assertEquals(
            NativeStats(dnsQueries = 5),
            NativeStats.fromJson("""{"dnsQueries":5}"""),
        )
    }

    /**
     * The core documents `{}` as the "no engine / unknown handle" answer. It must parse into the
     * defaults rather than being treated as an error, because that is what the debug screen shows
     * while the numbers are still zero.
     */
    @Test
    fun `an empty stats object is a valid document`() {
        assertEquals(NativeStats(), NativeStats.fromJson("{}"))
        // A JSON document that is valid but of the wrong shape is also survivable.
        assertEquals(NativeStats(), NativeStats.fromJson("[]"))
        assertEquals(NativeStats(), NativeStats.fromJson("null"))
    }

    @Test
    fun `tunnel fields are rendered with the keys the core parses`() {
        val json = JSONObject(
            NativeConfig(
                mode = TunnelMode.DNS_ONLY,
                mtu = 1400,
                blockQuic = false,
                blockEncryptedDnsBypass = false,
                encryptedDnsHostsFile = "/data/encrypted-dns-hosts.txt",
                tcpIdleTimeoutSecs = 600,
                udpIdleTimeoutSecs = 30,
                maxUdpFlows = 64,
                sniffBytes = 2048,
                sniffTimeoutMs = 1500,
                httpHeadBytes = 4096,
            ).toJson(),
        )
        assertEquals("dns_only", json.getString("mode"))
        assertEquals(1400, json.getInt("mtu"))
        assertFalse(json.getBoolean("blockQuic"))
        assertFalse(json.getBoolean("blockEncryptedDnsBypass"))
        assertEquals("/data/encrypted-dns-hosts.txt", json.getString("encryptedDnsHostsFile"))
        assertEquals(600L, json.getLong("tcpIdleTimeoutSecs"))
        assertEquals(30L, json.getLong("udpIdleTimeoutSecs"))
        assertEquals(64, json.getInt("maxUdpFlows"))
        assertEquals(2048, json.getInt("sniffBytes"))
        assertEquals(1500L, json.getLong("sniffTimeoutMs"))
        assertEquals(4096, json.getInt("httpHeadBytes"))
    }

    @Test
    fun `tunnel defaults are the full tunnel with the bypasses blocked`() {
        val config = NativeConfig()
        assertEquals(TunnelMode.FULL, config.mode)
        assertEquals(NativeConfig.DEFAULT_MTU, config.mtu)
        assertTrue(config.blockQuic)
        assertTrue(config.blockEncryptedDnsBypass)
        assertEquals(7200L, config.tcpIdleTimeoutSecs)
        assertEquals(60L, config.udpIdleTimeoutSecs)
        assertEquals(1024, config.maxUdpFlows)
        assertEquals(4096, config.sniffBytes)
        assertEquals(3000L, config.sniffTimeoutMs)
        assertEquals(NativeConfig.DEFAULT_HTTP_HEAD_BYTES, config.httpHeadBytes)
        // IPv6 is on by default: the core keeps the M2a behaviour unless the control plane, which
        // knows the underlying network, turns it off (MYS-2710).
        assertTrue(config.ipv6)
    }

    @Test
    fun `ipv6 flag is rendered and parsed under the key the core reads`() {
        val off = JSONObject(NativeConfig(ipv6 = false).toJson())
        assertTrue(off.has("ipv6"))
        assertFalse(off.getBoolean("ipv6"))

        val on = JSONObject(NativeConfig(ipv6 = true).toJson())
        assertTrue(on.getBoolean("ipv6"))

        // Round trip, and the default when the key is absent (an older core's config).
        assertEquals(false, NativeConfig.fromJson(NativeConfig(ipv6 = false).toJson()).ipv6)
        assertTrue(NativeConfig.fromJson("""{"ipv6":true}""").ipv6)
        assertTrue(NativeConfig.fromJson("{}").ipv6)
    }

    @Test
    fun `the full tunnel config round trips`() {
        val original = NativeConfig(
            mode = TunnelMode.DNS_ONLY,
            mtu = 1280,
            blockQuic = false,
            encryptedDnsHostsFile = "/data/hosts.txt",
            maxUdpFlows = 12,
            sniffBytes = 1024,
            httpHeadBytes = 2048,
        )
        assertEquals(original, NativeConfig.fromJson(original.toJson()))
    }

    @Test
    fun `http counters are parsed from stats json`() {
        // These keys are what `statsJson` emits for M2b (`docs/JNI.md` §3). A rename on one side
        // would silently show zeros in the UI, which is exactly what this pins.
        val json = """
            {"httpRequests":120,"httpBlocked":37,"httpRedirected":12,"httpDegraded":2,
             "httpEngineLoaded":true,"requestLogSize":120}
        """.trimIndent()
        val stats = NativeStats.fromJson(json)
        assertEquals(120L, stats.httpRequests)
        assertEquals(37L, stats.httpBlocked)
        assertEquals(12L, stats.httpRedirected)
        assertEquals(2L, stats.httpDegraded)
        assertTrue(stats.httpEngineLoaded)
        assertEquals(120L, stats.requestLogSize)
    }

    @Test
    fun `an absent http engine is reported as not loaded`() {
        // The default has to be false: a missing artifact means hostname-only filtering, and the UI
        // must be able to say so instead of implying HTTP is filtered.
        assertFalse(NativeStats().httpEngineLoaded)
        assertFalse(NativeStats.fromJson("""{"httpRequests":1}""").httpEngineLoaded)
    }

    @Test
    fun `tunnel counters are parsed from stats json`() {
        val json = """
            {"mode":"full","mtu":1500,"echStripped":2,"tcpActive":3,"tcpTotal":9,
             "udpActive":1,"bytesUp":1000,"bytesDown":2000,"blockedConnections":4,
             "quicDropped":5,"dnsHijacked":6,"encryptedDnsDropped":7}
        """.trimIndent()
        val stats = NativeStats.fromJson(json)
        assertEquals("full", stats.mode)
        assertEquals(1500, stats.mtu)
        assertEquals(2L, stats.echStripped)
        assertEquals(3L, stats.tcpActive)
        assertEquals(9L, stats.tcpTotal)
        assertEquals(1L, stats.udpActive)
        assertEquals(1000L, stats.bytesUp)
        assertEquals(2000L, stats.bytesDown)
        assertEquals(4L, stats.blockedConnections)
        assertEquals(5L, stats.quicDropped)
        assertEquals(6L, stats.dnsHijacked)
        assertEquals(7L, stats.encryptedDnsDropped)
    }
    // ---- M3a: HTTPS fields ----

    @Test
    fun `https fields default to off and round-trip when set`() {
        val default = NativeConfig()
        assertFalse(default.httpsFiltering)
        assertEquals(emptyList<Int>(), default.httpsUids)
        assertEquals(emptyList<String>(), default.httpsExcludedHosts)
        assertEquals("", default.httpsExcludedHostsFile)

        val config = NativeConfig(
            httpsFiltering = true,
            httpsUids = listOf(10123, 10456),
            httpsExcludedHosts = listOf("bank.example"),
            httpsExcludedHostsFile = "/data/user/0/top.zztweb.zshield/files/https-excluded-hosts.txt",
        )
        val parsed = NativeConfig.fromJson(config.toJson())
        assertTrue(parsed.httpsFiltering)
        assertEquals(listOf(10123, 10456), parsed.httpsUids)
        assertEquals(listOf("bank.example"), parsed.httpsExcludedHosts)
        assertEquals(config.httpsExcludedHostsFile, parsed.httpsExcludedHostsFile)
    }

    @Test
    fun `the config json uses the field names the core reads`() {
        // The wire format is the contract with `core/src/config.rs`; a rename on either side has to
        // fail here rather than silently disabling HTTPS filtering on a device.
        val json = org.json.JSONObject(
            NativeConfig(
                httpsFiltering = true,
                httpsUids = listOf(7),
                httpsExcludedHosts = listOf("a.example"),
                httpsExcludedHostsFile = "/x",
            ).toJson(),
        )
        assertTrue(json.getBoolean("httpsFiltering"))
        assertEquals(7, json.getJSONArray("httpsUids").getInt(0))
        assertEquals("a.example", json.getJSONArray("httpsExcludedHosts").getString(0))
        assertEquals("/x", json.getString("httpsExcludedHostsFile"))
    }

    @Test
    fun `a stats document without the https counters still parses`() {
        // An older core (or a disabled pipeline) omits them; the UI must not see a failure.
        val stats = NativeStats.fromJson("""{"dnsQueries":5}""")
        assertEquals(5, stats.dnsQueries)
        assertFalse(stats.httpsFiltering)
        assertEquals(0, stats.httpsIntercepted)
        assertEquals(0, stats.h2Streams)
        assertEquals(0, stats.httpsBypassEntries)
    }

    @Test
    fun `the https counters are read from the core's json`() {
        val stats = NativeStats.fromJson(
            """
            {"httpsFiltering":true,"httpsIntercepted":12,"httpsPassthrough":30,
             "httpsAutoBypassed":2,"httpsUpstreamInvalid":1,"httpsHandshakeFailures":3,
             "h2Streams":40,"h2Blocked":7,"httpsBypassEntries":2,"httpsRemoveHeaderRules":4}
            """.trimIndent(),
        )
        assertTrue(stats.httpsFiltering)
        assertEquals(12, stats.httpsIntercepted)
        assertEquals(30, stats.httpsPassthrough)
        assertEquals(2, stats.httpsAutoBypassed)
        assertEquals(1, stats.httpsUpstreamInvalid)
        assertEquals(3, stats.httpsHandshakeFailures)
        assertEquals(40, stats.h2Streams)
        assertEquals(7, stats.h2Blocked)
        assertEquals(2, stats.httpsBypassEntries)
        assertEquals(4, stats.httpsRemoveHeaderRules)
    }
}
