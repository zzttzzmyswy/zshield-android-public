package top.zztweb.zshield.filters

import org.json.JSONArray
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.File

class CompilationCacheTest {
    private lateinit var dir: File
    private lateinit var store: FilterStore
    private lateinit var source: File
    private lateinit var request: JSONObject
    private var calls = 0
    private val compiler: (String) -> String? = {
        calls++
        listOf("dns.bin", "engine.bin", "extras.txt").forEach { name ->
            File(store.compiledDir, name).writeText("$name:$calls")
        }
        """{"lists":[],"dnsRules":42,"elapsedMs":999}"""
    }

    @Before fun setup() {
        dir = kotlin.io.path.createTempDirectory("zshield-compile-cache").toFile()
        store = FilterStore(dir)
        store.ensureDirectories()
        source = store.listFile("a").apply { writeText("||ads.example^") }
        request = JSONObject().put("lists", JSONArray().put(JSONObject().put("id", "a").put("path", source.path)))
            .put("userRules", "").put("allowlist", JSONArray()).put("debugRules", false)
            .put("outputDir", store.compiledDir.path)
    }

    @After fun cleanup() { dir.deleteRecursively() }
    private fun run(reuse: Boolean = true, build: String = "15:0.1.3"): String? =
        CompilationCache(store, build).run(request.toString(), reuse, compiler)

    @Test fun unchanged_startup_reuses_a_verified_result_after_process_restart() {
        run()
        val result = JSONObject(run()!!)
        assertEquals(1, calls)
        assertEquals(42, result.getInt("dnsRules"))
        assertTrue(result.getLong("elapsedMs") >= 0)
    }

    @Test fun manual_compile_always_runs_even_with_a_valid_cache() {
        run()
        run(reuse = false)
        assertEquals(2, calls)
    }

    @Test fun changed_contents_with_the_same_size_and_timestamp_recompile() {
        run()
        val stamp = source.lastModified()
        source.writeText("||new.example^")
        source.setLastModified(stamp)
        run()
        assertEquals(2, calls)
    }

    @Test fun changed_rules_allowlist_list_selection_and_build_recompile() {
        run()
        request.put("userRules", "||mine.example^"); run()
        request.put("allowlist", JSONArray().put("allowed.example")); run()
        request.put("lists", JSONArray()); run()
        run(build = "16:0.1.4")
        assertEquals(5, calls)
    }

    @Test fun every_artifact_is_checked_including_extras() {
        run()
        for (name in listOf("dns.bin", "engine.bin", "extras.txt")) {
            File(store.compiledDir, name).appendText("corrupt")
            run()
        }
        File(store.compiledDir, "extras.txt").delete()
        run()
        assertEquals(5, calls)
    }

    @Test fun failed_compile_invalidates_old_success_even_when_outputs_survive() {
        run()
        CompilationCache(store, "15:0.1.3").run(request.toString(), false) { """{"error":"failed"}""" }
        run()
        assertEquals(2, calls)
    }

    @Test fun an_input_changed_during_compile_is_not_cached() {
        CompilationCache(store, "15:0.1.3").run(request.toString(), false) { json ->
            compiler(json).also { source.writeText("||changed.example^") }
        }
        assertFalse(File(store.compiledDir, "compile-cache.json").exists())
        run()
        assertEquals(2, calls)
    }

    @Test fun corrupt_marker_or_missing_input_causes_compile_instead_of_false_hit() {
        run()
        File(store.compiledDir, "compile-cache.json").writeText("{broken")
        run()
        source.delete()
        run()
        assertEquals(3, calls)
        assertFalse(File(store.compiledDir, "compile-cache.json").exists())
    }
}
