package top.zztweb.zshield.filters

import org.json.JSONObject
import java.io.File
import java.security.MessageDigest

/** Reuse a successful automatic compile only when its inputs, build and all outputs still match. */
internal class CompilationCache(private val store: FilterStore, private val build: String) {
    private val marker get() = File(store.compiledDir, "compile-cache.json")
    private val artifacts = listOf("dns.bin", "engine.bin", "extras.txt")

    // A manual compile and the debounced startup may overlap. Keep the output files and the
    // success marker from different native compiles from being paired with each other.
    @Synchronized
    fun run(request: String, reuse: Boolean, compile: (String) -> String?): String? {
        val started = System.nanoTime()
        val input = inputIdentity(request)
        if (reuse && input != null) {
            val saved = runCatching { JSONObject(marker.readText()) }.getOrNull()
            val outputs = outputIdentity()
            if (saved?.optString("input") == input && outputs != null &&
                saved.optString("outputs") == outputs
            ) {
                val stats = saved.optJSONObject("stats")
                if (stats != null && stats.has("lists") && !stats.has("error")) {
                    stats.put("elapsedMs", (System.nanoTime() - started) / 1_000_000)
                    android.util.Log.i("ZShield", "compile cache hit: inputs and all artifacts verified")
                    return stats.toString()
                }
            }
            android.util.Log.i("ZShield", "compile cache miss: marker=${saved != null}, " +
                "inputs=${saved?.optString("input") == input}, outputs=${outputs != null && saved?.optString("outputs") == outputs}")
        }

        // A failed or interrupted rebuild must never leave an older success marker usable.
        if (marker.exists() && !marker.delete()) error("cannot invalidate compilation cache")
        val result = compile(request)
        val stats = runCatching { JSONObject(result.orEmpty()) }.getOrNull()
        if (input != null && stats != null && stats.has("lists") && !stats.has("error") &&
            input == inputIdentity(request)
        ) {
            val outputs = outputIdentity()
            if (outputs != null) {
                val saved = JSONObject().put("input", input).put("outputs", outputs).put("stats", stats)
                // A cache write is optional. The native compile already succeeded, so a storage
                // error here should only cost a recompile at the next start, not disable filtering.
                runCatching { store.writeAtomically(marker, saved.toString().toByteArray(Charsets.UTF_8)) }
                    .onFailure { android.util.Log.w("ZShield", "compile cache write failed: ${it.javaClass.simpleName}") }
            }
        }
        return result
    }

    private fun inputIdentity(request: String): String? = runCatching {
        val sources = JSONObject(request).getJSONArray("lists")
        val identity = MessageDigest.getInstance("SHA-256")
        identity.update(build.toByteArray(Charsets.UTF_8))
        identity.update(0.toByte())
        // Includes list order/IDs, user rules, allowlist, debugRules and output directory.
        identity.update(request.toByteArray(Charsets.UTF_8))
        for (i in 0 until sources.length()) {
            identity.update(fileHash(File(sources.getJSONObject(i).getString("path"))))
        }
        identity.digest().hex()
    }.onFailure { android.util.Log.i("ZShield", "compile cache input unavailable: ${it.javaClass.simpleName}") }.getOrNull()

    private fun outputIdentity(): String? = runCatching {
        artifacts.joinToString(":") { fileHash(File(store.compiledDir, it)).hex() }
    }.onFailure { android.util.Log.i("ZShield", "compile cache output unavailable: ${it.javaClass.simpleName}") }.getOrNull()

    private fun fileHash(file: File): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().buffered().use { stream ->
            val buffer = ByteArray(16 * 1024)
            while (true) {
                val n = stream.read(buffer)
                if (n < 0) break
                digest.update(buffer, 0, n)
            }
        }
        return digest.digest()
    }

    private fun ByteArray.hex() = joinToString("") { "%02x".format(it.toInt() and 0xff) }
}
