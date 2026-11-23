package top.zztweb.zshield.https

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import android.widget.Toast
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import org.json.JSONObject
import top.zztweb.zshield.core.Native
import java.io.File
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * The device's root CA: generation, encrypted storage, export and install guidance.
 *
 * Interface fixed by the M3a task card §1 — the UI depends on exactly these members, so they are the
 * contract rather than an implementation detail.
 *
 * # Where the private key lives
 *
 * The key is generated **in Rust** (so the certificate and the key are one operation) and comes back
 * as PKCS#8 DER once. It is then encrypted with an AES-GCM key that never leaves the Android
 * Keystore, and the ciphertext is written to the app's private directory as `ca.key.enc`. The
 * certificate is public and is stored as `ca.crt`. Nothing in this class ever logs key material, and
 * the plaintext key exists only for the duration of one `generate()` call.
 *
 * # Why the state is a flow
 *
 * [state] is what the UI shows: whether a CA exists, its fingerprint, its expiry, and whether the
 * user has actually installed it. `installed` cannot be observed with a callback — Android has no
 * API for it — so [refreshInstalled] is called when the screen resumes and after an install attempt.
 */
object CertManager {

    private const val TAG = "ZShield"
    private const val CA_DIR = "https"
    private const val CERT_FILE = "ca.crt"
    private const val KEY_FILE = "ca.key.enc"
    private const val KEYSTORE = "AndroidKeyStore"
    private const val WRAPPING_KEY_ALIAS = "zshield-ca-wrapping-key"
    private const val GCM_TAG_BITS = 128
    private const val GCM_IV_BYTES = 12

    /** Settings' "scroll to and highlight this preference" extra, and the credentials entry's key. */
    private const val HIGHLIGHT_EXTRA = ":settings:fragment_args_key"
    private const val HIGHLIGHT_KEY = "encryption_and_credential"

    /** What the UI needs to know about the CA. */
    sealed interface CaState {
        /** No CA exists yet: HTTPS filtering cannot be enabled. */
        data object NotGenerated : CaState

        /**
         * A CA exists.
         *
         * @param fingerprintSha256 lowercase hex SHA-256 of the DER certificate, which is also part
         *   of the export file name and what the user can compare against the installed entry.
         * @param notAfterMs the certificate's `notAfter`, in milliseconds since the Unix epoch.
         * @param installed whether the user certificate store currently holds this certificate.
         */
        data class Ready(
            val fingerprintSha256: String,
            val notAfterMs: Long,
            val installed: Boolean,
        ) : CaState
    }

    private lateinit var appContext: Context
    private val mutableState = MutableStateFlow<CaState>(CaState.NotGenerated)

    /** Current CA state; collectors see every change. */
    val state: StateFlow<CaState> = mutableState.asStateFlow()

    /** Current CA state without collecting. */
    val current: CaState get() = mutableState.value

    /**
     * Loads the stored CA, if any. Idempotent, and safe to call before any other member.
     *
     * A stored certificate whose state cannot be parsed is treated as "not generated": the user can
     * regenerate, and the alternative — refusing to work forever because of one bad file — is worse.
     */
    @Synchronized
    fun initialize(context: Context) {
        if (::appContext.isInitialized) return
        appContext = context.applicationContext
        val stored = readStoredCertificate()
        mutableState.value = if (stored == null) {
            CaState.NotGenerated
        } else {
            CaState.Ready(
                fingerprintSha256 = fingerprintOf(stored),
                notAfterMs = stored.notAfter.time,
                installed = isInstalledInUserStore(fingerprintOf(stored)),
            )
        }
    }

    /**
     * Generates a new CA, or replaces the existing one.
     *
     * Replacing invalidates the old certificate: any app that trusted it keeps trusting it until the
     * user removes it from the system settings, which is why `installed` becomes `false` and the user
     * is offered the export again. The Rust core is told about the new root through [apply], which
     * every `start` calls; the old root's cached leaf certificates are dropped there.
     */
    suspend fun generate(): Result<Unit> = withContext(Dispatchers.IO) {
        runCatching<Unit> {
            // `Native.generateCa` is `String?`: `null` means the JVM could not hand back the
            // document at all, which is a generation failure with the reason in `lastError`
            // (MYS-2716 §2). `error(...)` surfaces it as the [Result] failure the caller expects.
            val raw = Native.generateCa()
                ?: error(Native.lastError()?.ifBlank { null } ?: "核心未返回证书")
            val json = JSONObject(raw)
            json.optString("error").takeIf { it.isNotBlank() }?.let { error(it) }
            val certPem = json.getString("certPem")
            val keyPkcs8 = android.util.Base64.decode(
                json.getString("keyPkcs8B64"),
                android.util.Base64.NO_WRAP,
            )
            require(keyPkcs8.isNotEmpty()) { "the core returned an empty key" }
            require(certPem.contains("BEGIN CERTIFICATE")) { "the core returned no certificate" }

            val dir = caDir()
            dir.mkdirs()
            writeAtomically(File(dir, KEY_FILE), encrypt(keyPkcs8))
            writeAtomically(File(dir, CERT_FILE), certPem.toByteArray(Charsets.UTF_8))
            // The plaintext key exists only for the length of this call.
            keyPkcs8.fill(0)

            val certificate = parseCertificate(certPem.toByteArray(Charsets.UTF_8))
                ?: error("the generated certificate cannot be parsed")
            mutableState.value = CaState.Ready(
                fingerprintSha256 = fingerprintOf(certificate),
                notAfterMs = certificate.notAfter.time,
                // A fresh certificate is never installed: it has a different fingerprint from
                // whatever the user installed before, so the system store cannot contain it.
                installed = false,
            )
            Log.i(TAG, "root CA generated: ${mutableState.value}")
        }.onFailure { error ->
            Log.w(TAG, "cannot generate the root CA", error)
        }
    }

    /**
     * Exports the certificate to the device's Downloads folder as
     * `ZShield-CA-<first 8 of the fingerprint>.crt` (PEM).
     *
     * `MediaStore` on API 29+, so the file lands where the system's certificate installer can find
     * it. On API 28 the app's external files directory is used, because `MediaStore.Downloads` does
     * not exist there.
     */
    suspend fun exportToDownloads(): Result<Uri> = withContext(Dispatchers.IO) {
        runCatching {
            val pem = readStoredCertificatePem() ?: error("no certificate to export")
            val certificate = parseCertificate(pem.toByteArray(Charsets.UTF_8))
                ?: error("the stored certificate cannot be parsed")
            val name = exportFileName(fingerprintOf(certificate))
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                val resolver = appContext.contentResolver
                val values = android.content.ContentValues().apply {
                    put(MediaStore.Downloads.DISPLAY_NAME, name)
                    put(MediaStore.Downloads.MIME_TYPE, "application/x-x509-ca-cert")
                    put(MediaStore.Downloads.IS_PENDING, 1)
                }
                val uri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
                    ?: error("cannot create the export file")
                resolver.openOutputStream(uri)?.use { it.write(pem.toByteArray(Charsets.UTF_8)) }
                    ?: error("cannot write the export file")
                values.clear()
                values.put(MediaStore.Downloads.IS_PENDING, 0)
                resolver.update(uri, values, null, null)
                Log.i(TAG, "root CA exported to $uri")
                uri
            } else {
                @Suppress("DEPRECATION")
                val dir = Environment.getExternalStoragePublicDirectory(
                    Environment.DIRECTORY_DOWNLOADS,
                )
                dir.mkdirs()
                val file = File(dir, name)
                writeAtomically(file, pem.toByteArray(Charsets.UTF_8))
                Log.i(TAG, "root CA exported to ${file.absolutePath}")
                Uri.fromFile(file)
            }
        }.onFailure { error ->
            Log.w(TAG, "cannot export the root CA", error)
        }
    }

    /**
     * Re-checks whether the stored certificate is in the user certificate store.
     *
     * Android offers no callback for "the user installed a certificate", so this is called when a
     * screen resumes and after the install settings return. A CA that is not installed is not used:
     * decrypting with an uninstalled CA produces nothing but handshake failures, so
     * `httpsFiltering` is only effective once this returns `true`.
     */
    fun refreshInstalled() {
        val stored = readStoredCertificate() ?: run {
            mutableState.value = CaState.NotGenerated
            return
        }
        val fingerprint = fingerprintOf(stored)
        val installed = isInstalledInUserStore(fingerprint)
        val ready = mutableState.value
        mutableState.value = CaState.Ready(
            fingerprintSha256 = fingerprint,
            notAfterMs = stored.notAfter.time,
            installed = installed,
        )
        if (ready is CaState.Ready && ready.installed != installed) {
            Log.i(TAG, "CA installation state changed: installed=$installed")
        }
    }

    /**
     * Opens the system settings page that holds "Encryption & credentials", where the user installs
     * the exported certificate.
     *
     * There is no intent that performs the install itself on Android 11+ (that is the platform
     * restriction `docs/DESIGN.md` decision 7 records), so the best this can do is land the user one
     * tap away from it. `TRUSTED_CREDENTIALS` is deliberately not used: it opens the read-only list of
     * trusted CAs, which has no install entry, and users got stuck there. The settings page that
     * contains "Encryption & credentials" moved between releases, so each candidate is tried in turn;
     * [HIGHLIGHT_KEY] makes Settings scroll to and highlight that entry (verified on Android 16).
     */
    fun openInstallSettings(context: Context) {
        val candidates = listOf(
            // Android 13+ (Pixel / AOSP): Security & privacy → More security & privacy.
            Intent("com.android.settings.MORE_SECURITY_PRIVACY_SETTINGS"),
            // Android 10–12 AOSP: Security → Advanced.
            Intent("com.android.settings.security.SECURITY_ADVANCED_SETTINGS"),
            Intent(android.provider.Settings.ACTION_SECURITY_SETTINGS),
            Intent(android.provider.Settings.ACTION_SETTINGS),
        ).onEach { it.putExtra(HIGHLIGHT_EXTRA, HIGHLIGHT_KEY) }
        for (intent in candidates) {
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            if (context.packageManager.resolveActivity(intent, 0) != null) {
                runCatching { context.startActivity(intent) }
                    .onSuccess {
                        Toast.makeText(
                            context,
                            context.getString(top.zztweb.zshield.R.string.https_install_hint),
                            Toast.LENGTH_LONG,
                        ).show()
                        return
                    }
                    .onFailure { error -> Log.w(TAG, "cannot open ${intent.action}", error) }
            }
        }
        Toast.makeText(
            context,
            context.getString(top.zztweb.zshield.R.string.https_install_hint),
            Toast.LENGTH_LONG,
        ).show()
    }

    /**
     * Hands the stored CA to the core, before every `Native.start`.
     *
     * Returns false when there is no CA or the key cannot be decrypted (a Keystore reset, a restored
     * backup). The caller then starts without HTTPS filtering rather than failing to start at all.
     */
    fun apply(): Boolean {
        val certPem = readStoredCertificatePem() ?: return false
        val key = runCatching { decrypt(readFile(File(caDir(), KEY_FILE))) }
            .onFailure { Log.w(TAG, "cannot read the stored CA key", it) }
            .getOrNull() ?: return false
        return try {
            Native.loadCa(certPem, key)
        } finally {
            key.fill(0)
        }
    }

    /**
     * Tells the running core to forget its auto-bypass table.
     *
     * A pair lands in that table when a client refuses our certificate — which is exactly what every
     * browser does while the CA is not installed. After an install, those entries would keep the
     * connection passed through for 24 h, so HTTPS filtering would look like it did nothing. Called
     * from the install-settings return path and after `generate`.
     */
    fun clearBypass(handle: Long) {
        if (handle == 0L) return
        runCatching { Native.clearHttpsBypass(handle) }
            .onFailure { Log.w(TAG, "cannot clear the auto-bypass table", it) }
    }

    /** Deletes the stored material. The user's installed copy stays in the system store. */
    @Synchronized
    fun clear() {
        if (!::appContext.isInitialized) return
        File(caDir(), CERT_FILE).delete()
        File(caDir(), KEY_FILE).delete()
        mutableState.value = CaState.NotGenerated
    }

    // -----------------------------------------------------------------------------------------
    // Storage
    // -----------------------------------------------------------------------------------------

    private fun caDir(): File = File(appContext.filesDir, CA_DIR)

    private fun readFile(file: File): ByteArray? =
        runCatching { if (file.isFile) file.readBytes() else null }.getOrNull()

    private fun readStoredCertificatePem(): String? =
        readFile(File(caDir(), CERT_FILE))?.toString(Charsets.UTF_8)

    private fun readStoredCertificate(): X509Certificate? =
        readStoredCertificatePem()?.let { parseCertificate(it.toByteArray(Charsets.UTF_8)) }

    /** Atomic write: `temp + fsync + rename`, the same contract the settings and list stores use. */
    private fun writeAtomically(target: File, bytes: ByteArray) {
        target.parentFile?.mkdirs()
        val temp = File(target.parentFile, "${target.name}.${System.nanoTime()}.part")
        try {
            java.io.FileOutputStream(temp).use { stream ->
                stream.write(bytes)
                stream.flush()
                stream.fd.sync()
            }
            check(temp.renameTo(target)) { "cannot rename ${temp.name} -> ${target.name}" }
        } finally {
            if (temp.exists()) temp.delete()
        }
    }

    // -----------------------------------------------------------------------------------------
    // Encryption (Android Keystore wrapping)
    // -----------------------------------------------------------------------------------------

    /**
     * The AES key that wraps the CA key.
     *
     * Created on first use in the Android Keystore, so its material never enters the app's memory or
     * its backup: a `ca.key.enc` lifted off the device is useless without the Keystore entry, which
     * is not exportable.
     */
    private fun wrappingKey(): SecretKey {
        val keyStore = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        (keyStore.getEntry(WRAPPING_KEY_ALIAS, null) as? KeyStore.SecretKeyEntry)?.let {
            return it.secretKey
        }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
        generator.init(
            KeyGenParameterSpec.Builder(
                WRAPPING_KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                // No user authentication: the key is used while the phone is locked, from a service
                // that must start without interaction.
                .setUserAuthenticationRequired(false)
                .build(),
        )
        return generator.generateKey()
    }

    /** `IV || ciphertext || tag`, exactly what [decrypt] expects. */
    private fun encrypt(plaintext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, wrappingKey())
        val ciphertext = cipher.doFinal(plaintext)
        return cipher.iv + ciphertext
    }

    private fun decrypt(wrapped: ByteArray?): ByteArray? {
        if (wrapped == null || wrapped.size <= GCM_IV_BYTES) return null
        val iv = wrapped.copyOfRange(0, GCM_IV_BYTES)
        val ciphertext = wrapped.copyOfRange(GCM_IV_BYTES, wrapped.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, wrappingKey(), GCMParameterSpec(GCM_TAG_BITS, iv))
        return cipher.doFinal(ciphertext)
    }

    // -----------------------------------------------------------------------------------------
    // Certificate helpers
    // -----------------------------------------------------------------------------------------

    /** Parses a PEM or DER certificate. */
    internal fun parseCertificate(bytes: ByteArray): X509Certificate? = runCatching {
        CertificateFactory.getInstance("X.509")
            .generateCertificate(bytes.inputStream()) as X509Certificate
    }.getOrNull()

    /** Lowercase hex SHA-256 of the DER encoding: what the system settings screen shows. */
    internal fun fingerprintOf(certificate: X509Certificate): String =
        java.security.MessageDigest.getInstance("SHA-256")
            .digest(certificate.encoded)
            .joinToString("") { "%02x".format(it) }

    /**
     * `ZShield-CA-<first 8 hex>.crt`.
     *
     * The prefix is what lets a user with two devices tell the two certificates apart in the system
     * settings list, which otherwise shows only the subject — and every install has the same subject
     * except for its random suffix.
     */
    internal fun exportFileName(fingerprintSha256: String): String =
        "ZShield-CA-${fingerprintSha256.take(8)}.crt"

    /**
     * Whether the user certificate store holds a certificate with this fingerprint.
     *
     * `AndroidCAStore` lists the user-installed CAs as `alias`-keyed entries. Reading it needs no
     * permission, and it is the only supported way to answer the question: there is no
     * "isCertificateInstalled" API.
     */
    internal fun isInstalledInUserStore(fingerprintSha256: String): Boolean = runCatching {
        val store = KeyStore.getInstance("AndroidCAStore").apply { load(null) }
        val aliases = store.aliases()
        while (aliases.hasMoreElements()) {
            val alias = aliases.nextElement()
            val certificate = store.getCertificate(alias) as? X509Certificate ?: continue
            if (fingerprintOf(certificate) == fingerprintSha256) return true
        }
        false
    }.getOrElse { error ->
        // A device whose CA store cannot be read must not make the app claim "not installed": the
        // user would export and install again forever. Reporting false is the safer direction (it
        // only means HTTPS filtering stays off), so it is reported and returned.
        Log.w(TAG, "cannot read the user CA store", error)
        false
    }

    /** The certificate's expiry, formatted for display. */
    fun expiryText(notAfterMs: Long): String =
        SimpleDateFormat("yyyy-MM-dd", Locale.getDefault()).format(Date(notAfterMs))

    /** Test seam: point the singleton at a context without going through the VPN service. */
    internal fun initializeForTest(context: Context) {
        appContext = context.applicationContext
        val stored = readStoredCertificate()
        mutableState.value = if (stored == null) {
            CaState.NotGenerated
        } else {
            CaState.Ready(
                fingerprintSha256 = fingerprintOf(stored),
                notAfterMs = stored.notAfter.time,
                installed = false,
            )
        }
    }
}
