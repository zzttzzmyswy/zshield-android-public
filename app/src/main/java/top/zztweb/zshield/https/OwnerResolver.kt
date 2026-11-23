package top.zztweb.zshield.https

import android.content.Context
import android.net.ConnectivityManager
import android.os.Build
import android.util.Log

/**
 * Answers "which application owns this TCP connection" for the HTTPS decision.
 *
 * The Rust core calls [ownerUid] through JNI (`docs/JNI.md` §7) on a connection it has already
 * decided is a 443 TLS candidate. Doing the lookup here rather than pre-computing a table is what
 * keeps the decision in one place: the core asks, this answers, and the core caches the result for
 * the connection's lifetime — the Binder call happens once per connection, not once per request.
 *
 * # Why it can answer "unknown"
 *
 * `ConnectivityManager.getConnectionOwnerUid` exists from API 29. On API 28 there is no supported way
 * to attribute a socket to a package, and returning a guess would decrypt an application the user
 * never selected — which breaks pinning and, worse, could break a banking app. `-1` therefore means
 * "unknown", and the core never decrypts an unknown owner (task card §2).
 */
object OwnerResolver {

    private const val TAG = "ZShield"
    private const val UNKNOWN = -1

    /**
     * `ConnectivityManager.getConnectionOwnerUid` for one live connection.
     *
     * @param protocol the IP protocol number (`6` for TCP), as the core passes it.
     * @param localIp the client's address **inside** the tunnel; unused, because Android attributes a
     *   socket by its *remote* endpoint and the local side here is our own virtual address.
     * @param remoteIp the address the client dialled.
     * @return the owning uid, or `-1` when it cannot be determined.
     */
    @JvmStatic
    fun ownerUid(
        protocol: Int,
        localIp: String,
        localPort: Int,
        remoteIp: String,
        remotePort: Int,
    ): Int {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return UNKNOWN
        val context = appContext ?: return UNKNOWN
        val manager = context.getSystemService(ConnectivityManager::class.java) ?: return UNKNOWN
        return try {
            val local = java.net.InetSocketAddress(localIp, localPort)
            val remote = java.net.InetSocketAddress(remoteIp, remotePort)
            manager.getConnectionOwnerUid(protocol, local, remote)
        } catch (error: Exception) {
            // A SecurityException (the caller lacks the permission on some builds) or an
            // IllegalArgumentException (an address family the platform refuses): both mean "cannot
            // attribute", which is answered the same way as API 28.
            Log.w(TAG, "cannot resolve the connection owner for $remoteIp:$remotePort", error)
            UNKNOWN
        }
    }

    /**
     * The application context, set once by [top.zztweb.zshield.ZShieldApp].
     *
     * A static rather than a JNI-passed object: the core calls this from a tokio worker thread, and
     * passing a `Context` through every call would mean holding a global reference for the process's
     * lifetime anyway.
     */
    @Volatile
    var appContext: Context? = null
        private set

    /** Called once from `Application.onCreate`. Idempotent. */
    fun initialize(context: Context) {
        appContext = context.applicationContext
    }
}
