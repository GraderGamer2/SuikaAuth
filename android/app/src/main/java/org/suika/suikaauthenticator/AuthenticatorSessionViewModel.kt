package org.suika.suikaauthenticator

import androidx.lifecycle.ViewModel
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

/**
 * Owns the process-local native session and serialized JNI worker across
 * Activity recreation. It never stores a password, OTP secret, or key itself.
 */
internal class AuthenticatorSessionViewModel : ViewModel() {
    val worker: ExecutorService = Executors.newSingleThreadExecutor()

    var nativeSessionHandle: Long? = null

    override fun onCleared() {
        val handle = nativeSessionHandle
        nativeSessionHandle = null
        if (handle != null) {
            runCatching {
                worker.execute {
                    runCatching { NativeBridge.nativeLockVault(handle) }
                }
            }
        }
        worker.shutdown()
    }
}
