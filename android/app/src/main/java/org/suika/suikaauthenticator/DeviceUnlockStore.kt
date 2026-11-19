package org.suika.suikaauthenticator

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.File
import java.io.FileOutputStream
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Stores only an encrypted Rust vault wrapping key. The AES key itself is
 * non-exportable and belongs to Android Keystore. Authentication is required
 * for every AES-GCM operation; biometric enrollment invalidates the key.
 */
internal object DeviceUnlockStore {
    internal data class WrappedMaterial(
        val iv: ByteArray,
        val ciphertext: ByteArray
    )

    private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
    private const val KEY_ALIAS = "org.suika.SuikaAuthenticator.device-unlock.v1"
    private const val DIRECTORY_NAME = "SuikaAuthenticator"
    private const val FILE_NAME = "device-unlock.bin"
    private const val TEMP_NAME = "device-unlock.tmp"
    private const val FORMAT_VERSION = 1
    private const val IV_BYTES = 12
    private const val WRAPPING_KEY_BYTES = 32
    private const val TAG_BYTES = 16
    private const val BLOB_BYTES = 1 + IV_BYTES + WRAPPING_KEY_BYTES + TAG_BYTES

    private val aad = "SuikaAuthenticator/device-unlock/v1".toByteArray(Charsets.US_ASCII)
    private val lock = Any()

    fun hasWrappedKey(context: Context): Boolean = synchronized(lock) {
        val file = dataFile(context)
        if (!file.isFile || file.length() != BLOB_BYTES.toLong()) return@synchronized false
        runCatching { keyStore().containsAlias(KEY_ALIAS) }.getOrDefault(false)
    }

    fun prepareEncryptionCipher(context: Context): Cipher = synchronized(lock) {
        clear(context)

        val generator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            KEYSTORE_PROVIDER
        )
        val builder = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setKeySize(256)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            builder.setUserAuthenticationParameters(
                0,
                KeyProperties.AUTH_BIOMETRIC_STRONG
            )
        } else {
            @Suppress("DEPRECATION")
            builder.setUserAuthenticationValidityDurationSeconds(-1)
        }

        generator.init(builder.build())
        val key = generator.generateKey()
        Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(Cipher.ENCRYPT_MODE, key)
            updateAAD(aad)
        }
    }

    fun prepareDecryptionCipher(iv: ByteArray): Cipher = synchronized(lock) {
        require(iv.size == IV_BYTES) {
            "Biometric unlock data has an invalid nonce."
        }
        val key = keyStore().getKey(KEY_ALIAS, null) as? SecretKey
            ?: throw IllegalStateException("The device-bound biometric key is missing.")
        Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BYTES * 8, iv))
            updateAAD(aad)
        }
    }

    fun store(context: Context, iv: ByteArray, ciphertext: ByteArray) = synchronized(lock) {
        require(iv.size == IV_BYTES && ciphertext.size == WRAPPING_KEY_BYTES + TAG_BYTES) {
            "The device-bound unlock data has an invalid length."
        }
        val directory = dataDirectory(context)
        check(directory.isDirectory || directory.mkdirs()) {
            "The private application data directory could not be created."
        }

        val blob = ByteArray(BLOB_BYTES)
        blob[0] = FORMAT_VERSION.toByte()
        iv.copyInto(blob, 1)
        ciphertext.copyInto(blob, 1 + IV_BYTES)
        val temporary = File(directory, TEMP_NAME)
        val destination = File(directory, FILE_NAME)
        try {
            if (temporary.exists() && !temporary.delete()) {
                throw IllegalStateException("A temporary biometric file could not be removed.")
            }
            FileOutputStream(temporary).use { output ->
                output.write(blob)
                output.fd.sync()
            }
            Files.move(
                temporary.toPath(),
                destination.toPath(),
                StandardCopyOption.ATOMIC_MOVE,
                StandardCopyOption.REPLACE_EXISTING
            )
        } finally {
            blob.fill(0)
            if (temporary.exists()) temporary.delete()
        }
    }

    fun load(context: Context): WrappedMaterial? = synchronized(lock) {
        val file = dataFile(context)
        if (!file.isFile) return@synchronized null
        if (file.length() != BLOB_BYTES.toLong()) {
            throw IllegalStateException("Biometric unlock data is malformed.")
        }

        val blob = file.readBytes()
        try {
            if (blob.size != BLOB_BYTES || blob[0].toInt() != FORMAT_VERSION) {
                throw IllegalStateException("Biometric unlock data uses an unsupported format.")
            }
            WrappedMaterial(
                iv = blob.copyOfRange(1, 1 + IV_BYTES),
                ciphertext = blob.copyOfRange(1 + IV_BYTES, blob.size)
            )
        } finally {
            blob.fill(0)
        }
    }

    fun clear(context: Context) = synchronized(lock) {
        val directory = dataDirectory(context)
        val file = File(directory, FILE_NAME)
        val temporary = File(directory, TEMP_NAME)
        if (file.exists() && !file.delete()) {
            throw IllegalStateException("Biometric unlock data could not be removed.")
        }
        if (temporary.exists() && !temporary.delete()) {
            throw IllegalStateException("Temporary biometric data could not be removed.")
        }
        val store = keyStore()
        if (store.containsAlias(KEY_ALIAS)) store.deleteEntry(KEY_ALIAS)
    }

    private fun dataDirectory(context: Context) =
        File(context.noBackupFilesDir, DIRECTORY_NAME)

    private fun dataFile(context: Context) =
        File(dataDirectory(context), FILE_NAME)

    private fun keyStore(): KeyStore =
        KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
}
