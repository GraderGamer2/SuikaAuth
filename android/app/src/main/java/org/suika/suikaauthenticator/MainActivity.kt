package org.suika.suikaauthenticator

import android.Manifest
import android.app.AlertDialog
import android.content.pm.PackageManager
import android.net.Uri
import androidx.activity.result.contract.ActivityResultContracts
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.view.CameraController
import androidx.camera.view.LifecycleCameraController
import androidx.camera.view.PreviewView
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.google.mlkit.vision.barcode.BarcodeScanning
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.barcode.BarcodeScannerOptions
import com.google.mlkit.vision.common.InputImage
import androidx.lifecycle.ViewModelProvider
import android.content.ClipData
import android.content.ClipboardManager
import android.content.ClipDescription
import android.content.Context
import android.graphics.Typeface
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle
import android.os.SystemClock
import android.text.Editable
import android.text.TextWatcher
import android.view.Gravity
import android.view.MotionEvent
import android.view.View
import android.view.inputmethod.EditorInfo
import android.widget.AdapterView
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Spinner
import android.widget.TextView
import android.widget.Toast
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.charset.StandardCharsets
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.UUID
import java.util.concurrent.atomic.AtomicInteger
import javax.crypto.Cipher

class MainActivity : FragmentActivity() {
    private lateinit var appState: AuthenticatorSessionViewModel
    private lateinit var worker: ExecutorService
    private val handler = Handler(Looper.getMainLooper())
    private val inactivityTimeoutMs = 5 * 60 * 1000L
    private val backgroundLock = Runnable { lockSession(showAuthentication = true) }

    companion object {
        private const val MAX_AEGIS_EXPORT_BYTES = 16 * 1024 * 1024
        private const val MAX_OTPAUTH_URI_LIST_BYTES = 16 * 1024 * 1024
        private const val MAX_BACKUP_PASSWORD_BYTES = 1024
        private const val MAX_BACKUP_FILE_BYTES = 158 + 16 * 1024 * 1024 + 16
        private const val OTP_CLIPBOARD_TTL_MS = 30_000L
        private const val OTP_CLIPBOARD_OWNER_KEY = "org.suika.SuikaAuthenticator.clipboard.owner"
        private const val OTP_CLIPBOARD_OWNER = "suika-authenticator-otp-v1"
        private const val OTP_CLIPBOARD_TOKEN_KEY = "org.suika.SuikaAuthenticator.clipboard.token"
        private const val OTP_CLIPBOARD_EXPIRY_KEY = "org.suika.SuikaAuthenticator.clipboard.expires"
    }
    private var backgroundLockTimeoutMs = 0L
    private var activeHandle: Long? = null
    private var vaultExists: Boolean? = null
    private var activeBiometricPrompt: BiometricPrompt? = null
    private var biometricPromptVisible = false
    private var activityStarted = false
    private var biometricEnrollmentInProgress = false
    private var pendingDeviceUnlockKey: ByteArray? = null
    private var pendingQrUriField: EditText? = null
    private var activeQrScannerCleanup: (() -> Unit)? = null
    private var sensitiveEnrollmentFields: List<EditText> = emptyList()
    private var pendingAegisUri: Uri? = null
    private var pendingUriListUri: Uri? = null
    private var pendingBackupExportUri: Uri? = null
    private var pendingBackupRestoreUri: Uri? = null
    private var activeAegisPasswordDialog: AlertDialog? = null
    private var activeBackupPasswordDialog: AlertDialog? = null
    private var isRefreshing = false
    private val pendingHotp = mutableSetOf<String>()

    private lateinit var content: LinearLayout
    private lateinit var status: TextView
    private lateinit var accountList: LinearLayout
    private lateinit var searchInput: EditText

    private val inactivityLock = Runnable { lockSession(showAuthentication = true) }
    private val otpClipboardExpiry = Runnable { refreshOtpClipboardExpiry() }

    private val cameraPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted ->
        val uriField = pendingQrUriField
        pendingQrUriField = null
        if (granted && uriField != null && !isFinishing && !isDestroyed) {
            showQrScanner(uriField)
        } else if (!granted && ::status.isInitialized && !isFinishing) {
            status.text = "Camera access is required to scan a QR code. You can still paste a provisioning URI."
        }
    }

    private val aegisDocumentPicker = registerForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri ->
        pendingAegisUri = uri
        if (uri == null) return@registerForActivityResult
        if (activeHandle != null) {
            promptAegisPassword()
        } else if (::status.isInitialized) {
            status.text = "Aegis export selected. Unlock your vault to continue the import."
        }
    }

    private val uriListDocumentPicker = registerForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri ->
        pendingUriListUri = uri
        if (uri == null) return@registerForActivityResult
        if (activeHandle != null) {
            importOtpauthUriList(uri)
        } else if (::status.isInitialized) {
            status.text = "Plaintext URI export selected. Unlock your vault to continue the import."
        }
    }

    private val backupExportDocumentPicker = registerForActivityResult(
        ActivityResultContracts.CreateDocument("application/octet-stream")
    ) { uri ->
        pendingBackupExportUri = uri
        if (uri == null) return@registerForActivityResult
        if (activeHandle != null) {
            promptBackupExportPassword()
        } else if (::status.isInitialized) {
            status.text = "Backup destination selected. Unlock your vault to continue."
        }
    }

    private val backupRestoreDocumentPicker = registerForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri ->
        pendingBackupRestoreUri = uri
        if (uri == null) return@registerForActivityResult
        if (activeHandle != null) {
            promptBackupRestorePassword()
        } else if (::status.isInitialized) {
            status.text = "Backup selected. Unlock your vault to continue."
        }
    }

    private val backgroundLockTimeoutChoices = longArrayOf(
        0L,
        60_000L,
        3 * 60_000L,
        5 * 60_000L,
        10 * 60_000L
    )
    private val totpPeriodChoices = longArrayOf(15L, 30L, 45L, 60L, 90L, 120L, 300L)

    private val accountRefresh = object : Runnable {
        override fun run() {
            val handle = activeHandle ?: return
            if (isRefreshing) {
                handler.postDelayed(this, 250L)
                return
            }
            isRefreshing = true
            worker.execute {
                val result = runCatching { NativeBridge.nativeListAccounts(handle) }
                runOnUiThread {
                    isRefreshing = false
                    if (activeHandle == handle) {
                        result.onSuccess { renderAccounts(it) }.onFailure { showError(it) }
                        handler.postDelayed(this, 1000L)
                    }
                }
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        appState = ViewModelProvider(this).get(AuthenticatorSessionViewModel::class.java)
        worker = appState.worker
        activeHandle = appState.nativeSessionHandle
        backgroundLockTimeoutMs = loadBackgroundLockTimeout()
        buildShell()
        if (activeHandle != null) {
            vaultExists = true
            showVault()
        } else {
            status.text = "Checking encrypted vault…"
            worker.execute {
                val result = runCatching { NativeBridge.nativeHasVault(noBackupFilesDir.absolutePath) }
                runOnUiThread {
                    if (!isFinishing && !isDestroyed) {
                        result.onSuccess {
                            vaultExists = it
                            renderAuthentication(it)
                        }.onFailure { showError(it) }
                    }
                }
            }
        }
    }

    override fun onStart() {
        super.onStart()
        activityStarted = true
        handler.removeCallbacks(backgroundLock)
        handler.post(otpClipboardExpiry)
        if (activeHandle == null && vaultExists == true && content.childCount > 0) {
            renderAuthentication(existingVault = true)
        } else if (activeHandle != null) {
            handler.removeCallbacks(accountRefresh)
            handler.post(accountRefresh)
            resetInactivityTimer()
        }
    }

    override fun onWindowFocusChanged(hasFocus: Boolean) {
        super.onWindowFocusChanged(hasFocus)
        if (hasFocus && ::appState.isInitialized) {
            handler.post(otpClipboardExpiry)
        }
    }

    override fun onStop() {
        activityStarted = false
        activeAegisPasswordDialog?.dismiss()
        activeBackupPasswordDialog?.dismiss()
        activeQrScannerCleanup?.invoke()
        handler.removeCallbacks(accountRefresh)
        handler.removeCallbacks(inactivityLock)
        if (!isChangingConfigurations && !biometricPromptVisible && activeHandle != null) {
            if (backgroundLockTimeoutMs == 0L) {
                lockSession(showAuthentication = true)
            } else {
                handler.removeCallbacks(backgroundLock)
                handler.postDelayed(backgroundLock, backgroundLockTimeoutMs)
            }
        }
        super.onStop()
    }

    override fun onDestroy() {
        activeAegisPasswordDialog?.dismiss()
        activeBackupPasswordDialog?.dismiss()
        activeQrScannerCleanup?.invoke()
        clearSensitiveEnrollmentFields()
        handler.removeCallbacksAndMessages(null)
        if (isChangingConfigurations) {
            if (biometricPromptVisible) cancelBiometricPrompt()
        } else {
            cancelBiometricPrompt()
            if (activeHandle != null) lockSession(showAuthentication = false)
        }
        super.onDestroy()
    }

    override fun dispatchTouchEvent(event: MotionEvent): Boolean {
        if (activeHandle != null && event.actionMasked == MotionEvent.ACTION_DOWN) resetInactivityTimer()
        return super.dispatchTouchEvent(event)
    }

    override fun dispatchKeyEvent(event: android.view.KeyEvent): Boolean {
        if (activeHandle != null && event.action == android.view.KeyEvent.ACTION_DOWN) resetInactivityTimer()
        return super.dispatchKeyEvent(event)
    }

    private fun buildShell() {
        val scroll = ScrollView(this)
        content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(24), dp(28), dp(24), dp(28))
        }
        scroll.addView(content)
        setContentView(scroll)
    }

    private fun renderAuthentication(existingVault: Boolean) {
        clearSensitiveEnrollmentFields()
        handler.removeCallbacks(accountRefresh)
        activeHandle = null
        content.removeAllViews()
        addHeading("SuikaAuthenticator")
        addText(if (existingVault) "Unlock your encrypted vault" else "Create your encrypted vault", 16f)
        if (existingVault && DeviceUnlockStore.hasWrappedKey(this)) {
            addButton("Unlock with biometrics").setOnClickListener { beginBiometricUnlock() }
        }
        val password = addPasswordField("Master password")
        val confirmation = if (existingVault) null else addPasswordField("Confirm master password")
        password.imeOptions = EditorInfo.IME_ACTION_DONE
        password.setOnEditorActionListener { _, actionId, _ ->
            if (actionId == EditorInfo.IME_ACTION_DONE) {
                performAuthentication(existingVault, password, confirmation)
                true
            } else false
        }
        val action = addButton(if (existingVault) "Unlock" else "Create encrypted vault")
        action.setOnClickListener { performAuthentication(existingVault, password, confirmation) }
        status = addText("", 14f)
        status.setTextIsSelectable(false)
    }

    private fun performAuthentication(
        existingVault: Boolean,
        passwordField: EditText,
        confirmationField: EditText?
    ) {
        val passwordBytes = passwordField.text.toString().toByteArray(StandardCharsets.UTF_8)
        val confirmationBytes = confirmationField?.text?.toString()?.toByteArray(StandardCharsets.UTF_8)
        passwordField.text?.clear()
        confirmationField?.text?.clear()

        if (passwordBytes.isEmpty()) {
            passwordBytes.fill(0)
            confirmationBytes?.fill(0)
            status.text = "Enter your master password."
            return
        }
        if (confirmationBytes != null && !passwordBytes.contentEquals(confirmationBytes)) {
            passwordBytes.fill(0)
            confirmationBytes.fill(0)
            status.text = "The passwords do not match."
            return
        }
        confirmationBytes?.fill(0)
        setAuthenticationEnabled(false)
        status.text = if (existingVault) "Deriving key and unlocking…" else "Deriving key and creating vault…"

        worker.execute {
            val result = runCatching {
                if (existingVault) NativeBridge.nativeUnlockVault(noBackupFilesDir.absolutePath, passwordBytes)
                else NativeBridge.nativeCreateVault(noBackupFilesDir.absolutePath, passwordBytes)
            }
            passwordBytes.fill(0)
            runOnUiThread {
                result.onSuccess { handle ->
                    activeHandle = handle
                    appState.nativeSessionHandle = handle
                    vaultExists = true
                    showVault()
                }.onFailure {
                    setAuthenticationEnabled(true)
                    showError(it)
                }
            }
        }
    }

    private fun setAuthenticationEnabled(enabled: Boolean) {
        for (index in 0 until content.childCount) content.getChildAt(index).isEnabled = enabled
    }

    private fun showVault() {
        clearSensitiveEnrollmentFields()
        handler.removeCallbacks(accountRefresh)
        content.removeAllViews()
        addHeading("Your accounts")
        addText("Vault unlocked · encrypted storage is active", 13f)
        addButton("Lock vault").setOnClickListener { lockSession(showAuthentication = true) }
        addButton("Import Aegis export").setOnClickListener {
            if (pendingAegisUri != null) {
                promptAegisPassword()
            } else {
                aegisDocumentPicker.launch(
                    arrayOf(
                        "application/json",
                        "text/json",
                        "text/plain",
                        "application/octet-stream",
                        "*/*"
                    )
                )
            }
        }
        addButton("Import plaintext URI list").setOnClickListener {
            if (activeHandle == null) {
                status.text = "Unlock your vault before importing a text export."
            } else if (pendingUriListUri != null) {
                importOtpauthUriList(pendingUriListUri ?: return@setOnClickListener)
            } else {
                uriListDocumentPicker.launch(arrayOf("text/plain", "text/*", "*/*"))
            }
        }
        addText(
            "Imports plaintext text exports containing one otpauth:// URI per line, including Ente Auth plaintext exports. The file contains secret keys; import only from a trusted source and delete the source file when no longer needed.",
            12f
        )
        addButton("Create encrypted backup").setOnClickListener {
            if (activeHandle == null) {
                status.text = "Unlock your vault before creating a backup."
            } else if (pendingBackupExportUri != null) {
                promptBackupExportPassword()
            } else {
                backupExportDocumentPicker.launch("SuikaAuthenticator.suikabak")
            }
        }
        addButton("Restore encrypted backup").setOnClickListener {
            if (activeHandle == null) {
                status.text = "Unlock your vault before restoring a backup."
            } else if (pendingBackupRestoreUri != null) {
                promptBackupRestorePassword()
            } else {
                backupRestoreDocumentPicker.launch(
                    arrayOf("application/octet-stream", "application/x-suikabak", "*/*")
                )
            }
        }
        addText(
            "Backups are encrypted with a separate password. Restoring replaces all current accounts; it does not merge them.",
            12f
        )

        addSectionTitle("Security")
        addButton("Enable / replace biometric unlock").setOnClickListener {
            enableBiometricUnlock()
        }
        if (DeviceUnlockStore.hasWrappedKey(this)) {
            addButton("Disable biometric unlock").setOnClickListener {
                runCatching { DeviceUnlockStore.clear(applicationContext) }
                    .onSuccess { status.text = "Biometric unlock disabled on this device." }
                    .onFailure { showError(it) }
            }
        }
        addText(
            "Biometric unlock is device-specific. Your master password remains the recovery method.",
            12f
        )
        val lockChoices = arrayOf(
            "Immediately",
            "After 1 minute",
            "After 3 minutes",
            "After 5 minutes",
            "After 10 minutes"
        )
        val backgroundLockSelector = addDropdownField(
            "Lock when the app is no longer visible",
            lockChoices,
            backgroundLockTimeoutChoices.indexOf(backgroundLockTimeoutMs).coerceAtLeast(0)
        )

        searchInput = addTextField("Search issuer or account")
        searchInput.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) = Unit
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) = refreshAccountsNow()
            override fun afterTextChanged(s: Editable?) = Unit
        })
        accountList = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        content.addView(accountList, matchWidthWrapHeight())

        addSectionTitle("Add authenticator account")
        addText("Paste an otpauth:// provisioning URI or enter the account details and Base32 secret manually.", 13f)
        val issuer = addTextField("Issuer (optional)")
        val label = addTextField("Account name")
        val provisioningUri = addPasswordField("Provisioning URI (optional)")
        provisioningUri.filters = arrayOf(android.text.InputFilter.LengthFilter(4096))
        addButton("Scan QR code").setOnClickListener {
            requestQrScanner(provisioningUri)
        }
        val secret = addPasswordField("Base32 secret")
        sensitiveEnrollmentFields = listOf(provisioningUri, secret)
        val algorithm = addDropdownField(
            "HMAC algorithm",
            arrayOf("SHA-1", "SHA-256", "SHA-512"),
            0
        )
        val digits = addDropdownField("Code digits", arrayOf("6", "7", "8"), 0)
        val period = addDropdownField(
            "TOTP period",
            arrayOf("15 seconds", "30 seconds", "45 seconds", "60 seconds", "90 seconds", "120 seconds", "300 seconds"),
            1
        )
        val add = addButton("Add account")
        add.setOnClickListener {
            val handle = activeHandle ?: return@setOnClickListener
            val encodedUri = provisioningUri.text.toString().toByteArray(StandardCharsets.UTF_8)
            provisioningUri.text?.clear()
            if (encodedUri.isNotEmpty()) {
                secret.text?.clear()
                if (encodedUri.size > 4096) {
                    encodedUri.fill(0)
                    status.text = "The provisioning URI exceeds the supported 4096-byte limit."
                    return@setOnClickListener
                }
                add.isEnabled = false
                worker.execute {
                    val result = runCatching {
                        NativeBridge.nativeImportOtpAuthUri(handle, encodedUri)
                    }
                    encodedUri.fill(0)
                    runOnUiThread {
                        add.isEnabled = true
                        if (activeHandle == handle) {
                            result.onSuccess {
                                issuer.text?.clear()
                                label.text?.clear()
                                status.text = "Authenticator imported and encrypted."
                                refreshAccountsNow()
                            }.onFailure { showError(it) }
                        }
                    }
                }
                return@setOnClickListener
            }

            val issuerText = issuer.text.toString()
            val labelText = label.text.toString()
            val encodedSecret = secret.text.toString().toByteArray(StandardCharsets.US_ASCII)
            secret.text?.clear()
            if (labelText.isBlank() || encodedSecret.isEmpty()) {
                encodedSecret.fill(0)
                status.text = "Enter an account name and Base32 secret."
                return@setOnClickListener
            }
            val selectedAlgorithm = algorithm.selectedItemPosition + 1
            val selectedDigits = intArrayOf(6, 7, 8).getOrNull(digits.selectedItemPosition)
            val selectedPeriod = totpPeriodChoices.getOrNull(period.selectedItemPosition)
            if (selectedDigits == null || selectedPeriod == null) {
                encodedSecret.fill(0)
                status.text = "Choose valid OTP settings before adding the account."
                return@setOnClickListener
            }
            add.isEnabled = false
            worker.execute {
                val result = runCatching {
                    NativeBridge.nativeAddTotp(
                        handle,
                        issuerText,
                        labelText,
                        encodedSecret,
                        selectedAlgorithm,
                        selectedDigits,
                        selectedPeriod
                    )
                }
                encodedSecret.fill(0)
                runOnUiThread {
                    add.isEnabled = true
                    result.onSuccess {
                        issuer.text?.clear()
                        label.text?.clear()
                        status.text = "Account added and encrypted."
                        refreshAccountsNow()
                    }.onFailure { showError(it) }
                }
            }
        }
        status = addText("", 13f)
        backgroundLockSelector.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(
                parent: AdapterView<*>?,
                view: View?,
                position: Int,
                id: Long
            ) {
                val selectedTimeout = backgroundLockTimeoutChoices.getOrNull(position) ?: return
                if (selectedTimeout == backgroundLockTimeoutMs) return
                runCatching { saveBackgroundLockTimeout(selectedTimeout) }
                    .onSuccess {
                        status.text = "Background auto-lock updated."
                    }
                    .onFailure {
                        val previousIndex = backgroundLockTimeoutChoices.indexOf(backgroundLockTimeoutMs)
                        backgroundLockSelector.setSelection(previousIndex.coerceAtLeast(0))
                        status.text = "Could not save the auto-lock setting: " + it.message
                    }
            }

            override fun onNothingSelected(parent: AdapterView<*>?) = Unit
        }
        handler.removeCallbacks(accountRefresh)
        handler.removeCallbacks(accountRefresh)
        if (activityStarted) handler.post(accountRefresh)
        resetInactivityTimer()
        if (pendingAegisUri != null) {
            handler.post { promptAegisPassword() }
        }
        if (pendingUriListUri != null) {
            handler.post { pendingUriListUri?.let(::importOtpauthUriList) }
        }
        // A system document picker may background/auto-lock the vault before
        // returning its URI. Resume the pending backup action after re-unlock.
        if (pendingBackupExportUri != null) {
            handler.post { promptBackupExportPassword() }
        }
        if (pendingBackupRestoreUri != null) {
            handler.post { promptBackupRestorePassword() }
        }
    }

    private fun promptAegisPassword(message: String? = null) {
        val uri = pendingAegisUri ?: return
        if (activeAegisPasswordDialog?.isShowing == true) return
        if (activeHandle == null || isFinishing || isDestroyed) return

        val passwordField = EditText(this).apply {
            hint = "Aegis export password (leave blank for plaintext)"
            inputType = android.text.InputType.TYPE_CLASS_TEXT or
                android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD
            isSingleLine = true
            isSaveEnabled = false
            importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO
        }
        val dialog = AlertDialog.Builder(this)
            .setTitle("Import Aegis export")
            .setMessage(
                message ?: "Enter the export password. Leave it blank for an unencrypted Aegis JSON export."
            )
            .setView(passwordField)
            .setNegativeButton("Cancel") { _, _ -> pendingAegisUri = null }
            .setPositiveButton("Import", null)
            .create()
        dialog.setOnShowListener {
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                val password = passwordField.text.toString().toByteArray(StandardCharsets.UTF_8)
                passwordField.text?.clear()
                dialog.dismiss()
                importAegisDocument(uri, password)
            }
        }
        dialog.setOnCancelListener { pendingAegisUri = null }
        dialog.setOnDismissListener {
            passwordField.text?.clear()
            if (activeAegisPasswordDialog === dialog) {
                activeAegisPasswordDialog = null
            }
        }
        activeAegisPasswordDialog = dialog
        dialog.show()
        passwordField.requestFocus()
    }

    private fun promptBackupExportPassword() {
        val uri = pendingBackupExportUri ?: return
        if (activeHandle == null || isFinishing || isDestroyed) return

        val passwordField = EditText(this).apply {
            hint = "New backup password"
            inputType = android.text.InputType.TYPE_CLASS_TEXT or
                android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD
            isSingleLine = true
            isSaveEnabled = false
            importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO
        }
        val confirmationField = EditText(this).apply {
            hint = "Confirm backup password"
            inputType = android.text.InputType.TYPE_CLASS_TEXT or
                android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD
            isSingleLine = true
            isSaveEnabled = false
            importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO
        }
        val form = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(8), dp(20), 0)
            addView(passwordField, matchWidthWrapHeight())
            addView(confirmationField, matchWidthWrapHeight())
        }
        val dialog = AlertDialog.Builder(this)
            .setTitle("Encrypt backup")
            .setMessage("Choose a separate backup password. It is not your vault password; you will need it on any device to restore this file.")
            .setView(form)
            .setNegativeButton("Cancel") { _, _ -> pendingBackupExportUri = null }
            .setPositiveButton("Create backup", null)
            .create()
        dialog.setOnShowListener {
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                val passwordText = passwordField.text.toString()
                val confirmationText = confirmationField.text.toString()
                if (passwordText.isEmpty()) {
                    status.text = "Choose a non-empty backup password."
                    return@setOnClickListener
                }
                if (passwordText != confirmationText) {
                    status.text = "The backup password confirmation does not match."
                    return@setOnClickListener
                }
                val password = passwordText.toByteArray(StandardCharsets.UTF_8)
                if (password.size > MAX_BACKUP_PASSWORD_BYTES) {
                    password.fill(0)
                    status.text = "The backup password exceeds the supported 1024-byte limit."
                    return@setOnClickListener
                }
                passwordField.text?.clear()
                confirmationField.text?.clear()
                dialog.dismiss()
                pendingBackupExportUri = null
                exportEncryptedBackup(uri, password)
            }
        }
        dialog.setOnCancelListener { pendingBackupExportUri = null }
        dialog.setOnDismissListener {
            passwordField.text?.clear()
            confirmationField.text?.clear()
            pendingBackupExportUri = null
            if (activeBackupPasswordDialog === dialog) {
                activeBackupPasswordDialog = null
            }
        }
        activeBackupPasswordDialog = dialog
        dialog.show()
        passwordField.requestFocus()
    }

    private fun promptBackupRestorePassword(message: String? = null) {
        val uri = pendingBackupRestoreUri ?: return
        if (activeHandle == null || isFinishing || isDestroyed) return

        val passwordField = EditText(this).apply {
            hint = "Backup password"
            inputType = android.text.InputType.TYPE_CLASS_TEXT or
                android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD
            isSingleLine = true
            isSaveEnabled = false
            importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO
        }
        val dialog = AlertDialog.Builder(this)
            .setTitle("Restore encrypted backup")
            .setMessage(
                message ?: "This will replace every authenticator account currently in your vault. It does not merge accounts. Enter the separate password used when this backup was created."
            )
            .setView(passwordField)
            .setNegativeButton("Cancel") { _, _ -> pendingBackupRestoreUri = null }
            .setPositiveButton("Replace current accounts", null)
            .create()
        dialog.setOnShowListener {
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                val password = passwordField.text.toString().toByteArray(StandardCharsets.UTF_8)
                passwordField.text?.clear()
                if (password.isEmpty() || password.size > MAX_BACKUP_PASSWORD_BYTES) {
                    password.fill(0)
                    status.text = "Enter a valid backup password (maximum 1024 UTF-8 bytes)."
                    return@setOnClickListener
                }
                dialog.dismiss()
                pendingBackupRestoreUri = null
                restoreEncryptedBackup(uri, password)
            }
        }
        dialog.setOnCancelListener { pendingBackupRestoreUri = null }
        dialog.setOnDismissListener {
            passwordField.text?.clear()
            pendingBackupRestoreUri = null
            if (activeBackupPasswordDialog === dialog) {
                activeBackupPasswordDialog = null
            }
        }
        activeBackupPasswordDialog = dialog
        dialog.show()
        passwordField.requestFocus()
    }

    private fun exportEncryptedBackup(uri: Uri, password: ByteArray) {
        val handle = activeHandle
        if (handle == null) {
            password.fill(0)
            status.text = "Unlock your vault before creating a backup."
            return
        }
        status.text = "Encrypting backup…"
        worker.execute {
            var backup: ByteArray? = null
            val result = runCatching {
                backup = NativeBridge.nativeExportBackup(handle, password)
                val output = contentResolver.openOutputStream(uri, "wt")
                    ?: throw IllegalStateException("The selected backup destination could not be opened.")
                output.use { stream ->
                    stream.write(backup ?: throw IllegalStateException("Backup encryption returned no data."))
                    stream.flush()
                }
            }
            backup?.fill(0)
            password.fill(0)
            runOnUiThread {
                if (activeHandle != handle || isFinishing || isDestroyed) return@runOnUiThread
                result.onSuccess {
                    status.text = "Encrypted backup created. Keep its separate password safe; it cannot be recovered."
                }.onFailure { error ->
                    pendingBackupExportUri = uri
                    showError(error)
                }
            }
        }
    }

    private fun restoreEncryptedBackup(uri: Uri, password: ByteArray) {
        val handle = activeHandle
        if (handle == null) {
            password.fill(0)
            status.text = "Unlock your vault before restoring a backup."
            return
        }
        status.text = "Validating and restoring encrypted backup…"
        worker.execute {
            var backup: ByteArray? = null
            val result = runCatching {
                backup = readEncryptedBackup(uri)
                NativeBridge.nativeRestoreBackup(
                    handle,
                    backup ?: throw IllegalStateException("The encrypted backup could not be read."),
                    password
                )
            }
            backup?.fill(0)
            password.fill(0)
            runOnUiThread {
                if (activeHandle != handle || isFinishing || isDestroyed) return@runOnUiThread
                result.onSuccess { restoredCount ->
                    status.text = "Restored $restoredCount account(s). The previous account list was replaced."
                    refreshAccountsNow()
                }.onFailure { error ->
                    val message = error.message ?: "The encrypted backup could not be restored."
                    if (message.contains("backup password is incorrect", ignoreCase = true)) {
                        pendingBackupRestoreUri = uri
                        promptBackupRestorePassword(message)
                    } else {
                        showError(error)
                    }
                }
            }
        }
    }

    private fun readEncryptedBackup(uri: Uri): ByteArray =
        readBoundedDocument(
            uri,
            MAX_BACKUP_FILE_BYTES,
            "The encrypted backup exceeds its supported size limit."
        )

    private fun readBoundedDocument(uri: Uri, maximumBytes: Int, limitMessage: String): ByteArray {
        val input = contentResolver.openInputStream(uri)
            ?: throw IllegalStateException("The selected document could not be opened.")
        val output = ZeroizingByteArrayOutputStream(maximumBytes, limitMessage)
        val buffer = ByteArray(8192)
        try {
            input.use { stream ->
                while (true) {
                    val count = stream.read(buffer)
                    if (count < 0) break
                    if (count == 0) continue
                    if (count > maximumBytes || output.size() > maximumBytes - count) {
                        throw IllegalArgumentException(limitMessage)
                    }
                    output.write(buffer, 0, count)
                }
            }
            return output.toByteArray()
        } finally {
            buffer.fill(0)
            output.clear()
        }
    }

    private fun importOtpauthUriList(uri: Uri) {
        val handle = activeHandle
        if (handle == null) {
            pendingUriListUri = uri
            status.text = "Unlock your vault before importing a text export."
            return
        }
        pendingUriListUri = null
        status.text = "Reading and validating plaintext URI export…"
        worker.execute {
            var encodedExport: ByteArray? = null
            val result = runCatching {
                encodedExport = readBoundedDocument(
                    uri,
                    MAX_OTPAUTH_URI_LIST_BYTES,
                    "The plaintext URI export exceeds the 16 MiB import limit."
                )
                NativeBridge.nativeImportOtpAuthUriList(
                    handle,
                    encodedExport
                        ?: throw IllegalStateException("The plaintext URI export could not be read.")
                )
            }
            encodedExport?.fill(0)
            runOnUiThread {
                if (activeHandle != handle || isFinishing || isDestroyed) return@runOnUiThread
                result.onSuccess { imported ->
                    status.text = "Imported $imported authenticator account(s). The source text file is unchanged and contains unencrypted secret keys; delete it when no longer needed."
                    refreshAccountsNow()
                }.onFailure { showError(it) }
            }
        }
    }

    private fun importAegisDocument(uri: Uri, password: ByteArray) {
        val handle = activeHandle
        if (handle == null) {
            password.fill(0)
            status.text = "Unlock your vault before importing an Aegis export."
            return
        }
        status.text = "Reading and importing the Aegis export…"
        worker.execute {
            var exportBytes: ByteArray? = null
            val result = runCatching {
                exportBytes = readAegisExport(uri)
                NativeBridge.nativeImportAegisExport(
                    handle,
                    exportBytes ?: throw IllegalStateException("The Aegis export could not be read."),
                    password
                )
            }
            exportBytes?.fill(0)
            password.fill(0)
            runOnUiThread {
                if (activeHandle != handle || isFinishing || isDestroyed) return@runOnUiThread
                result.onSuccess { summary ->
                    val values = summary.split(':')
                    val imported = values.getOrNull(0)?.toIntOrNull()
                    val skipped = values.getOrNull(1)?.toIntOrNull()
                    if (imported == null || skipped == null) {
                        status.text = "The native importer returned an invalid result."
                    } else {
                        pendingAegisUri = null
                        status.text = "Imported $imported accounts; skipped $skipped unsupported entries. Imported secrets are now encrypted in your vault."
                        refreshAccountsNow()
                    }
                }.onFailure { error ->
                    val message = error.message ?: "The Aegis export could not be imported."
                    if (
                        message.contains("password is incorrect", ignoreCase = true) ||
                        message.contains("enter its export password", ignoreCase = true)
                    ) {
                        promptAegisPassword(message)
                    } else {
                        showError(error)
                    }
                }
            }
        }
    }

    private fun readAegisExport(uri: Uri): ByteArray =
        readBoundedDocument(
            uri,
            MAX_AEGIS_EXPORT_BYTES,
            "The Aegis export exceeds the 16 MiB import limit."
        )

    private class ZeroizingByteArrayOutputStream(
        private val maximumBytes: Int,
        private val limitMessage: String
    ) : ByteArrayOutputStream(8192) {
        private fun ensureBoundedCapacity(minimumCapacity: Int) {
            if (minimumCapacity < 0 || minimumCapacity > maximumBytes) {
                throw IllegalArgumentException(limitMessage)
            }
            if (minimumCapacity <= buf.size) return

            val doubled = (buf.size.toLong() * 2L)
                .coerceAtMost(maximumBytes.toLong())
                .toInt()
            val newCapacity = maxOf(minimumCapacity, doubled)
            val previous = buf
            buf = previous.copyOf(newCapacity)
            previous.fill(0)
        }

        @Synchronized
        override fun write(value: Int) {
            ensureBoundedCapacity(count + 1)
            super.write(value)
        }

        @Synchronized
        override fun write(source: ByteArray, offset: Int, length: Int) {
            if (
                offset < 0 || length < 0 ||
                offset > source.size - length
            ) {
                throw IndexOutOfBoundsException()
            }
            ensureBoundedCapacity(count + length)
            super.write(source, offset, length)
        }

        fun clear() {
            buf.fill(0)
            reset()
        }
    }

    private fun requestQrScanner(uriField: EditText) {
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA) ==
            PackageManager.PERMISSION_GRANTED
        ) {
            showQrScanner(uriField)
        } else {
            pendingQrUriField = uriField
            cameraPermissionLauncher.launch(Manifest.permission.CAMERA)
        }
    }

    private fun showQrScanner(uriField: EditText) {
        val scannerOptions = BarcodeScannerOptions.Builder()
            .setBarcodeFormats(Barcode.FORMAT_QR_CODE)
            .build()
        val scanner = BarcodeScanning.getClient(scannerOptions)
        val analysisExecutor = Executors.newSingleThreadExecutor()
        val mainExecutor = ContextCompat.getMainExecutor(this)
        val scannerClosed = AtomicBoolean(false)
        val closeRequested = AtomicBoolean(false)
        val scanAccepted = AtomicBoolean(false)
        val processingFrames = AtomicInteger(0)
        val preview = PreviewView(this).apply {
            scaleType = PreviewView.ScaleType.FILL_CENTER
        }
        val cameraController = LifecycleCameraController(this).apply {
            cameraSelector = CameraSelector.DEFAULT_BACK_CAMERA
            setEnabledUseCases(CameraController.IMAGE_ANALYSIS)
            setImageAnalysisBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
        }

        val scanLayout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(12), dp(8), dp(12), dp(8))
            addView(
                TextView(this@MainActivity).apply {
                    text = "Point the rear camera at an authenticator QR code."
                    textSize = 14f
                },
                matchWidthWrapHeight()
            )
            addView(
                preview,
                LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    dp(380)
                )
            )
        }
        val dialog = AlertDialog.Builder(this)
            .setTitle("Scan authenticator QR code")
            .setView(scanLayout)
            .setNegativeButton("Cancel", null)
            .create()

        fun closeScannerClient() {
            if (scannerClosed.compareAndSet(false, true)) {
                scanner.close()
            }
        }

        fun cleanupScanner() {
            if (closeRequested.compareAndSet(false, true)) {
                runCatching { cameraController.clearImageAnalysisAnalyzer() }
                runCatching { cameraController.unbind() }
                // Queue cleanup after every analyzer task already submitted by CameraX.
                // ML Kit tasks may outlive their analyzer callback; their completion
                // listener closes the scanner once the last in-flight frame is done.
                runCatching {
                    analysisExecutor.execute {
                        if (processingFrames.get() == 0) closeScannerClient()
                    }
                }
                analysisExecutor.shutdown()
            }
            activeQrScannerCleanup = null
        }

        dialog.setOnDismissListener { cleanupScanner() }
        activeQrScannerCleanup = {
            if (dialog.isShowing) dialog.dismiss()
            cleanupScanner()
        }

        cameraController.setImageAnalysisAnalyzer(
            analysisExecutor,
            ImageAnalysis.Analyzer { imageProxy ->
                if (closeRequested.get() || scanAccepted.get()) {
                    imageProxy.close()
                    return@Analyzer
                }
                val mediaImage = imageProxy.image
                if (mediaImage == null) {
                    imageProxy.close()
                    return@Analyzer
                }

                val inputImage = runCatching {
                    InputImage.fromMediaImage(
                        mediaImage,
                        imageProxy.imageInfo.rotationDegrees
                    )
                }.getOrElse {
                    imageProxy.close()
                    return@Analyzer
                }

                processingFrames.incrementAndGet()
                var capturedUri: String? = null
                try {
                    scanner.process(inputImage)
                        .addOnSuccessListener(mainExecutor) { barcodes ->
                            val value = barcodes.firstNotNullOfOrNull { barcode ->
                                barcode.rawValue?.takeIf {
                                    barcode.format == Barcode.FORMAT_QR_CODE &&
                                        it.startsWith("otpauth://", ignoreCase = true) &&
                                        it.toByteArray(StandardCharsets.UTF_8).size <= 4096
                                }
                            }
                            if (value != null && scanAccepted.compareAndSet(false, true)) {
                                capturedUri = value
                            }
                        }
                        .addOnFailureListener(mainExecutor) {
                            if (!closeRequested.get() && ::status.isInitialized) {
                                status.text = "The camera could not decode this frame. Keep the QR code steady and try again."
                            }
                        }
                        .addOnCompleteListener(mainExecutor) {
                            imageProxy.close()
                            val remaining = processingFrames.decrementAndGet()
                            if (closeRequested.get() && remaining == 0) closeScannerClient()

                            val value = capturedUri
                            if (value != null && !closeRequested.get()) {
                                uriField.setText(value)
                                if (::status.isInitialized) {
                                    status.text = "QR code decoded. Review the URI, then tap Add account."
                                }
                                dialog.dismiss()
                            }
                        }
                } catch (_: Exception) {
                    imageProxy.close()
                    val remaining = processingFrames.decrementAndGet()
                    if (closeRequested.get() && remaining == 0) closeScannerClient()
                    if (!closeRequested.get() && ::status.isInitialized) {
                        status.text = "The QR scanner could not process this camera frame."
                    }
                }
            }
        )

        try {
            dialog.show()
            preview.controller = cameraController
            cameraController.bindToLifecycle(this)
        } catch (error: Exception) {
            cleanupScanner()
            if (dialog.isShowing) dialog.dismiss()
            showError(error)
        }
    }

    private fun enableBiometricUnlock() {
        val handle = activeHandle ?: return
        val biometricStatus = BiometricManager.from(this)
            .canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)
        if (biometricStatus != BiometricManager.BIOMETRIC_SUCCESS) {
            status.text = when (biometricStatus) {
                BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED ->
                    "Enroll a strong biometric in Android settings before enabling biometric unlock."
                BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE ->
                    "This device does not have compatible strong biometric hardware."
                BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE ->
                    "Biometric hardware is temporarily unavailable."
                else -> "Strong biometric authentication is not available on this device."
            }
            return
        }

        status.text = "Preparing device-bound unlock…"
        worker.execute {
            val result = runCatching {
                val wrappingKey = NativeBridge.nativeExportDeviceUnlockKey(handle)
                try {
                    val cipher = DeviceUnlockStore.prepareEncryptionCipher(applicationContext)
                    Pair(wrappingKey, cipher)
                } catch (error: Throwable) {
                    wrappingKey.fill(0)
                    runCatching { DeviceUnlockStore.clear(applicationContext) }
                    throw error
                }
            }
            runOnUiThread {
                if (activeHandle != handle || isFinishing || isDestroyed) {
                    result.getOrNull()?.first?.fill(0)
                    runCatching { DeviceUnlockStore.clear(applicationContext) }
                    return@runOnUiThread
                }
                result.onSuccess { (wrappingKey, cipher) ->
                    pendingDeviceUnlockKey = wrappingKey
                    biometricEnrollmentInProgress = true
                    authenticateWithBiometric(
                        cipher,
                        "Enable biometric unlock",
                        "Cancel",
                        onAuthenticated = { authenticatedCipher ->
                            val material = pendingDeviceUnlockKey
                            pendingDeviceUnlockKey = null
                            if (material == null) {
                                runCatching { DeviceUnlockStore.clear(applicationContext) }
                                biometricEnrollmentInProgress = false
                                status.text = "Biometric enrollment was canceled."
                                return@authenticateWithBiometric
                            }
                            val encrypted = runCatching {
                                authenticatedCipher.doFinal(material)
                            }
                            material.fill(0)
                            encrypted.onSuccess { ciphertext ->
                                val iv = authenticatedCipher.iv
                                worker.execute {
                                    val saved = runCatching {
                                        DeviceUnlockStore.store(applicationContext, iv, ciphertext)
                                    }
                                    ciphertext.fill(0)
                                    iv.fill(0)
                                    runOnUiThread {
                                        biometricEnrollmentInProgress = false
                                        if (activeHandle == handle && !isFinishing && !isDestroyed) {
                                            if (saved.isSuccess) {
                                                status.text = "Biometric unlock enabled on this device."
                                            } else {
                                                runCatching { DeviceUnlockStore.clear(applicationContext) }
                                                saved.onFailure { showError(it) }
                                            }
                                        } else {
                                            runCatching { DeviceUnlockStore.clear(applicationContext) }
                                        }
                                    }
                                }
                            }.onFailure {
                                runCatching { DeviceUnlockStore.clear(applicationContext) }
                                biometricEnrollmentInProgress = false
                                showError(it)
                            }
                        },
                        onError = { _, message ->
                            pendingDeviceUnlockKey?.fill(0)
                            pendingDeviceUnlockKey = null
                            biometricEnrollmentInProgress = false
                            runCatching { DeviceUnlockStore.clear(applicationContext) }
                            if (!isFinishing && !isDestroyed) status.text = message
                        }
                    )
                }.onFailure {
                    if (!isFinishing && !isDestroyed) showError(it)
                }
            }
        }
    }

    private fun beginBiometricUnlock() {
        if (activeHandle != null) return
        val wrapped = runCatching { DeviceUnlockStore.load(applicationContext) }
            .getOrElse {
                runCatching { DeviceUnlockStore.clear(applicationContext) }
                status.text = "Biometric unlock data is unavailable. Use your master password."
                return
            } ?: run {
                status.text = "Biometric unlock is not configured. Use your master password."
                return
            }

        val cipher = try {
            DeviceUnlockStore.prepareDecryptionCipher(wrapped.iv)
        } catch (error: android.security.keystore.KeyPermanentlyInvalidatedException) {
            wrapped.iv.fill(0)
            wrapped.ciphertext.fill(0)
            runCatching { DeviceUnlockStore.clear(applicationContext) }
            status.text = "Device security or biometric enrollment changed. Unlock with your master password, then enable biometrics again."
            return
        } catch (error: Throwable) {
            wrapped.iv.fill(0)
            wrapped.ciphertext.fill(0)
            runCatching { DeviceUnlockStore.clear(applicationContext) }
            showError(error)
            return
        }

        authenticateWithBiometric(
            cipher,
            "Unlock SuikaAuthenticator",
            "Use master password",
            onAuthenticated = { authenticatedCipher ->
                val material = runCatching {
                    authenticatedCipher.doFinal(wrapped.ciphertext)
                }.getOrElse {
                    wrapped.iv.fill(0)
                    wrapped.ciphertext.fill(0)
                    runCatching { DeviceUnlockStore.clear(applicationContext) }
                    status.text = "Biometric unlock failed. Use your master password."
                    return@authenticateWithBiometric
                }
                wrapped.iv.fill(0)
                wrapped.ciphertext.fill(0)
                if (material.size != 32) {
                    material.fill(0)
                    runCatching { DeviceUnlockStore.clear(applicationContext) }
                    status.text = "Biometric unlock data is invalid. Use your master password."
                    return@authenticateWithBiometric
                }

                status.text = "Unlocking encrypted vault…"
                worker.execute {
                    val result = runCatching {
                        NativeBridge.nativeUnlockVaultWithDeviceKey(
                            noBackupFilesDir.absolutePath,
                            material
                        )
                    }
                    material.fill(0)
                    runOnUiThread {
                        result.onSuccess { handle ->
                            if (activeHandle == null && !isFinishing && !isDestroyed) {
                                activeHandle = handle
                                appState.nativeSessionHandle = handle
                                vaultExists = true
                                showVault()
                                applyBackgroundLockPolicy()
                            } else {
                                worker.execute { runCatching { NativeBridge.nativeLockVault(handle) } }
                            }
                        }.onFailure {
                            runCatching { DeviceUnlockStore.clear(applicationContext) }
                            if (!isFinishing && !isDestroyed) {
                                status.text = "Biometric unlock was rejected. Use your master password."
                            }
                        }
                    }
                }
            },
            onError = { errorCode, message ->
                wrapped.iv.fill(0)
                wrapped.ciphertext.fill(0)
                if (!isFinishing && !isDestroyed) {
                    status.text = if (errorCode == BiometricPrompt.ERROR_NEGATIVE_BUTTON) {
                        "Enter your master password to unlock."
                    } else {
                        message
                    }
                }
            }
        )
    }

    private fun authenticateWithBiometric(
        cipher: Cipher,
        title: String,
        negativeButton: String,
        onAuthenticated: (Cipher) -> Unit,
        onError: (Int, CharSequence) -> Unit
    ) {
        val prompt = BiometricPrompt(
            this,
            ContextCompat.getMainExecutor(this),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    biometricPromptVisible = false
                    activeBiometricPrompt = null
                    onError(errorCode, errString)
                    applyBackgroundLockPolicy()
                }

                override fun onAuthenticationSucceeded(
                    result: BiometricPrompt.AuthenticationResult
                ) {
                    biometricPromptVisible = false
                    activeBiometricPrompt = null
                    val authenticatedCipher = result.cryptoObject?.cipher
                    if (authenticatedCipher == null) {
                        onError(
                            BiometricPrompt.ERROR_UNABLE_TO_PROCESS,
                            "Biometric authentication did not return a cryptographic operation."
                        )
                    } else {
                        onAuthenticated(authenticatedCipher)
                    }
                    applyBackgroundLockPolicy()
                }

                override fun onAuthenticationFailed() {
                    if (::status.isInitialized && !isFinishing && !isDestroyed) {
                        status.text = "Biometric not recognized. Try again."
                    }
                }
            }
        )
        activeBiometricPrompt = prompt
        biometricPromptVisible = true
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setSubtitle("Authenticate with this device to protect your encrypted vault")
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .setNegativeButtonText(negativeButton)
            .build()
        prompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
    }

    private fun applyBackgroundLockPolicy() {
        if (activityStarted || isChangingConfigurations || isFinishing || isDestroyed || activeHandle == null) {
            return
        }
        handler.removeCallbacks(backgroundLock)
        if (backgroundLockTimeoutMs == 0L) {
            lockSession(showAuthentication = true)
        } else {
            handler.postDelayed(backgroundLock, backgroundLockTimeoutMs)
        }
    }

    private fun cancelBiometricPrompt() {
        activeBiometricPrompt?.cancelAuthentication()
        activeBiometricPrompt = null
        biometricPromptVisible = false
        pendingDeviceUnlockKey?.fill(0)
        pendingDeviceUnlockKey = null
        if (biometricEnrollmentInProgress) {
            runCatching { DeviceUnlockStore.clear(applicationContext) }
            biometricEnrollmentInProgress = false
        }
    }

    private fun refreshAccountsNow() {
        val handle = activeHandle ?: return
        if (isRefreshing || !::accountList.isInitialized) return
        isRefreshing = true
        worker.execute {
            val result = runCatching { NativeBridge.nativeListAccounts(handle) }
            runOnUiThread {
                isRefreshing = false
                if (activeHandle == handle) {
                    result.onSuccess { renderAccounts(it) }.onFailure { showError(it) }
                }
            }
        }
    }

    private fun renderAccounts(fields: Array<String>) {
        if (!::accountList.isInitialized) return
        val handle = activeHandle ?: return
        accountList.removeAllViews()
        val filter = if (::searchInput.isInitialized) searchInput.text.toString().trim() else ""
        val rows = fields.toList().chunked(5).filter { row ->
            row.size == 5 && (filter.isEmpty() ||
                row[1].contains(filter, ignoreCase = true) ||
                row[2].contains(filter, ignoreCase = true))
        }
        if (rows.isEmpty()) {
            val empty = TextView(this).apply {
                text = if (fields.isEmpty()) "No accounts yet. Add a TOTP account below." else "No matching accounts."
                textSize = 14f
                setTextColor(0xFF202124.toInt())
            }
            accountList.addView(empty, matchWidthWrapHeight())
            return
        }

        rows.forEach { row ->
            val accountId = row[0]
            val issuer = row[1]
            val label = row[2]
            val code = row[3]
            val kind = row[4]
            val card = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(dp(14), dp(12), dp(14), dp(12))
                setBackgroundColor(0xFFF1F3F4.toInt())
            }
            val title = TextView(this).apply {
                text = if (issuer.isBlank()) label else "$issuer · $label"
                textSize = 15f
                setTextColor(0xFF202124.toInt())
            }
            val value = TextView(this).apply {
                text = if (code.isBlank()) "Tap to generate next code" else code.chunked(3).joinToString(" ")
                textSize = if (code.isBlank()) 14f else 25f
                typeface = if (code.isBlank()) Typeface.DEFAULT else Typeface.MONOSPACE
                setTextColor(0xFF202124.toInt())
                setPadding(0, dp(8), 0, dp(4))
            }
            val type = TextView(this).apply {
                text = kind
                textSize = 12f
                setTextColor(0xFF5F6368.toInt())
            }
            card.addView(title)
            card.addView(value)
            card.addView(type)

            val actions = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
                setPadding(0, dp(8), 0, 0)
            }
            val edit = Button(this).apply {
                text = "Edit"
                setOnClickListener {
                    showEditAccountDialog(handle, accountId, issuer, label)
                }
            }
            val remove = Button(this).apply {
                text = "Remove"
                setOnClickListener {
                    confirmRemoveAccount(handle, accountId, label)
                }
            }
            actions.addView(edit, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
            actions.addView(remove, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
            card.addView(actions)

            card.setOnClickListener {
                if (kind.startsWith("HOTP")) consumeAndCopyHotp(handle, accountId, label)
                else copyCode(code, label)
            }
            accountList.addView(card, matchWidthWrapHeight().apply { bottomMargin = dp(10) })
        }
    }

    private fun showEditAccountDialog(
        handle: Long,
        accountId: String,
        currentIssuer: String,
        currentLabel: String
    ) {
        val form = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(8), dp(20), 0)
        }
        val issuerField = EditText(this).apply {
            hint = "Issuer (optional)"
            setText(currentIssuer)
            isSingleLine = true
            isSaveEnabled = false
        }
        val labelField = EditText(this).apply {
            hint = "Account name"
            setText(currentLabel)
            isSingleLine = true
            isSaveEnabled = false
        }
        val replacementSecret = EditText(this).apply {
            hint = "Replacement Base32 secret (optional)"
            inputType = android.text.InputType.TYPE_CLASS_TEXT or
                android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD
            isSingleLine = true
            isSaveEnabled = false
            importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO
        }
        form.addView(issuerField, matchWidthWrapHeight())
        form.addView(labelField, matchWidthWrapHeight())
        form.addView(replacementSecret, matchWidthWrapHeight())

        val dialog = AlertDialog.Builder(this)
            .setTitle("Edit authenticator")
            .setView(form)
            .setNegativeButton("Cancel", null)
            .setPositiveButton("Save", null)
            .create()
        dialog.setOnShowListener {
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                val updatedLabel = labelField.text.toString().trim()
                if (updatedLabel.isEmpty()) {
                    status.text = "Enter an account name."
                    return@setOnClickListener
                }
                val updatedIssuer = issuerField.text.toString()
                val secretBytes = replacementSecret.text.toString()
                    .trim()
                    .toByteArray(StandardCharsets.US_ASCII)
                replacementSecret.text?.clear()
                dialog.dismiss()
                worker.execute {
                    val result = runCatching {
                        NativeBridge.nativeUpdateAccount(
                            handle,
                            accountId,
                            updatedIssuer,
                            updatedLabel,
                            secretBytes
                        )
                    }
                    secretBytes.fill(0)
                    runOnUiThread {
                        if (activeHandle == handle) {
                            result.onSuccess {
                                status.text = "Account updated and encrypted."
                                refreshAccountsNow()
                            }.onFailure { showError(it) }
                        }
                    }
                }
            }
        }
        dialog.show()
    }

    private fun confirmRemoveAccount(handle: Long, accountId: String, label: String) {
        AlertDialog.Builder(this)
            .setTitle("Remove authenticator")
            .setMessage("Remove ‘$label’? Its secret will be removed from the encrypted vault.")
            .setNegativeButton("Cancel", null)
            .setPositiveButton("Remove") { _, _ ->
                worker.execute {
                    val result = runCatching {
                        NativeBridge.nativeRemoveAccount(handle, accountId)
                    }
                    runOnUiThread {
                        if (activeHandle == handle) {
                            result.onSuccess {
                                status.text = "Account removed from the encrypted vault."
                                refreshAccountsNow()
                            }.onFailure { showError(it) }
                        }
                    }
                }
            }
            .show()
    }

    private fun consumeAndCopyHotp(handle: Long, accountId: String, label: String) {
        if (!pendingHotp.add(accountId)) return
        worker.execute {
            val result = runCatching { NativeBridge.nativeConsumeHotp(handle, accountId) }
            runOnUiThread {
                pendingHotp.remove(accountId)
                if (activeHandle == handle) {
                    result.onSuccess { code ->
                        copyCode(code, label)
                        refreshAccountsNow()
                    }.onFailure { showError(it) }
                }
            }
        }
    }

    private fun copyCode(code: String, label: String) {
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val token = UUID.randomUUID().toString()
        val expiresAt = SystemClock.elapsedRealtime() + OTP_CLIPBOARD_TTL_MS
        val clip = ClipData.newPlainText("One-time code for $label", code).apply {
            description.extras = PersistableBundle().apply {
                putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
                putString(OTP_CLIPBOARD_OWNER_KEY, OTP_CLIPBOARD_OWNER)
                putString(OTP_CLIPBOARD_TOKEN_KEY, token)
                putLong(OTP_CLIPBOARD_EXPIRY_KEY, expiresAt)
            }
        }

        clipboard.setPrimaryClip(clip)
        appState.otpClipboardToken = token
        appState.otpClipboardExpiresAtElapsedRealtime = expiresAt
        handler.removeCallbacks(otpClipboardExpiry)
        handler.postDelayed(otpClipboardExpiry, OTP_CLIPBOARD_TTL_MS)

        // Android 13+ displays its own copy confirmation.
        if (Build.VERSION.SDK_INT <= Build.VERSION_CODES.S_V2) {
            Toast.makeText(this, "Code copied", Toast.LENGTH_SHORT).show()
        }
    }

    private fun refreshOtpClipboardExpiry() {
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        // Android may return null while this Activity is not allowed to inspect
        // the clipboard. Keep the marker and retry when the app is foregrounded.
        val description = clipboard.primaryClipDescription ?: return
        val extras = description.extras
        if (extras?.getString(OTP_CLIPBOARD_OWNER_KEY) != OTP_CLIPBOARD_OWNER) {
            appState.otpClipboardToken = null
            appState.otpClipboardExpiresAtElapsedRealtime = 0L
            return
        }

        val clipToken = extras.getString(OTP_CLIPBOARD_TOKEN_KEY)
        val trackedToken = appState.otpClipboardToken
        if (trackedToken != null && trackedToken != clipToken) {
            appState.otpClipboardToken = null
            appState.otpClipboardExpiresAtElapsedRealtime = 0L
            return
        }

        val expiresAt = extras.getLong(
            OTP_CLIPBOARD_EXPIRY_KEY,
            appState.otpClipboardExpiresAtElapsedRealtime
        )
        if (expiresAt <= 0L) {
            appState.otpClipboardToken = null
            appState.otpClipboardExpiresAtElapsedRealtime = 0L
            return
        }

        appState.otpClipboardToken = clipToken
        appState.otpClipboardExpiresAtElapsedRealtime = expiresAt
        val remaining = expiresAt - SystemClock.elapsedRealtime()
        if (remaining > 0L) {
            handler.removeCallbacks(otpClipboardExpiry)
            handler.postDelayed(otpClipboardExpiry, remaining)
            return
        }

        // Clear only the clip whose metadata still identifies it as ours.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            clipboard.clearPrimaryClip()
        } else {
            clipboard.setPrimaryClip(ClipData.newPlainText("", ""))
        }
        appState.otpClipboardToken = null
        appState.otpClipboardExpiresAtElapsedRealtime = 0L
    }

    private fun lockSession(showAuthentication: Boolean) {
        activeQrScannerCleanup?.invoke()
        clearSensitiveEnrollmentFields()
        cancelBiometricPrompt()
        handler.removeCallbacks(accountRefresh)
        handler.removeCallbacks(inactivityLock)
        pendingBackupExportUri = null
        pendingBackupRestoreUri = null
        activeBackupPasswordDialog?.dismiss()
        val handle = activeHandle
        activeHandle = null
        appState.nativeSessionHandle = null
        if (handle != null) worker.execute { runCatching { NativeBridge.nativeLockVault(handle) } }
        if (showAuthentication && vaultExists != null && !isFinishing) renderAuthentication(existingVault = true)
    }

    private fun clearSensitiveEnrollmentFields() {
        sensitiveEnrollmentFields.forEach { field ->
            field.text?.clear()
        }
        sensitiveEnrollmentFields = emptyList()
    }

    private fun resetInactivityTimer() {
        handler.removeCallbacks(inactivityLock)
        handler.postDelayed(inactivityLock, inactivityTimeoutMs)
    }

    private fun showError(error: Throwable) {
        val message = error.message?.takeIf { it.isNotBlank() } ?: "An unexpected native operation failed."
        if (::status.isInitialized) status.text = message
        else Toast.makeText(this, message, Toast.LENGTH_LONG).show()
    }

    private fun addHeading(value: String) {
        addText(value, 26f).apply {
            setTypeface(null, Typeface.BOLD)
            setPadding(0, 0, 0, dp(8))
        }
    }

    private fun addSectionTitle(value: String) {
        addText(value, 17f).apply {
            setTypeface(null, Typeface.BOLD)
            setPadding(0, dp(20), 0, dp(8))
        }
    }

    private fun addText(value: String, size: Float): TextView {
        val view = TextView(this).apply {
            text = value
            textSize = size
            setTextColor(0xFF202124.toInt())
            setPadding(0, dp(5), 0, dp(5))
        }
        content.addView(view, matchWidthWrapHeight())
        return view
    }

    private fun addPasswordField(hint: String): EditText = addTextField(hint).apply {
        inputType = android.text.InputType.TYPE_CLASS_TEXT or android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD
    }

    private fun addTextField(hint: String): EditText {
        val field = EditText(this).apply {
            this.hint = hint
            isSingleLine = true
            isSaveEnabled = false
            importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO
            setPadding(dp(10), dp(8), dp(10), dp(8))
        }
        content.addView(field, matchWidthWrapHeight())
        return field
    }

    private fun addDropdownField(
        label: String,
        options: Array<String>,
        selectedIndex: Int
    ): Spinner {
        addSectionTitle(label)
        val spinner = Spinner(this)
        val adapter = ArrayAdapter(this, android.R.layout.simple_spinner_item, options)
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        spinner.adapter = adapter
        spinner.setSelection(selectedIndex.coerceIn(options.indices))
        content.addView(spinner, matchWidthWrapHeight())
        return spinner
    }

    private fun loadBackgroundLockTimeout(): Long = runCatching {
        val settings = File(
            File(noBackupFilesDir, "SuikaAuthenticator"),
            "background-lock-timeout-ms"
        )
        val stored = if (settings.isFile) settings.readText().trim().toLongOrNull() else null
        backgroundLockTimeoutChoices.firstOrNull { it == stored } ?: 0L
    }.getOrDefault(0L)

    private fun saveBackgroundLockTimeout(timeout: Long) {
        require(backgroundLockTimeoutChoices.any { it == timeout }) {
            "Unsupported background auto-lock interval."
        }
        val directory = File(noBackupFilesDir, "SuikaAuthenticator")
        check(directory.isDirectory || directory.mkdirs()) {
            "The application data directory could not be created."
        }
        File(directory, "background-lock-timeout-ms").writeText(timeout.toString())
        backgroundLockTimeoutMs = timeout
    }

    private fun addButton(label: String): Button {
        val button = Button(this).apply { text = label; gravity = Gravity.CENTER }
        content.addView(button, matchWidthWrapHeight())
        return button
    }

    private fun matchWidthWrapHeight() = LinearLayout.LayoutParams(
        LinearLayout.LayoutParams.MATCH_PARENT,
        LinearLayout.LayoutParams.WRAP_CONTENT
    )

    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()
}
