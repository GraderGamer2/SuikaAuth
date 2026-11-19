package org.suika.suikaauthenticator

import android.app.Activity
import android.app.AlertDialog
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.graphics.Typeface
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.Editable
import android.text.TextWatcher
import android.view.Gravity
import android.view.MotionEvent
import android.view.View
import android.view.inputmethod.EditorInfo
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import java.nio.charset.StandardCharsets
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

class MainActivity : Activity() {
    private val worker: ExecutorService = Executors.newSingleThreadExecutor()
    private val handler = Handler(Looper.getMainLooper())
    private val inactivityTimeoutMs = 5 * 60 * 1000L
    private var activeHandle: Long? = null
    private var vaultExists: Boolean? = null
    private var isRefreshing = false
    private val pendingHotp = mutableSetOf<String>()

    private lateinit var content: LinearLayout
    private lateinit var status: TextView
    private lateinit var accountList: LinearLayout
    private lateinit var searchInput: EditText

    private val inactivityLock = Runnable { lockSession(showAuthentication = true) }

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
        buildShell()
        status.text = "Checking encrypted vault…"
        worker.execute {
            val result = runCatching { NativeBridge.nativeHasVault(noBackupFilesDir.absolutePath) }
            runOnUiThread {
                result.onSuccess {
                    vaultExists = it
                    renderAuthentication(it)
                }.onFailure { showError(it) }
            }
        }
    }

    override fun onStart() {
        super.onStart()
        if (activeHandle == null && vaultExists == true && content.childCount > 0) {
            renderAuthentication(existingVault = true)
        }
    }

    override fun onStop() {
        handler.removeCallbacks(accountRefresh)
        handler.removeCallbacks(inactivityLock)
        val handle = activeHandle
        activeHandle = null
        if (handle != null) worker.execute { runCatching { NativeBridge.nativeLockVault(handle) } }
        super.onStop()
    }

    override fun onDestroy() {
        handler.removeCallbacksAndMessages(null)
        worker.shutdown()
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
        handler.removeCallbacks(accountRefresh)
        activeHandle = null
        content.removeAllViews()
        addHeading("SuikaAuthenticator")
        addText(if (existingVault) "Unlock your encrypted vault" else "Create your encrypted vault", 16f)
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
        handler.removeCallbacks(accountRefresh)
        content.removeAllViews()
        addHeading("Your accounts")
        addText("Vault unlocked · encrypted storage is active", 13f)
        addButton("Lock vault").setOnClickListener { lockSession(showAuthentication = true) }

        searchInput = addTextField("Search issuer or account")
        searchInput.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) = Unit
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) = refreshAccountsNow()
            override fun afterTextChanged(s: Editable?) = Unit
        })
        accountList = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        content.addView(accountList, matchWidthWrapHeight())

        addSectionTitle("Add TOTP account")
        val issuer = addTextField("Issuer (optional)")
        val label = addTextField("Account name")
        val secret = addPasswordField("Base32 secret")
        val add = addButton("Add account")
        add.setOnClickListener {
            val handle = activeHandle ?: return@setOnClickListener
            val issuerText = issuer.text.toString()
            val labelText = label.text.toString()
            val encodedSecret = secret.text.toString().toByteArray(StandardCharsets.US_ASCII)
            secret.text?.clear()
            if (labelText.isBlank() || encodedSecret.isEmpty()) {
                encodedSecret.fill(0)
                status.text = "Enter an account name and Base32 secret."
                return@setOnClickListener
            }
            add.isEnabled = false
            worker.execute {
                val result = runCatching {
                    NativeBridge.nativeAddTotp(handle, issuerText, labelText, encodedSecret, 1, 6, 30L)
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
        handler.post(accountRefresh)
        resetInactivityTimer()
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
        clipboard.setPrimaryClip(ClipData.newPlainText("One-time code for $label", code))
        Toast.makeText(this, "Code copied", Toast.LENGTH_SHORT).show()
    }

    private fun lockSession(showAuthentication: Boolean) {
        handler.removeCallbacks(accountRefresh)
        handler.removeCallbacks(inactivityLock)
        val handle = activeHandle
        activeHandle = null
        if (handle != null) worker.execute { runCatching { NativeBridge.nativeLockVault(handle) } }
        if (showAuthentication && vaultExists != null && !isFinishing) renderAuthentication(existingVault = true)
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
