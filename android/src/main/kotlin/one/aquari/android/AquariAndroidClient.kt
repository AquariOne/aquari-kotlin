package one.aquari.android

import android.content.Context
import android.net.Uri
import androidx.browser.customtabs.CustomTabsIntent
import one.aquari.sdk.AquariAuthorizationPrompt
import one.aquari.sdk.AquariAuthorizationTransaction
import one.aquari.sdk.AquariClient
import one.aquari.sdk.AquariIdentity
import one.aquari.sdk.AquariOAuthException
import one.aquari.sdk.AquariTokenSet

/**
 * Defines protected storage for the current Aquari token set on a device.
 */
interface AquariTokenStore {
    /**
     * Reads the current value from protected Aquari storage. Returns no value when the store is empty.
     */
    suspend fun read(): AquariTokenSet?
    /**
     * Replaces the current value in protected Aquari storage.
     */
    suspend fun write(tokens: AquariTokenSet)
    /**
     * Removes the current value from protected Aquari storage.
     */
    suspend fun clear()
}

/**
 * Defines protected storage for the pending Aquari authorization transaction.
 */
interface AquariAuthorizationTransactionStore {
    /**
     * Reads the current value from protected Aquari storage. Returns no value when the store is empty.
     */
    suspend fun read(): AquariAuthorizationTransaction?
    /**
     * Replaces the current value in protected Aquari storage.
     */
    suspend fun write(transaction: AquariAuthorizationTransaction)
    /**
     * Removes the current value from protected Aquari storage.
     */
    suspend fun clear()
}

/**
 * Defines the external browser handoff used to start Aquari authorization.
 */
fun interface AquariAuthorizationLauncher {
    /**
     * Opens the supplied Aquari authorization URL in the platform system browser.
     */
    fun launch(url: Uri)
}

/**
 * Opens Aquari authorization in Android Custom Tabs through the system browser.
 */
class CustomTabsAquariAuthorizationLauncher(
    private val context: Context,
) : AquariAuthorizationLauncher {
    /**
     * Opens the supplied Aquari authorization URL in the platform system browser.
     */
    override fun launch(url: Uri) {
        CustomTabsIntent.Builder()
            .build()
            .launchUrl(context, url)
    }
}

/**
 * Contains the current Aquari token set and subject-bound identity on Android.
 */
data class AquariAndroidSession(
    /**
     * Gets the current subject-bound token set. Do not log token values.
     */
    val tokens: AquariTokenSet,
    /**
     * Gets the subject-bound Aquari identity.
     */
    val identity: AquariIdentity,
)

/**
 * Coordinates system-browser authorization, protected session storage, refresh, and sign-out on
 * Android.
 */
class AquariAndroidClient(
    private val client: AquariClient,
    private val tokenStore: AquariTokenStore,
    private val transactionStore: AquariAuthorizationTransactionStore,
    private val authorizationLauncher: AquariAuthorizationLauncher,
) {
    /**
     * Creates and stores a pending Authorization Code transaction, then opens the Aquari authorization URL
     * in the system browser.
     */
    suspend fun beginAuthorization(prompt: AquariAuthorizationPrompt? = null) {
        val result = client.auth.begin(prompt)
        transactionStore.write(result.transaction)
        authorizationLauncher.launch(Uri.parse(result.url))
    }

    /**
     * Completes the stored authorization transaction. The SDK validates callback state and issuer data,
     * exchanges the code, validates the returned identity, stores the new token set, and clears pending
     * transaction state.
     */
    suspend fun completeAuthorization(callback: Uri): AquariAndroidSession {
        val transaction = transactionStore.read()
            ?: throw AquariOAuthException(
                "missing_transaction",
                "Aquari cannot complete authorization because the initiating transaction is unavailable.",
            )

        return try {
            val result = client.auth.complete(callback.toString(), transaction)
            tokenStore.write(result.tokens)
            AquariAndroidSession(result.tokens, result.identity)
        } finally {
            transactionStore.clear()
        }
    }

    /**
     * Restores session state from protected storage and resolves Aquari UserInfo for the stored token set.
     * This operation does not refresh an expired token automatically; call refreshSession when a refresh
     * is required.
     */
    suspend fun restoreSession(): AquariAndroidSession? {
        val tokens = tokenStore.read() ?: return null
        val identity = client.auth.userInfo(tokens)
        return AquariAndroidSession(tokens, identity)
    }

    /**
     * Refreshes the stored Aquari session, replaces the token set, resolves UserInfo, and preserves
     * subject continuity.
     */
    suspend fun refreshSession(): AquariAndroidSession {
        val current = tokenStore.read()
            ?: throw AquariOAuthException("missing_session", "Aquari cannot refresh because no stored session exists.")
        val refreshed = client.auth.refresh(current)
        tokenStore.write(refreshed)
        val identity = client.auth.userInfo(refreshed)
        return AquariAndroidSession(refreshed, identity)
    }

    /**
     * Clears local Aquari session and pending authorization state. This operation does not grant or revoke
     * application permissions.
     */
    suspend fun signOut() {
        transactionStore.clear()
        tokenStore.clear()
    }
}
