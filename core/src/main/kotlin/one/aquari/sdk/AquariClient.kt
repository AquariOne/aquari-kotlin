package one.aquari.sdk

/**
 * Provides the main Aquari runtime entry point for authentication, Passport, and trust operations.
 */
class AquariClient(options: AquariClientOptions) {
    private val resolved = resolveOptions(options)
    private val transport = AquariHttpTransport(
        baseUrl = resolved.issuer,
        timeoutMs = resolved.timeoutMs,
        maxRetries = resolved.maxRetries,
        maxRetryDelayMs = resolved.maxRetryDelayMs,
        executor = resolved.httpExecutor,
    )

    /**
     * Gets the normalized Aquari issuer URL.
     */
    val issuer: String = resolved.issuer
    /**
     * Gets the configured OAuth client identifier.
     */
    val clientId: String = resolved.clientId
    /**
     * Gets the registered OAuth redirect URI.
     */
    val redirectUri: String = resolved.redirectUri
    /**
     * Gets the OAuth scopes requested by this client.
     */
    val scopes: List<String> = resolved.scopes

    /**
     * Gets authentication and token-lifecycle operations.
     */
    val auth = AquariAuthClient(resolved, transport)
    /**
     * Gets Passport read operations.
     */
    val passport = AquariPassportClient(transport)
    /**
     * Gets trust-evaluation operations.
     */
    val trust = AquariTrustClient(transport)
}
