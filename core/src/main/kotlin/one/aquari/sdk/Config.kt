package one.aquari.sdk

import java.net.URI

const val DEFAULT_REQUEST_TIMEOUT_MS: Long = 15_000
const val DEFAULT_MAX_RETRIES: Int = 2
const val DEFAULT_MAX_RETRY_DELAY_MS: Long = 5_000

/**
 * Configures an Aquari OAuth client and its HTTP behavior. Do not put a confidential client secret in
 * distributable client code.
 */
data class AquariClientOptions(
    /**
     * Sets the absolute Aquari issuer URL. Remote issuers must use HTTPS.
     */
    val issuer: String,
    /**
     * Sets the OAuth client identifier registered for this application.
     */
    val clientId: String,
    /**
     * Sets the exact OAuth redirect URI registered for this client.
     */
    val redirectUri: String,
    /**
     * Sets the OAuth scopes requested during authorization. Request offline_access when the application
     * needs refresh tokens.
     */
    val scopes: List<String>,
    /**
     * Sets the request timeout in milliseconds.
     */
    val timeoutMs: Long = DEFAULT_REQUEST_TIMEOUT_MS,
    /**
     * Sets the maximum number of transport retries after the first request attempt.
     */
    val maxRetries: Int = DEFAULT_MAX_RETRIES,
    /**
     * Caps retry backoff in milliseconds.
     */
    val maxRetryDelayMs: Long = DEFAULT_MAX_RETRY_DELAY_MS,
    val httpExecutor: AquariHttpExecutor? = null,
)

internal data class ResolvedAquariClientOptions(
    /**
     * Sets the absolute Aquari issuer URL. Remote issuers must use HTTPS.
     */
    val issuer: String,
    /**
     * Sets the OAuth client identifier registered for this application.
     */
    val clientId: String,
    /**
     * Sets the exact OAuth redirect URI registered for this client.
     */
    val redirectUri: String,
    /**
     * Sets the OAuth scopes requested during authorization. Request offline_access when the application
     * needs refresh tokens.
     */
    val scopes: List<String>,
    /**
     * Sets the request timeout in milliseconds.
     */
    val timeoutMs: Long,
    /**
     * Sets the maximum number of transport retries after the first request attempt.
     */
    val maxRetries: Int,
    /**
     * Caps retry backoff in milliseconds.
     */
    val maxRetryDelayMs: Long,
    val httpExecutor: AquariHttpExecutor,
)

internal fun resolveOptions(options: AquariClientOptions): ResolvedAquariClientOptions {
    require(options.timeoutMs > 0) { "timeoutMs must be a positive integer." }
    require(options.maxRetries >= 0) { "maxRetries must be a non-negative integer." }
    require(options.maxRetryDelayMs >= 0) { "maxRetryDelayMs must be a non-negative integer." }

    /**
     * Sets the absolute Aquari issuer URL. Remote issuers must use HTTPS.
     */
    val issuer = normalizeBaseUrl(options.issuer)
    /**
     * Sets the OAuth client identifier registered for this application.
     */
    val clientId = validateTokenLikeValue(options.clientId, "clientId")
    /**
     * Sets the exact OAuth redirect URI registered for this client.
     */
    val redirectUri = validateRedirectUri(options.redirectUri)
    /**
     * Sets the OAuth scopes requested during authorization. Request offline_access when the application
     * needs refresh tokens.
     */
    val scopes = validateScopes(options.scopes)
    return ResolvedAquariClientOptions(
        issuer = issuer,
        clientId = clientId,
        redirectUri = redirectUri,
        scopes = scopes,
        timeoutMs = options.timeoutMs,
        maxRetries = options.maxRetries,
        maxRetryDelayMs = options.maxRetryDelayMs,
        httpExecutor = options.httpExecutor ?: OkHttpAquariExecutor(),
    )
}

/**
 * Validates and normalizes an Aquari base URL while preserving its origin and path identity.
 */
fun normalizeBaseUrl(value: String): String {
    val uri = try {
        URI(value)
    } catch (cause: Exception) {
        throw AquariConfigurationException("Aquari base URL must be a valid absolute URL.", cause)
    }

    if (!uri.isAbsolute || uri.scheme !in setOf("https", "http")) {
        throw AquariConfigurationException("Aquari base URL must use HTTPS or HTTP.")
    }
    if (uri.scheme == "http" && !isLocalDevelopmentHost(uri.host)) {
        throw AquariConfigurationException("Insecure HTTP Aquari URLs are allowed only for local development.")
    }
    if (uri.userInfo != null) {
        throw AquariConfigurationException("Aquari base URL must not contain credentials.")
    }
    if (uri.query != null || uri.fragment != null) {
        throw AquariConfigurationException("Aquari base URL must not contain a query string or fragment.")
    }

    val path = when {
        uri.path.isNullOrEmpty() -> "/"
        uri.path.endsWith("/") -> uri.path
        else -> "${uri.path}/"
    }

    return URI(uri.scheme, null, uri.host, uri.port, path, null, null).toString()
}

private fun validateRedirectUri(value: String): String {
    if (value.isEmpty() || value != value.trim()) {
        throw AquariConfigurationException("Aquari redirectUri must be a non-empty absolute URI.")
    }
    val uri = try {
        URI(value)
    } catch (cause: Exception) {
        throw AquariConfigurationException("Aquari redirectUri must be a valid absolute URI.", cause)
    }
    if (!uri.isAbsolute) throw AquariConfigurationException("Aquari redirectUri must be a valid absolute URI.")
    if (uri.userInfo != null) throw AquariConfigurationException("Aquari redirectUri must not contain credentials.")
    if (uri.fragment != null) throw AquariConfigurationException("Aquari redirectUri must not contain a fragment.")
    return value
}

private fun validateScopes(values: List<String>): List<String> {
    if (values.isEmpty()) throw AquariConfigurationException("Aquari scopes must contain at least one explicit scope.")
    val seen = linkedSetOf<String>()
    for (scope in values) {
        if (scope.isEmpty() || scope != scope.trim() || scope.any(Char::isWhitespace)) {
            throw AquariConfigurationException("Aquari scope values must be non-empty and must not contain whitespace.")
        }
        if (!seen.add(scope)) throw AquariConfigurationException("Aquari scope values must not contain duplicates.")
    }
    if ("openid" !in seen) throw AquariConfigurationException("Aquari authentication requires the explicit 'openid' scope.")
    return seen.toList()
}

internal fun validateTokenLikeValue(value: String, label: String): String {
    if (value.isEmpty() || value != value.trim() || value.any(Char::isWhitespace)) {
        throw AquariConfigurationException("Aquari $label must be a non-empty value without whitespace.")
    }
    return value
}

internal fun isLocalDevelopmentHost(host: String?): Boolean = when (host?.lowercase()) {
    "localhost", "127.0.0.1", "::1", "[::1]" -> true
    else -> false
}

/**
 * Provides standard OAuth scope values used by Aquari client applications.
 */
object AquariScopes {
    const val OpenId = "openid"
    const val Profile = "profile"
    const val Email = "email"
    const val OfflineAccess = "offline_access"
    const val PassportRead = "passport.read"
}
