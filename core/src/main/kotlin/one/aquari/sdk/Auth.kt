package one.aquari.sdk

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jwt.SignedJWT
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.longOrNull
import java.net.URI
import java.net.URLDecoder
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.time.Instant
import java.util.Date

private const val AUTH_TRANSACTION_MAX_AGE_MS = 15L * 60L * 1000L
private const val AUTH_TRANSACTION_CLOCK_SKEW_MS = 60L * 1000L
private const val ID_TOKEN_CLOCK_TOLERANCE_SECONDS = 60L
private val transactionStatePattern = Regex("^[A-Za-z0-9_-]{43}$")
private val transactionVerifierPattern = Regex("^[A-Za-z0-9_-]{64}$")
private const val CANONICAL_HANDLE_CLAIM = "https://aquari.one/claims/canonical_handle"
private const val VERIFIED_HANDLE_CLAIM = "https://aquari.one/claims/verified_handle"

/**
 * Lists the supported prompt values for an Aquari authorization request.
 */
enum class AquariAuthorizationPrompt(val wireValue: String) {
    Consent("consent"),
    Login("login"),
    None("none"),
    SelectAccount("select_account"),
}

@Serializable
/**
 * Stores the authorization transaction that binds an OAuth callback to the request that started it.
 * Preserve this value until authorization completes. Treat the PKCE verifier, state, and nonce as
 * sensitive.
 */
class AquariAuthorizationTransaction(
    val version: Int,
    val issuer: String,
    val clientId: String,
    val redirectUri: String,
    val scopes: List<String>,
    /**
     * Gets the PKCE verifier. Treat this value as sensitive and preserve it only until callback
     * completion.
     */
    val codeVerifier: String,
    /**
     * Gets the OAuth state value used to bind the callback to this transaction. Treat it as sensitive.
     */
    val state: String,
    /**
     * Gets the OpenID Connect nonce used to validate the returned ID token. Treat it as sensitive.
     */
    val nonce: String,
    /**
     * Gets the transaction creation time used to reject stale authorization state.
     */
    val createdAt: Long,
) {
    /**
     * Returns a diagnostic representation that does not expose protected token or authorization secret
     * values.
     */
    override fun toString(): String =
        "AquariAuthorizationTransaction(version=$version, issuer=$issuer, clientId=$clientId, redirectUri=$redirectUri, scopes=$scopes, secrets=[REDACTED], createdAt=$createdAt)"
}

/**
 * Contains the authorization URL and transaction created when an Aquari authorization request starts.
 */
data class AquariBeginAuthorizationResult(
    val url: String,
    val transaction: AquariAuthorizationTransaction,
)

/**
 * Represents the subject-bound identity returned by Aquari UserInfo.
 */
class AquariIdentity(
    val subject: String,
    val handle: String? = null,
    val canonicalHandle: String? = null,
    val verifiedHandle: String? = null,
    val name: String? = null,
    val pictureUrl: String? = null,
    val email: String? = null,
    val emailVerified: Boolean? = null,
) {
    /**
     * Returns a diagnostic representation that does not expose protected token or authorization secret
     * values.
     */
    override fun toString(): String =
        "AquariIdentity(subject=$subject, handle=$handle, canonicalHandle=$canonicalHandle, verifiedHandle=$verifiedHandle, name=$name, pictureUrl=$pictureUrl, email=$email, emailVerified=$emailVerified)"
}

@Serializable
/**
 * Contains the OAuth tokens, subject, scopes, and expiration metadata for an Aquari session. Do not
 * log or expose token values.
 */
class AquariTokenSet(
    /**
     * Gets the stable Aquari subject identifier bound to this token set.
     */
    val subject: String,
    val tokenType: String,
    /**
     * Gets the bearer access token. Do not log or expose this value.
     */
    val accessToken: String,
    /**
     * Gets the validated OpenID Connect ID token. Do not log or expose this value.
     */
    val idToken: String,
    /**
     * Gets the current refresh token when one is available. Aquari can rotate this value; always persist
     * the replacement token set.
     */
    val refreshToken: String? = null,
    val expiresIn: Long,
    /**
     * Gets the time when the access token expires.
     */
    val expiresAt: Long,
    val scopes: List<String>,
) {
    /**
     * Returns a diagnostic representation that does not expose protected token or authorization secret
     * values.
     */
    override fun toString(): String =
        "AquariTokenSet(subject=$subject, tokenType=$tokenType, tokens=[REDACTED], expiresIn=$expiresIn, expiresAt=$expiresAt, scopes=$scopes)"
}

/**
 * Contains the validated token set and subject-bound Aquari identity produced by authorization.
 */
data class AquariAuthorizationResult(
    val tokens: AquariTokenSet,
    val identity: AquariIdentity,
)

/**
 * Serializes the Aquari state to a protected-storage representation.
 */
fun serializeAuthorizationTransaction(transaction: AquariAuthorizationTransaction): String =
    kotlinx.serialization.json.Json.encodeToString(transaction)

/**
 * Restores Aquari state from protected storage and rejects malformed data.
 */
fun deserializeAuthorizationTransaction(value: String): AquariAuthorizationTransaction = try {
    kotlinx.serialization.json.Json.decodeFromString(value)
} catch (cause: Exception) {
    throw AquariOAuthException("invalid_transaction", "Aquari authorization transaction is invalid.", cause = cause)
}

/**
 * Serializes the Aquari state to a protected-storage representation.
 */
fun serializeTokenSet(tokens: AquariTokenSet): String = kotlinx.serialization.json.Json.encodeToString(tokens)

/**
 * Restores Aquari state from protected storage and rejects malformed data.
 */
fun deserializeTokenSet(value: String): AquariTokenSet = try {
    kotlinx.serialization.json.Json.decodeFromString(value)
} catch (cause: Exception) {
    throw AquariOAuthException("invalid_token_set", "Aquari token set is invalid.", cause = cause)
}

/**
 * Provides OIDC discovery, Authorization Code with S256 PKCE, refresh-token rotation, and UserInfo
 * operations.
 */
class AquariAuthClient internal constructor(
    private val options: ResolvedAquariClientOptions,
    private val transport: AquariHttpTransport,
) {
    @Volatile
    private var cachedDiscovery: AquariOidcDiscovery? = null

    /**
     * Loads and validates Aquari OpenID Connect discovery metadata. The client reuses cached metadata
     * unless the caller requests a refresh.
     */
    suspend fun discover(forceRefresh: Boolean = false): AquariOidcDiscovery {
        if (!forceRefresh) cachedDiscovery?.let { return it }
        val discovery = discoverAquariOidc(transport, options.issuer)
        cachedDiscovery = discovery
        return discovery
    }

    /**
     * Starts an Authorization Code request. The SDK creates S256 PKCE, state, nonce, and a serializable
     * authorization transaction, then returns the system-browser URL. Preserve the transaction until
     * authorization completes.
     */
    suspend fun begin(prompt: AquariAuthorizationPrompt? = null): AquariBeginAuthorizationResult {
        val discovery = discover()
        val pkce = createPkcePair()
        val transaction = AquariAuthorizationTransaction(
            version = 1,
            issuer = options.issuer,
            clientId = options.clientId,
            redirectUri = options.redirectUri,
            scopes = options.scopes,
            codeVerifier = pkce.codeVerifier,
            state = createSecureRandomValue(),
            nonce = createSecureRandomValue(),
            createdAt = System.currentTimeMillis(),
        )

        val parameters = linkedMapOf(
            "client_id" to transaction.clientId,
            "redirect_uri" to transaction.redirectUri,
            "response_type" to "code",
            "scope" to transaction.scopes.joinToString(" "),
            "state" to transaction.state,
            "nonce" to transaction.nonce,
            "code_challenge" to pkce.codeChallenge,
            "code_challenge_method" to "S256",
        )
        prompt?.let { parameters["prompt"] = it.wireValue }

        return AquariBeginAuthorizationResult(
            url = appendQuery(discovery.authorizationEndpoint, parameters),
            transaction = transaction,
        )
    }

    /**
     * Validates the authorization callback against the original transaction, exchanges the authorization
     * code, validates the ID token and nonce, and returns subject-bound session state.
     */
    suspend fun complete(callbackUrl: String, transaction: AquariAuthorizationTransaction): AquariAuthorizationResult {
        validateTransaction(transaction)
        val callback = parseCallback(callbackUrl, transaction.redirectUri)
        val parameters = parseQuery(callback.rawQuery)

        val state = singleCallbackValue(parameters, "state", required = true)
        if (state != transaction.state) {
            throw AquariOAuthException("state_mismatch", "Aquari authorization callback state does not match the initiating transaction.")
        }

        val callbackIssuer = singleCallbackValue(parameters, "iss", required = false)
        if (callbackIssuer != null && callbackIssuer != transaction.issuer) {
            throw AquariOAuthException("issuer_mismatch", "Aquari authorization callback issuer does not match the initiating transaction.")
        }

        val oauthError = singleCallbackValue(parameters, "error", required = false)
        val code = singleCallbackValue(parameters, "code", required = false)
        if (oauthError != null && code != null) {
            throw AquariOAuthException("invalid_callback", "Aquari authorization callback cannot contain both a code and an OAuth error.")
        }
        if (oauthError != null) {
            val description = singleCallbackValue(parameters, "error_description", required = false)
            val errorUri = singleCallbackValue(parameters, "error_uri", required = false)
            throw AquariOAuthException(
                oauthCode = oauthError,
                message = description ?: "Aquari returned OAuth error '$oauthError'.",
                errorDescription = description,
                errorUri = errorUri,
            )
        }
        if (code == null) {
            throw AquariOAuthException("invalid_callback", "Aquari authorization callback does not contain an authorization code.")
        }

        val discovery = discover()
        if (discovery.authorizationResponseIssuerParameterSupported && callbackIssuer == null) {
            throw AquariOAuthException("missing_issuer", "Aquari authorization callback is missing the advertised issuer parameter.")
        }

        val body = linkedMapOf(
            "grant_type" to "authorization_code",
            "client_id" to transaction.clientId,
            "redirect_uri" to transaction.redirectUri,
            "code" to code,
            "code_verifier" to transaction.codeVerifier,
        )
        val response = transport.requestAbsoluteJson(
            url = discovery.tokenEndpoint,
            method = "POST",
            headers = mapOf("accept" to "application/json"),
            body = encodeForm(body),
            contentType = "application/x-www-form-urlencoded",
            retryMode = AquariRetryMode.Never,
        ) as? JsonObject ?: throw AquariOAuthException("invalid_token_response", "Aquari returned an invalid token response.")

        val unbound = parseAuthorizationTokenResponse(response, transaction.scopes)
        val identity = validateIdToken(unbound.idToken, discovery, transaction.clientId, transaction.nonce)
        return AquariAuthorizationResult(
            tokens = AquariTokenSet(
                subject = identity.subject,
                tokenType = unbound.tokenType,
                accessToken = unbound.accessToken,
                idToken = unbound.idToken,
                refreshToken = unbound.refreshToken,
                expiresIn = unbound.expiresIn,
                expiresAt = unbound.expiresAt,
                scopes = unbound.scopes,
            ),
            identity = identity,
        )
    }

    /**
     * Exchanges the current refresh token for a replacement token set. Treat the returned token set as the
     * new session state because Aquari rotates refresh tokens.
     */
    suspend fun refresh(tokens: AquariTokenSet): AquariTokenSet {
        validateTokenSet(tokens)
        val refreshToken = tokens.refreshToken
            ?: throw AquariOAuthException("missing_refresh_token", "Aquari cannot refresh this token set because it does not contain a refresh token.")
        val discovery = discover()

        val body = linkedMapOf(
            "grant_type" to "refresh_token",
            "client_id" to options.clientId,
            "refresh_token" to refreshToken,
        )
        val response = transport.requestAbsoluteJson(
            url = discovery.tokenEndpoint,
            method = "POST",
            headers = mapOf("accept" to "application/json"),
            body = encodeForm(body),
            contentType = "application/x-www-form-urlencoded",
            retryMode = AquariRetryMode.Never,
        ) as? JsonObject ?: throw AquariOAuthException("invalid_token_response", "Aquari returned an invalid refresh response.")

        val refreshed = parseRefreshTokenResponse(response, tokens)
        if (refreshed.idToken != tokens.idToken) {
            val identity = validateIdToken(refreshed.idToken, discovery, options.clientId, expectedNonce = null)
            if (identity.subject != tokens.subject) {
                throw invalidIdToken("Aquari refreshed ID token subject does not match the existing token set.")
            }
        }
        return refreshed
    }

    /**
     * Reads Aquari UserInfo with the current access token and returns the subject-bound identity.
     */
    suspend fun userInfo(tokens: AquariTokenSet): AquariIdentity {
        validateTokenSet(tokens)
        val discovery = discover()
        val response = transport.requestAbsoluteJson(
            url = discovery.userInfoEndpoint,
            method = "GET",
            headers = mapOf(
                "accept" to "application/json",
                "authorization" to "Bearer ${tokens.accessToken}",
            ),
            retryMode = AquariRetryMode.Never,
        ) as? JsonObject ?: throw AquariOAuthException("invalid_userinfo_response", "Aquari returned an invalid UserInfo response.")
        val identity = parseIdentity(response, "UserInfo", errorCode = "invalid_userinfo_response")
        if (identity.subject != tokens.subject) {
            throw AquariOAuthException("userinfo_subject_mismatch", "Aquari UserInfo subject does not match the authenticated token set.")
        }
        return identity
    }

    private fun validateTransaction(transaction: AquariAuthorizationTransaction) {
        val now = System.currentTimeMillis()
        val structurallyValid =
            transaction.version == 1 &&
                transaction.issuer == options.issuer &&
                transaction.clientId == options.clientId &&
                transaction.redirectUri == options.redirectUri &&
                transaction.scopes == options.scopes &&
                transactionVerifierPattern.matches(transaction.codeVerifier) &&
                transactionStatePattern.matches(transaction.state) &&
                transactionStatePattern.matches(transaction.nonce)
        if (!structurallyValid) {
            throw AquariOAuthException("invalid_transaction", "Aquari authorization transaction is invalid or does not match this client configuration.")
        }
        if (transaction.createdAt > now + AUTH_TRANSACTION_CLOCK_SKEW_MS || now - transaction.createdAt > AUTH_TRANSACTION_MAX_AGE_MS) {
            throw AquariOAuthException("expired_transaction", "Aquari authorization transaction is expired or has an invalid timestamp.")
        }
    }

    private suspend fun validateIdToken(
        idToken: String,
        discovery: AquariOidcDiscovery,
        clientId: String,
        expectedNonce: String?,
    ): AquariIdentity {
        val jwt = try {
            SignedJWT.parse(idToken)
        } catch (cause: Exception) {
            throw invalidIdToken(cause = cause)
        }
        if (jwt.header.algorithm != JWSAlgorithm.RS256) throw invalidIdToken()

        val jwksRaw = transport.requestAbsoluteJson(discovery.jwksUri, retryMode = AquariRetryMode.Never)
        val jwkSet = try {
            JWKSet.parse(jwksRaw.toString())
        } catch (cause: Exception) {
            throw invalidIdToken(cause = cause)
        }
        val kid = jwt.header.keyID
        val candidates = jwkSet.keys
            .filterIsInstance<RSAKey>()
            .filter { kid == null || it.keyID == kid }
            .filter { it.algorithm == null || it.algorithm == JWSAlgorithm.RS256 }
            .filter { it.keyUse == null || it.keyUse == KeyUse.SIGNATURE }
        if (candidates.size != 1) throw invalidIdToken()
        if (!jwt.verify(RSASSAVerifier(candidates.single().toRSAPublicKey()))) throw invalidIdToken()

        val claims = try {
            jwt.jwtClaimsSet
        } catch (cause: Exception) {
            throw invalidIdToken(cause = cause)
        }
        if (claims.issuer != discovery.issuer) throw invalidIdToken()
        val audience = claims.audience ?: emptyList()
        if (clientId !in audience) throw invalidIdToken()
        val expiration = claims.expirationTime ?: throw invalidIdToken("Aquari ID token is missing an expiration claim.")
        val issuedAt = claims.issueTime ?: throw invalidIdToken("Aquari ID token is missing an issued-at claim.")
        val now = Instant.now()
        if (expiration.toInstant().isBefore(now.minusSeconds(ID_TOKEN_CLOCK_TOLERANCE_SECONDS))) throw invalidIdToken()
        if (issuedAt.toInstant().isAfter(now.plusSeconds(ID_TOKEN_CLOCK_TOLERANCE_SECONDS))) {
            throw invalidIdToken("Aquari ID token has an issued-at time too far in the future.")
        }
        val subject = claims.subject?.takeIf { it.isNotEmpty() }
            ?: throw invalidIdToken("Aquari ID token is missing a valid subject claim.")
        if (expectedNonce != null) {
            val nonce = safeStringClaim(claims.claims, "nonce")
            if (nonce != expectedNonce) throw invalidIdToken("Aquari ID token nonce does not match the authorization transaction.")
        }
        if (audience.size > 1 && safeStringClaim(claims.claims, "azp") != clientId) {
            throw invalidIdToken("Aquari ID token with multiple audiences must identify this client as the authorized party.")
        }
        return parseIdentity(JsonObject(claims.claims.mapValues { (_, value) -> toJsonPrimitive(value) }), "ID token", knownSubject = subject)
    }
}

private data class UnboundTokenSet(
    val tokenType: String,
    val accessToken: String,
    val idToken: String,
    val refreshToken: String?,
    val expiresIn: Long,
    val expiresAt: Long,
    val scopes: List<String>,
)

private fun parseAuthorizationTokenResponse(value: JsonObject, requestedScopes: List<String>): UnboundTokenSet {
    val tokenType = requireBearer(value)
    val access = value.requiredTokenString("access_token")
    val id = value.requiredTokenString("id_token")
    val refresh = value.optionalTokenString("refresh_token")
    val expiresIn = value.requiredPositiveLong("expires_in")
    val scopes = parseScope(value.optionalScopeString(), requestedScopes)
    return UnboundTokenSet(tokenType, access, id, refresh, expiresIn, System.currentTimeMillis() + expiresIn * 1000L, scopes)
}

private fun parseRefreshTokenResponse(value: JsonObject, current: AquariTokenSet): AquariTokenSet {
    val tokenType = requireBearer(value)
    val access = value.requiredTokenString("access_token")
    val id = value.optionalTokenString("id_token") ?: current.idToken
    val refresh = value.optionalTokenString("refresh_token") ?: current.refreshToken
    val expiresIn = value.requiredPositiveLong("expires_in")
    val scopes = parseScope(value.optionalScopeString(), current.scopes)
    return AquariTokenSet(current.subject, tokenType, access, id, refresh, expiresIn, System.currentTimeMillis() + expiresIn * 1000L, scopes)
}

private fun validateTokenSet(tokens: AquariTokenSet) {
    if (tokens.subject.isEmpty() || tokens.tokenType != "Bearer" || tokens.accessToken.isEmpty() || tokens.idToken.isEmpty() || tokens.expiresIn <= 0 || tokens.expiresAt <= 0 || tokens.scopes.isEmpty()) {
        throw AquariOAuthException("invalid_token_set", "Aquari token set is invalid.")
    }
}

private fun requireBearer(value: JsonObject): String {
    val raw = value.requiredTokenString("token_type")
    if (!raw.equals("Bearer", ignoreCase = true)) throw AquariOAuthException("invalid_token_response", "Aquari token response did not use the Bearer token type.")
    return "Bearer"
}

private fun JsonObject.requiredTokenString(name: String): String =
    optionalTokenString(name) ?: throw AquariOAuthException("invalid_token_response", "Aquari returned an invalid token response.")

private fun JsonObject.optionalTokenString(name: String): String? {
    val element = this[name] ?: return null
    val value = (element as? JsonPrimitive)?.contentOrNull
    if (value.isNullOrEmpty()) throw AquariOAuthException("invalid_token_response", "Aquari returned an invalid token response.")
    return value
}

private fun JsonObject.requiredPositiveLong(name: String): Long {
    val primitive = this[name] as? JsonPrimitive ?: throw AquariOAuthException("invalid_token_response", "Aquari returned an invalid token response.")
    val value = primitive.longOrNull ?: primitive.intOrNull?.toLong()
    if (value == null || value <= 0) throw AquariOAuthException("invalid_token_response", "Aquari returned an invalid token response.")
    return value
}


private fun JsonObject.optionalScopeString(): String? {
    val element = this["scope"] ?: return null
    val primitive = element as? JsonPrimitive
    if (primitive == null || !primitive.isString) {
        throw AquariOAuthException("invalid_token_response", "Aquari returned an invalid scope value.")
    }
    return primitive.content
}

private fun parseScope(value: String?, fallback: List<String>): List<String> {
    if (value == null) return fallback
    val scopes = value.split(' ').filter(String::isNotEmpty)
    if (scopes.isEmpty() || scopes.any { it != it.trim() || it.any(Char::isWhitespace) } || scopes.toSet().size != scopes.size) {
        throw AquariOAuthException("invalid_token_response", "Aquari returned an invalid scope value.")
    }
    return scopes
}

private fun parseIdentity(
    value: JsonObject,
    label: String,
    knownSubject: String? = null,
    errorCode: String = "invalid_id_token",
): AquariIdentity {
    val subject = knownSubject ?: value.stringStrict("sub", required = true, label = label, errorCode = errorCode)!!
    return AquariIdentity(
        subject = subject,
        handle = value.stringStrict("preferred_username", false, label, errorCode),
        canonicalHandle = value.stringStrict(CANONICAL_HANDLE_CLAIM, false, label, errorCode),
        verifiedHandle = value.stringStrict(VERIFIED_HANDLE_CLAIM, false, label, errorCode),
        name = value.stringStrict("name", false, label, errorCode),
        pictureUrl = value.stringStrict("picture", false, label, errorCode),
        email = value.stringStrict("email", false, label, errorCode),
        emailVerified = value.booleanStrict("email_verified", label, errorCode),
    )
}

private fun JsonObject.stringStrict(name: String, required: Boolean, label: String, errorCode: String): String? {
    val element = this[name] ?: if (required) throw AquariOAuthException(errorCode, "Aquari $label is missing '$name'.") else return null
    val value = (element as? JsonPrimitive)?.takeIf { it.isString }?.contentOrNull
        ?: throw AquariOAuthException(errorCode, "Aquari $label claim '$name' is malformed.")
    if (required && value.isEmpty()) throw AquariOAuthException(errorCode, "Aquari $label claim '$name' is malformed.")
    return value
}

private fun JsonObject.booleanStrict(name: String, label: String, errorCode: String): Boolean? {
    val element = this[name] ?: return null
    val primitive = element as? JsonPrimitive ?: throw AquariOAuthException(errorCode, "Aquari $label claim '$name' is malformed.")
    return primitive.content.toBooleanStrictOrNull()
        ?: throw AquariOAuthException(errorCode, "Aquari $label claim '$name' is malformed.")
}

private fun safeStringClaim(claims: Map<String, Any>, name: String): String? {
    val value = claims[name] ?: return null
    return value as? String ?: throw invalidIdToken("Aquari ID token claim '$name' is malformed.")
}

private fun toJsonPrimitive(value: Any?): kotlinx.serialization.json.JsonElement = when (value) {
    null -> kotlinx.serialization.json.JsonNull
    is String -> JsonPrimitive(value)
    is Boolean -> JsonPrimitive(value)
    is Number -> JsonPrimitive(value)
    is Date -> JsonPrimitive(value.toInstant().epochSecond)
    else -> JsonPrimitive(value.toString())
}

private fun invalidIdToken(message: String = "Aquari returned an ID token that failed cryptographic or claims validation.", cause: Throwable? = null): AquariOAuthException =
    AquariOAuthException("invalid_id_token", message, cause = cause)

private fun appendQuery(url: String, parameters: Map<String, String>): String {
    val encoded = parameters.entries.joinToString("&") { (key, value) -> "${queryEncode(key)}=${queryEncode(value)}" }
    return url + if (url.contains('?')) "&$encoded" else "?$encoded"
}

private fun encodeForm(parameters: Map<String, String>): String =
    parameters.entries.joinToString("&") { (key, value) -> "${queryEncode(key)}=${queryEncode(value)}" }

private fun queryEncode(value: String): String = URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20")
private fun queryDecode(value: String): String = URLDecoder.decode(value, StandardCharsets.UTF_8)

private fun parseQuery(raw: String?): Map<String, List<String>> {
    if (raw.isNullOrEmpty()) return emptyMap()
    return raw.split('&').filter { it.isNotEmpty() }.map { part ->
        val index = part.indexOf('=')
        val key = queryDecode(if (index >= 0) part.substring(0, index) else part)
        val value = queryDecode(if (index >= 0) part.substring(index + 1) else "")
        key to value
    }.groupBy({ it.first }, { it.second })
}

private fun parseCallback(value: String, redirectUri: String): URI {
    val callback = try { URI(value) } catch (cause: Exception) {
        throw AquariOAuthException("invalid_callback", "Aquari authorization callback URL is invalid.", cause = cause)
    }
    val redirect = URI(redirectUri)
    val sameBase = callback.scheme == redirect.scheme &&
        callback.userInfo == redirect.userInfo &&
        callback.host == redirect.host &&
        callback.port == redirect.port &&
        callback.path == redirect.path &&
        callback.fragment == null
    if (!sameBase || !containsFixedQuery(callback, redirect)) {
        throw AquariOAuthException("invalid_callback", "Aquari authorization callback URL does not match the configured redirect URI.")
    }
    return callback
}

private fun containsFixedQuery(callback: URI, redirect: URI): Boolean {
    val callbackValues = parseQuery(callback.rawQuery)
    val expected = parseQuery(redirect.rawQuery)
    return expected.all { (key, values) ->
        val remaining = callbackValues[key]?.toMutableList() ?: mutableListOf()
        values.all { expectedValue ->
            val index = remaining.indexOf(expectedValue)
            if (index < 0) false else { remaining.removeAt(index); true }
        }
    }
}

private fun singleCallbackValue(parameters: Map<String, List<String>>, name: String, required: Boolean): String? {
    val values = parameters[name].orEmpty()
    if (values.size > 1) throw AquariOAuthException("invalid_callback", "Aquari authorization callback contains multiple '$name' parameters.")
    val value = values.firstOrNull()
    if (value.isNullOrEmpty()) {
        if (required) throw AquariOAuthException("invalid_callback", "Aquari authorization callback is missing '$name'.")
        return null
    }
    return value
}
