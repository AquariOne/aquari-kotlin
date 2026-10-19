package one.aquari.sdk

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import java.net.URI
import java.time.Instant
import java.util.Date

private const val ISSUER = "https://dev.api.aquari.one/"
private const val CLIENT_ID = "aqc_test_public"
private const val REDIRECT = "com.example.app:/oauth/callback"

class CoreTest {
    @Test
    fun `configuration normalizes issuer and requires openid`() {
        val client = AquariClient(
            AquariClientOptions(
                issuer = "https://dev.api.aquari.one",
                clientId = CLIENT_ID,
                redirectUri = REDIRECT,
                scopes = listOf("openid", "profile"),
                httpExecutor = fakeExecutor { error("network not expected") },
            ),
        )
        assertEquals(ISSUER, client.issuer)

        assertFailsWith<AquariConfigurationException> {
            AquariClient(
                AquariClientOptions(
                    issuer = ISSUER,
                    clientId = CLIENT_ID,
                    redirectUri = REDIRECT,
                    scopes = listOf("profile"),
                    httpExecutor = fakeExecutor { error("network not expected") },
                ),
            )
        }
    }

    @Test
    fun `pkce uses verifier challenge state shapes`() {
        val first = createPkcePair()
        val second = createPkcePair()
        assertTrue(Regex("^[A-Za-z0-9_-]{64}$").matches(first.codeVerifier))
        assertTrue(Regex("^[A-Za-z0-9_-]{43}$").matches(first.codeChallenge))
        assertNotEquals(first.codeVerifier, second.codeVerifier)
        assertTrue(Regex("^[A-Za-z0-9_-]{43}$").matches(createSecureRandomValue()))
    }

    @Test
    fun `discovery requires exact issuer and S256`() = runBlocking {
        val client = clientWithExecutor(fakeExecutor {
            jsonResponse(discoveryJson(codeChallengeMethods = listOf("plain")))
        })
        assertFailsWith<AquariConfigurationException> { client.auth.discover() }
    }

    @Test
    fun `begin authorization creates public PKCE transaction`() = runBlocking {
        val client = clientWithExecutor(fakeExecutor { jsonResponse(discoveryJson()) })
        val result = client.auth.begin(AquariAuthorizationPrompt.Login)
        val uri = URI(result.url)
        val query = uri.rawQuery
        assertTrue(query.contains("client_id=$CLIENT_ID"))
        assertTrue(query.contains("code_challenge_method=S256"))
        assertTrue(query.contains("prompt=login"))
        assertEquals(1, result.transaction.version)
        assertEquals(CLIENT_ID, result.transaction.clientId)
        assertTrue(result.transaction.toString().contains("REDACTED"))
    }

    @Test
    fun `callback state mismatch fails before token exchange`() = runBlocking {
        var calls = 0
        val client = clientWithExecutor(fakeExecutor {
            calls += 1
            jsonResponse(discoveryJson())
        })
        val result = client.auth.begin()
        val error = assertFailsWith<AquariOAuthException> {
            client.auth.complete("$REDIRECT?code=abc&state=wrong&iss=${encode(ISSUER)}", result.transaction)
        }
        assertEquals("state_mismatch", error.oauthCode)
        assertEquals(1, calls)
    }

    @Test
    fun `real signed id token completes public authorization and userinfo`() = runBlocking {
        val key = RSAKeyGenerator(2048).keyID("k1").generate()
        lateinit var transaction: AquariAuthorizationTransaction

        val executor = fakeExecutor { request ->
            when {
                request.url.endsWith("/.well-known/openid-configuration") -> jsonResponse(discoveryJson())
                request.url.endsWith("/connect/token") -> {
                    val idToken = signIdToken(key, transaction.nonce)
                    jsonResponse(
                        """{"token_type":"Bearer","access_token":"access-secret","id_token":"$idToken","refresh_token":"refresh-secret","expires_in":3600,"scope":"openid profile email offline_access passport.read"}""",
                    )
                }
                request.url.endsWith("/.well-known/jwks") -> jsonResponse(JWKSet(key.toPublicJWK()).toString())
                request.url.endsWith("/connect/userinfo") -> jsonResponse(
                    """{"sub":"subject-1","preferred_username":"@test.aquari.one","name":"Test User","email":"test@example.com","email_verified":true}""",
                )
                else -> error("unexpected request ${request.method} ${request.url}")
            }
        }

        val client = clientWithExecutor(executor)
        val begun = client.auth.begin()
        transaction = begun.transaction
        val result = client.auth.complete(
            "$REDIRECT?code=code-1&state=${transaction.state}&iss=${encode(ISSUER)}",
            transaction,
        )
        assertEquals("subject-1", result.identity.subject)
        assertEquals("Bearer", result.tokens.tokenType)
        assertTrue(result.tokens.toString().contains("REDACTED"))

        val userInfo = client.auth.userInfo(result.tokens)
        assertEquals("subject-1", userInfo.subject)
        assertEquals("test@example.com", userInfo.email)
    }

    @Test
    fun `passport and trust parse forward compatible runtime shapes`() = runBlocking {
        val executor = fakeExecutor { request ->
            when {
                request.url.endsWith("/api/v1/passport") -> jsonResponse(
                    """{"passport":{"id":"p1","passportNumber":"AQ-00000001","subjectId":"subject-1","profile":{"displayName":"Test","handle":"@test.aquari.one","publicUrl":"https://aquari.one/test","verified":true,"visibility":"public"},"signals":{"total":0}}}""",
                )
                request.url.endsWith("/api/v1/passport/signals") -> jsonResponse(
                    """{"items":[],"page":{"nextCursor":null,"hasMore":false}}""",
                )
                request.url.endsWith("/api/v1/passport/trust/evaluation") -> jsonResponse(
                    """{"evaluationId":"e1","subjectId":"subject-1","consumerApplicationId":"app1","evaluatedAt":"2026-09-27T12:00:00Z","outcomes":[]}""",
                )
                request.url.contains("/api/v1/public/passports/") -> jsonResponse(
                    """{"displayName":"Test","handle":"@test.aquari.one","publicUrl":"https://aquari.one/test","verified":true,"signals":[]}""",
                )
                else -> error("unexpected request ${request.url}")
            }
        }
        val client = clientWithExecutor(executor)
        assertEquals("AQ-00000001", client.passport.get("token").passportNumber)
        assertEquals(0, client.passport.signals.list("token").items.size)
        assertEquals("@test.aquari.one", client.passport.getPublic("@test.aquari.one").handle)
        assertEquals("e1", client.trust.evaluate("token").evaluationId)
    }
}

private fun clientWithExecutor(executor: AquariHttpExecutor): AquariClient = AquariClient(
    AquariClientOptions(
        issuer = ISSUER,
        clientId = CLIENT_ID,
        redirectUri = REDIRECT,
        scopes = listOf("openid", "profile", "email", "offline_access", "passport.read"),
        httpExecutor = executor,
        maxRetries = 0,
    ),
)

private fun fakeExecutor(block: suspend (AquariRawRequest) -> AquariRawResponse): AquariHttpExecutor =
    AquariHttpExecutor(block)

private fun jsonResponse(body: String, status: Int = 200): AquariRawResponse =
    AquariRawResponse(status, mapOf("content-type" to listOf("application/json")), body)

private fun discoveryJson(codeChallengeMethods: List<String> = listOf("S256")): String =
    """{
      "issuer":"$ISSUER",
      "authorization_endpoint":"${ISSUER}connect/authorize",
      "token_endpoint":"${ISSUER}connect/token",
      "userinfo_endpoint":"${ISSUER}connect/userinfo",
      "jwks_uri":"${ISSUER}.well-known/jwks",
      "grant_types_supported":["authorization_code","refresh_token"],
      "response_types_supported":["code"],
      "code_challenge_methods_supported":[${codeChallengeMethods.joinToString(",") { "\"$it\"" }}],
      "id_token_signing_alg_values_supported":["RS256"],
      "token_endpoint_auth_methods_supported":["none","client_secret_post"],
      "authorization_response_iss_parameter_supported":true
    }""".trimIndent()

private fun signIdToken(key: RSAKey, nonce: String): String {
    val now = Instant.now()
    val claims = JWTClaimsSet.Builder()
        .issuer(ISSUER)
        .audience(CLIENT_ID)
        .subject("subject-1")
        .issueTime(Date.from(now))
        .expirationTime(Date.from(now.plusSeconds(3600)))
        .claim("nonce", nonce)
        .claim("preferred_username", "@test.aquari.one")
        .build()
    val jwt = SignedJWT(JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.keyID).build(), claims)
    jwt.sign(RSASSASigner(key))
    return jwt.serialize()
}

private fun encode(value: String): String = java.net.URLEncoder.encode(value, java.nio.charset.StandardCharsets.UTF_8)
