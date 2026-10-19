package one.aquari.sdk

import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64

internal data class PkcePair(val codeVerifier: String, val codeChallenge: String)

private val secureRandom = SecureRandom()
private val base64UrlEncoder = Base64.getUrlEncoder().withoutPadding()

internal fun createPkcePair(): PkcePair {
    val verifier = createSecureRandomValue(48)
    val digest = MessageDigest.getInstance("SHA-256").digest(verifier.toByteArray(Charsets.US_ASCII))
    return PkcePair(verifier, base64UrlEncoder.encodeToString(digest))
}

internal fun createSecureRandomValue(byteCount: Int = 32): String {
    require(byteCount > 0)
    val bytes = ByteArray(byteCount)
    secureRandom.nextBytes(bytes)
    return base64UrlEncoder.encodeToString(bytes)
}
