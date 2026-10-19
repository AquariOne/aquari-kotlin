package one.aquari.sdk

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import java.net.URLEncoder
import java.nio.charset.StandardCharsets

/**
 * Identifies the Aquari signal family represented by a Passport signal.
 */
enum class AquariPassportSignalFamily {
    Badge,
    Stamp,
    Credential,
    Entitlement,
    Role,
    Membership,
    Unknown,
}

/**
 * Contains the profile fields exposed by a connected Aquari Passport.
 */
data class AquariPassportProfile(
    val displayName: String,
    val handle: String,
    val avatarUrl: String?,
    val publicUrl: String,
    val verified: Boolean,
    val visibility: String,
)

/**
 * Contains the total number of signals reported for a connected Passport.
 */
data class AquariPassportSignalSummary(val total: Int)

/**
 * Represents the connected Passport returned for the authenticated Aquari subject.
 */
data class AquariPassport(
    val id: String,
    val passportNumber: String,
    val subjectId: String,
    val profile: AquariPassportProfile,
    val signals: AquariPassportSignalSummary,
)

/**
 * Identifies the issuer that produced a Passport signal.
 */
data class AquariPassportSignalIssuer(
    val type: String,
    val id: String,
    val name: String,
    val logoUrl: String?,
)

/**
 * Identifies the resource scope attached to a Passport signal.
 */
data class AquariPassportSignalScope(val type: String, val id: String)

/**
 * Represents one portable signal on an Aquari Passport.
 */
data class AquariPassportSignal(
    val id: String,
    val subjectId: String,
    val family: AquariPassportSignalFamily,
    val sourceType: String,
    val definitionId: String?,
    val presentationType: String,
    val name: String,
    val description: String,
    val imageUrl: String?,
    val issuer: AquariPassportSignalIssuer,
    val issuedAt: String,
    val expiresAt: String?,
    val visibility: String,
    val verified: Boolean,
    val occurredAt: String?,
    val scope: AquariPassportSignalScope?,
)

/**
 * Contains one page of Passport signals and cursor pagination state.
 */
data class AquariPassportSignalPage(
    val items: List<AquariPassportSignal>,
    val nextCursor: String?,
    val hasMore: Boolean,
)

/**
 * Represents one signal that is visible on a public Aquari Passport.
 */
data class AquariPublicPassportSignal(
    val id: String,
    val type: String,
    val name: String,
    val description: String,
    val imageUrl: String?,
    val issuer: String,
    val issuerLogoUrl: String?,
    val issuedAt: String,
    val expiresAt: String?,
    val verified: Boolean,
    val occurredAt: String?,
    val scope: AquariPassportSignalScope?,
)

/**
 * Represents public Passport data that can be read by handle without an authenticated session.
 */
data class AquariPublicPassport(
    val displayName: String,
    val handle: String,
    val avatarUrl: String?,
    val publicUrl: String,
    val verified: Boolean,
    val signals: List<AquariPublicPassportSignal>,
)

/**
 * Configures Passport signal filtering and cursor pagination.
 */
data class AquariPassportSignalQuery(
    val type: String? = null,
    val issuerId: String? = null,
    val definitionId: String? = null,
    val limit: Int? = null,
    val cursor: String? = null,
)

/**
 * Lists and reads signals on the authenticated subject's Passport.
 */
class AquariPassportSignalsClient internal constructor(private val transport: AquariHttpTransport) {
    /**
     * Reads one page of Passport signals using the supplied filters and cursor.
     */
    suspend fun list(accessToken: String, query: AquariPassportSignalQuery = AquariPassportSignalQuery()): AquariPassportSignalPage {
        val params = mutableListOf<Pair<String, String>>()
        query.type?.let { params += "type" to validateFilter(it, "type") }
        query.issuerId?.let { params += "issuer_id" to validateFilter(it, "issuerId") }
        query.definitionId?.let { params += "definition_id" to validateFilter(it, "definitionId") }
        query.limit?.let {
            if (it !in 1..100) throw IllegalArgumentException("Aquari Passport signal limit must be an integer from 1 through 100.")
            params += "limit" to it.toString()
        }
        query.cursor?.let { params += "cursor" to validateFilter(it, "cursor") }

        val suffix = if (params.isEmpty()) "" else "?" + params.joinToString("&") { (key, value) -> "${encode(key)}=${encode(value)}" }
        val root = transport.requestJson(
            "/api/v1/passport/signals$suffix",
            headers = bearerHeaders(accessToken),
        ).requireObject("Passport signal page")

        val items = root.requireArray("items", "Passport signal page items").map(::parseSignal)
        val page = root.requireObject("page", "Passport page metadata")
        return AquariPassportSignalPage(
            items = items,
            nextCursor = page.optionalString("nextCursor", "Passport next cursor"),
            hasMore = page.requireBoolean("hasMore", "Passport hasMore value"),
        )
    }

    /**
     * Reads one Passport signal by identifier for the authenticated subject.
     */
    suspend fun get(signalId: String, accessToken: String): AquariPassportSignal {
        val id = validateFilter(signalId, "signalId")
        val root = transport.requestJson(
            "/api/v1/passport/signals/${encode(id)}",
            headers = bearerHeaders(accessToken),
        ).requireObject("Passport signal response")
        return parseSignal(root["signal"])
    }

    /**
     * Streams Passport signals across cursor pages until Aquari reports that no additional page is
     * available.
     */
    fun iterate(accessToken: String, query: AquariPassportSignalQuery = AquariPassportSignalQuery()): Flow<AquariPassportSignal> = flow {
        var cursor = query.cursor
        while (true) {
            val page = list(accessToken, query.copy(cursor = cursor))
            page.items.forEach { emit(it) }
            if (!page.hasMore || page.nextCursor == null) return@flow
            cursor = page.nextCursor
        }
    }
}

/**
 * Reads connected and public Passport data.
 */
class AquariPassportClient internal constructor(private val transport: AquariHttpTransport) {
    /**
     * Gets Passport signal read operations.
     */
    val signals = AquariPassportSignalsClient(transport)

    /**
     * Reads the connected Passport for the authenticated subject represented by the supplied access token.
     */
    suspend fun get(accessToken: String): AquariPassport {
        val root = transport.requestJson(
            "/api/v1/passport",
            headers = bearerHeaders(accessToken),
        ).requireObject("Passport response")
        return parsePassport(root["passport"])
    }

    /**
     * Reads public Passport data for the supplied Aquari handle without using a bearer access token.
     */
    suspend fun getPublic(handle: String): AquariPublicPassport {
        val value = validateFilter(handle, "handle")
        return parsePublicPassport(
            transport.requestJson("/api/v1/public/passports/${encode(value)}"),
        )
    }
}

private fun parsePassport(value: Any?): AquariPassport {
    val record = (value as? kotlinx.serialization.json.JsonElement).requireObject("Passport object")
    val profile = record.requireObject("profile", "Passport profile")
    /**
     * Gets Passport signal read operations.
     */
    val signals = record.requireObject("signals", "Passport signal summary")
    return AquariPassport(
        id = record.requireString("id", "Passport id"),
        passportNumber = record.requireString("passportNumber", "Passport number"),
        subjectId = record.requireString("subjectId", "Passport subject id"),
        profile = AquariPassportProfile(
            displayName = profile.requireStringAllowEmpty("displayName", "Passport display name"),
            handle = profile.requireString("handle", "Passport handle"),
            avatarUrl = profile.optionalString("avatarUrl", "Passport avatar URL"),
            publicUrl = profile.requireString("publicUrl", "Passport public URL"),
            verified = profile.requireBoolean("verified", "Passport verified value"),
            visibility = profile.requireString("visibility", "Passport visibility"),
        ),
        signals = AquariPassportSignalSummary(signals.requireInt("total", "Passport signal total")),
    )
}

private fun parseSignal(value: kotlinx.serialization.json.JsonElement?): AquariPassportSignal {
    val record = value.requireObject("Passport signal")
    val issuer = record.requireObject("issuer", "Passport signal issuer")
    val scope = record.optionalObject("scope", "Passport signal scope")
    val sourceType = record.requireString("sourceType", "Passport signal sourceType")
    val presentationType = record.requireString("type", "Passport signal type")
    return AquariPassportSignal(
        id = record.requireString("id", "Passport signal id"),
        subjectId = record.requireString("subjectId", "Passport signal subject id"),
        family = resolveSignalFamily(sourceType, presentationType),
        sourceType = sourceType,
        definitionId = record.optionalString("definitionId", "Passport signal definition id"),
        presentationType = presentationType,
        name = record.requireString("name", "Passport signal name"),
        description = record.requireStringAllowEmpty("description", "Passport signal description"),
        imageUrl = record.optionalString("imageUrl", "Passport signal image URL"),
        issuer = AquariPassportSignalIssuer(
            type = issuer.requireString("type", "Passport issuer type"),
            id = issuer.requireString("id", "Passport issuer id"),
            name = issuer.requireString("name", "Passport issuer name"),
            logoUrl = issuer.optionalString("logoUrl", "Passport issuer logo URL"),
        ),
        issuedAt = record.requireIsoDate("issuedAt", "Passport signal issuedAt"),
        expiresAt = record.optionalIsoDate("expiresAt", "Passport signal expiresAt"),
        visibility = record.requireString("visibility", "Passport signal visibility"),
        verified = record.requireBoolean("verified", "Passport signal verified value"),
        occurredAt = record.optionalIsoDate("occurredAt", "Passport signal occurredAt"),
        scope = scope?.let {
            AquariPassportSignalScope(
                type = it.requireString("type", "Passport signal scope type"),
                id = it.requireString("id", "Passport signal scope id"),
            )
        },
    )
}

private fun parsePublicPassport(value: kotlinx.serialization.json.JsonElement): AquariPublicPassport {
    val record = value.requireObject("public Passport response")
    return AquariPublicPassport(
        displayName = record.requireStringAllowEmpty("displayName", "public Passport display name"),
        handle = record.requireString("handle", "public Passport handle"),
        avatarUrl = record.optionalString("avatarUrl", "public Passport avatar URL"),
        publicUrl = record.requireString("publicUrl", "public Passport URL"),
        verified = record.requireBoolean("verified", "public Passport verified value"),
        signals = record.requireArray("signals", "public Passport signals").map { item ->
            val signal = item.requireObject("public Passport signal")
            val scope = signal.optionalObject("scope", "public Passport signal scope")
            AquariPublicPassportSignal(
                id = signal.requireString("id", "public Passport signal id"),
                type = signal.requireString("type", "public Passport signal type"),
                name = signal.requireString("name", "public Passport signal name"),
                description = signal.requireStringAllowEmpty("description", "public Passport signal description"),
                imageUrl = signal.optionalString("imageUrl", "public Passport signal image URL"),
                issuer = signal.requireString("issuer", "public Passport signal issuer"),
                issuerLogoUrl = signal.optionalString("issuerLogoUrl", "public Passport signal issuer logo URL"),
                issuedAt = signal.requireIsoDate("issuedAt", "public Passport signal issuedAt"),
                expiresAt = signal.optionalIsoDate("expiresAt", "public Passport signal expiresAt"),
                verified = signal.requireBoolean("verified", "public Passport signal verified value"),
                occurredAt = signal.optionalIsoDate("occurredAt", "public Passport signal occurredAt"),
                scope = scope?.let { AquariPassportSignalScope(it.requireString("type", "public Passport signal scope type"), it.requireString("id", "public Passport signal scope id")) },
            )
        },
    )
}

private fun resolveSignalFamily(sourceType: String, presentationType: String): AquariPassportSignalFamily = when {
    sourceType == "badge" && presentationType == "badge" -> AquariPassportSignalFamily.Badge
    sourceType == "passport_stamp" && presentationType == "stamp" -> AquariPassportSignalFamily.Stamp
    sourceType == "credential" && presentationType == "credential" -> AquariPassportSignalFamily.Credential
    sourceType == "user_entitlement" && presentationType == "credential" -> AquariPassportSignalFamily.Entitlement
    sourceType == "app_membership" && presentationType == "role" -> AquariPassportSignalFamily.Role
    sourceType == "app_membership" && presentationType == "membership" -> AquariPassportSignalFamily.Membership
    else -> AquariPassportSignalFamily.Unknown
}

private fun bearerHeaders(accessToken: String): Map<String, String> {
    if (accessToken.isEmpty() || accessToken != accessToken.trim()) throw IllegalArgumentException("Aquari accessToken must be a non-empty value without surrounding whitespace.")
    return mapOf("authorization" to "Bearer $accessToken")
}

private fun validateFilter(value: String, label: String): String {
    if (value.isEmpty() || value != value.trim()) throw IllegalArgumentException("Aquari $label must be a non-empty value without surrounding whitespace.")
    return value
}

private fun encode(value: String): String = URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20")

internal fun kotlinx.serialization.json.JsonElement?.requireObject(label: String): JsonObject =
    this as? JsonObject ?: throw AquariTransportException("Aquari $label is malformed.")

internal fun JsonObject.requireObject(name: String, label: String): JsonObject = this[name].requireObject(label)
internal fun JsonObject.optionalObject(name: String, label: String): JsonObject? = this[name]?.let { if (it is kotlinx.serialization.json.JsonNull) null else it.requireObject(label) }
internal fun JsonObject.requireArray(name: String, label: String): JsonArray = this[name] as? JsonArray ?: throw AquariTransportException("Aquari $label is malformed.")

internal fun JsonObject.requireString(name: String, label: String): String {
    val value = (this[name] as? JsonPrimitive)?.takeIf { it.isString }?.contentOrNull
    if (value.isNullOrEmpty()) throw AquariTransportException("Aquari $label is malformed.")
    return value
}

internal fun JsonObject.requireStringAllowEmpty(name: String, label: String): String =
    (this[name] as? JsonPrimitive)?.takeIf { it.isString }?.contentOrNull ?: throw AquariTransportException("Aquari $label is malformed.")

internal fun JsonObject.optionalString(name: String, label: String): String? {
    val element = this[name] ?: return null
    if (element is kotlinx.serialization.json.JsonNull) return null
    return (element as? JsonPrimitive)?.takeIf { it.isString }?.contentOrNull ?: throw AquariTransportException("Aquari $label is malformed.")
}

internal fun JsonObject.requireBoolean(name: String, label: String): Boolean =
    (this[name] as? JsonPrimitive)?.booleanOrNull ?: throw AquariTransportException("Aquari $label is malformed.")

internal fun JsonObject.requireInt(name: String, label: String): Int =
    (this[name] as? JsonPrimitive)?.intOrNull ?: throw AquariTransportException("Aquari $label is malformed.")

internal fun JsonObject.requireIsoDate(name: String, label: String): String {
    val value = requireString(name, label)
    try { java.time.Instant.parse(value) } catch (cause: Exception) { throw AquariTransportException("Aquari $label is malformed.", cause) }
    return value
}

internal fun JsonObject.optionalIsoDate(name: String, label: String): String? = optionalString(name, label)?.also { value ->
    try { java.time.Instant.parse(value) } catch (cause: Exception) { throw AquariTransportException("Aquari $label is malformed.", cause) }
}
