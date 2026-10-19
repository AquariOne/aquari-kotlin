package one.aquari.sdk

/**
 * Contains the trust outcomes Aquari calculated for one subject and consumer application.
 */
data class AquariTrustEvaluation(
    val evaluationId: String,
    val subjectId: String,
    val consumerApplicationId: String,
    val evaluatedAt: String,
    val outcomes: List<AquariTrustOutcome>,
)

/**
 * Represents one trust outcome and the signals that support it.
 */
data class AquariTrustOutcome(
    val type: String,
    val value: String,
    val supports: List<AquariTrustSupport>,
)

/**
 * Explains which trusted mapping and signal support a trust outcome.
 */
data class AquariTrustSupport(
    val mappingId: String,
    val mappingVersion: Int,
    val trustedIssuerId: String,
    val signal: AquariTrustSignal,
)

/**
 * Describes the Passport signal that supported a trust outcome.
 */
data class AquariTrustSignal(
    val id: String,
    val signalFamily: String,
    val definitionId: String?,
    val authority: AquariTrustAuthority,
    val scope: AquariTrustScope?,
    val issuedAt: String,
    val expiresAt: String?,
)

/**
 * Identifies the authority attached to a trusted signal.
 */
data class AquariTrustAuthority(val type: String, val id: String)
/**
 * Identifies the resource scope attached to a trusted signal.
 */
data class AquariTrustScope(val type: String, val id: String)

/**
 * Evaluates the current application's configured trust mappings for an authenticated Aquari subject.
 */
class AquariTrustClient internal constructor(private val transport: AquariHttpTransport) {
    /**
     * Requests Aquari trust evaluation for the authenticated subject represented by the supplied access
     * token.
     */
    suspend fun evaluate(accessToken: String): AquariTrustEvaluation {
        if (accessToken.isEmpty() || accessToken != accessToken.trim()) throw IllegalArgumentException("Aquari accessToken must be a non-empty value without surrounding whitespace.")
        val root = transport.requestJson(
            "/api/v1/passport/trust/evaluation",
            headers = mapOf("authorization" to "Bearer $accessToken"),
        ).requireObject("trust evaluation")
        return AquariTrustEvaluation(
            evaluationId = root.requireString("evaluationId", "trust evaluation id"),
            subjectId = root.requireString("subjectId", "trust subject id"),
            consumerApplicationId = root.requireString("consumerApplicationId", "trust consumer application id"),
            evaluatedAt = root.requireIsoDate("evaluatedAt", "trust evaluatedAt"),
            outcomes = root.requireArray("outcomes", "trust evaluation outcomes").map { item ->
                val outcome = item.requireObject("trust outcome")
                AquariTrustOutcome(
                    type = outcome.requireString("type", "trust outcome type"),
                    value = outcome.requireString("value", "trust outcome value"),
                    supports = outcome.requireArray("supports", "trust outcome supports").map { supportElement ->
                        val support = supportElement.requireObject("trust support")
                        AquariTrustSupport(
                            mappingId = support.requireString("mappingId", "trust mapping id"),
                            mappingVersion = support.requireInt("mappingVersion", "trust mapping version"),
                            trustedIssuerId = support.requireString("trustedIssuerId", "trusted issuer id"),
                            signal = parseTrustSignal(support["signal"].requireObject("trust signal")),
                        )
                    },
                )
            },
        )
    }
}

private fun parseTrustSignal(record: kotlinx.serialization.json.JsonObject): AquariTrustSignal {
    val authority = record.requireObject("authority", "trust authority")
    val scope = record.optionalObject("scope", "trust signal scope")
    return AquariTrustSignal(
        id = record.requireString("id", "trust signal id"),
        signalFamily = record.requireString("signalFamily", "trust signal family"),
        definitionId = record.optionalString("definitionId", "trust signal definition id"),
        authority = AquariTrustAuthority(
            type = authority.requireString("type", "trust authority type"),
            id = authority.requireString("id", "trust authority id"),
        ),
        scope = scope?.let {
            AquariTrustScope(
                type = it.requireString("type", "trust scope type"),
                id = it.requireString("id", "trust scope id"),
            )
        },
        issuedAt = record.requireIsoDate("issuedAt", "trust signal issuedAt"),
        expiresAt = record.optionalIsoDate("expiresAt", "trust signal expiresAt"),
    )
}
