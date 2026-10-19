package one.aquari.sdk

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import java.net.URI

/**
 * Contains validated OpenID Connect discovery metadata for the configured Aquari issuer.
 */
data class AquariOidcDiscovery(
    val issuer: String,
    val authorizationEndpoint: String,
    val tokenEndpoint: String,
    val userInfoEndpoint: String,
    val jwksUri: String,
    val grantTypesSupported: List<String>,
    val responseTypesSupported: List<String>,
    val codeChallengeMethodsSupported: List<String>,
    val idTokenSigningAlgorithmsSupported: List<String>,
    val tokenEndpointAuthMethodsSupported: List<String>,
    val authorizationResponseIssuerParameterSupported: Boolean,
)

internal suspend fun discoverAquariOidc(
    transport: AquariHttpTransport,
    configuredIssuer: String,
): AquariOidcDiscovery {
    val raw = transport.requestJson("/.well-known/openid-configuration") as? JsonObject
        ?: throw AquariConfigurationException("Aquari OIDC discovery returned an invalid document.")

    val issuer = raw.requiredString("issuer")
    if (issuer != configuredIssuer) {
        throw AquariConfigurationException("Aquari OIDC discovery issuer does not exactly match the configured issuer.")
    }

    val grants = raw.requiredStringList("grant_types_supported")
    val responses = raw.requiredStringList("response_types_supported")
    val pkce = raw.requiredStringList("code_challenge_methods_supported")
    val algorithms = raw.requiredStringList("id_token_signing_alg_values_supported")

    requireAdvertised(grants, "authorization_code", "Aquari OIDC discovery does not advertise the authorization-code grant.")
    requireAdvertised(grants, "refresh_token", "Aquari OIDC discovery does not advertise the refresh-token grant.")
    requireAdvertised(responses, "code", "Aquari OIDC discovery does not advertise the code response type.")
    requireAdvertised(pkce, "S256", "Aquari OIDC discovery does not advertise S256 PKCE.")
    requireAdvertised(algorithms, "RS256", "Aquari OIDC discovery does not advertise RS256 ID-token signing.")

    return AquariOidcDiscovery(
        issuer = issuer,
        authorizationEndpoint = raw.requiredEndpoint("authorization_endpoint"),
        tokenEndpoint = raw.requiredEndpoint("token_endpoint"),
        userInfoEndpoint = raw.requiredEndpoint("userinfo_endpoint"),
        jwksUri = raw.requiredEndpoint("jwks_uri"),
        grantTypesSupported = grants,
        responseTypesSupported = responses,
        codeChallengeMethodsSupported = pkce,
        idTokenSigningAlgorithmsSupported = algorithms,
        tokenEndpointAuthMethodsSupported = raw.optionalStringList("token_endpoint_auth_methods_supported"),
        authorizationResponseIssuerParameterSupported =
            (raw["authorization_response_iss_parameter_supported"] as? JsonPrimitive)?.booleanOrNull ?: false,
    )
}

private fun JsonObject.requiredString(name: String): String {
    val value = (this[name] as? JsonPrimitive)?.takeIf { it.isString }?.contentOrNull
    if (value.isNullOrEmpty() || value != value.trim()) {
        throw AquariConfigurationException("Aquari OIDC discovery field '$name' must be a non-empty normalized string.")
    }
    return value
}

private fun JsonObject.requiredStringList(name: String): List<String> {
    val value = this[name] as? JsonArray
        ?: throw AquariConfigurationException("Aquari OIDC discovery field '$name' must be a non-empty string array.")
    val items = value.map { element ->
        val item = (element as? JsonPrimitive)?.takeIf { it.isString }?.contentOrNull
        if (item.isNullOrEmpty() || item != item.trim()) {
            throw AquariConfigurationException("Aquari OIDC discovery field '$name' must be a non-empty string array.")
        }
        item
    }
    if (items.isEmpty()) throw AquariConfigurationException("Aquari OIDC discovery field '$name' must be a non-empty string array.")
    return items
}

private fun JsonObject.optionalStringList(name: String): List<String> {
    val value = this[name] ?: return emptyList()
    val array = value as? JsonArray ?: return emptyList()
    return array.mapNotNull { element ->
        (element as? JsonPrimitive)?.takeIf { it.isString }?.contentOrNull?.takeIf { it.isNotEmpty() && it == it.trim() }
    }
}

private fun JsonObject.requiredEndpoint(name: String): String {
    val raw = requiredString(name)
    val uri = try {
        URI(raw)
    } catch (cause: Exception) {
        throw AquariConfigurationException("Aquari OIDC discovery field '$name' must be an absolute URL.", cause)
    }
    if (!uri.isAbsolute) throw AquariConfigurationException("Aquari OIDC discovery field '$name' must be an absolute URL.")
    if (uri.scheme != "https" && !(uri.scheme == "http" && isLocalDevelopmentHost(uri.host))) {
        throw AquariConfigurationException("Aquari OIDC discovery field '$name' must use HTTPS outside local development.")
    }
    if (uri.userInfo != null || uri.fragment != null) {
        throw AquariConfigurationException("Aquari OIDC discovery field '$name' contains unsupported URL components.")
    }
    return uri.toString()
}

private fun requireAdvertised(values: List<String>, required: String, message: String) {
    if (required !in values) throw AquariConfigurationException(message)
}
