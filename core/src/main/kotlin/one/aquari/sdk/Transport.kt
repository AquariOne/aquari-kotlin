package one.aquari.sdk

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.delay
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.longOrNull
import java.net.URI
import java.time.ZonedDateTime
import java.time.Instant
import java.util.Locale
import java.time.temporal.ChronoField
import java.time.format.ResolverStyle
import java.time.format.DateTimeFormatterBuilder
import java.time.ZoneOffset
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter
import kotlin.math.min
import kotlin.random.Random

internal enum class AquariRetryMode { Auto, Never, Idempotent }

internal class AquariHttpTransport(
    private val baseUrl: String,
    private val timeoutMs: Long,
    private val maxRetries: Int,
    private val maxRetryDelayMs: Long,
    private val executor: AquariHttpExecutor,
) {
    internal val json = Json {
        ignoreUnknownKeys = true
    }

    /**
     * Sends an Aquari API request relative to the configured base URL and returns the parsed JSON
     * response.
     */
    suspend fun requestJson(
        path: String,
        method: String = "GET",
        headers: Map<String, String> = emptyMap(),
        body: String? = null,
        contentType: String? = null,
        retryMode: AquariRetryMode = AquariRetryMode.Auto,
    ): JsonElement = requestAbsoluteJson(
        url = resolveUrl(path),
        method = method,
        headers = headers,
        body = body,
        contentType = contentType,
        retryMode = retryMode,
    )

    /**
     * Sends an Aquari API request to an absolute validated URL and returns the parsed JSON response.
     */
    suspend fun requestAbsoluteJson(
        url: String,
        method: String = "GET",
        headers: Map<String, String> = emptyMap(),
        body: String? = null,
        contentType: String? = null,
        retryMode: AquariRetryMode = AquariRetryMode.Auto,
    ): JsonElement {
        val retryable = isRetryableRequest(method, retryMode)
        var attempt = 0

        while (true) {
            try {
                val response = withTimeout(timeoutMs) {
                    executor.execute(
                        AquariRawRequest(
                            method = method,
                            url = url,
                            headers = headers,
                            body = body,
                            contentType = contentType,
                        ),
                    )
                }

                if (response.status in 200..299) {
                    return if (response.body.isBlank()) JsonNull else parseJson(response.body)
                }

                if (retryable && attempt < maxRetries && isRetryableStatus(response.status)) {
                    val delayMs = parseRetryAfterMs(response.headers)
                        ?: jitteredBackoff(attempt)
                    if (delayMs <= maxRetryDelayMs) {
                        delay(delayMs)
                        attempt += 1
                        continue
                    }
                }

                throw classifyApiError(response)
            } catch (error: TimeoutCancellationException) {
                if (retryable && attempt < maxRetries) {
                    val delayMs = jitteredBackoff(attempt)
                    if (delayMs <= maxRetryDelayMs) {
                        delay(delayMs)
                        attempt += 1
                        continue
                    }
                }
                throw AquariTimeoutException(timeoutMs, error)
            } catch (error: CancellationException) {
                throw AquariTransportException("Aquari request was cancelled.", error, cancelled = true)
            } catch (error: AquariApiException) {
                throw error
            } catch (error: AquariException) {
                throw error
            } catch (error: Exception) {
                if (retryable && attempt < maxRetries) {
                    val delayMs = jitteredBackoff(attempt)
                    if (delayMs <= maxRetryDelayMs) {
                        delay(delayMs)
                        attempt += 1
                        continue
                    }
                }
                throw AquariTransportException(
                    "Aquari request failed before a valid API response was received.",
                    error,
                )
            }
        }
    }

    private fun resolveUrl(path: String): String =
        URI(baseUrl).resolve(path).toString()

    private fun parseJson(body: String): JsonElement = try {
        json.parseToJsonElement(body)
    } catch (cause: Exception) {
        throw AquariTransportException("Aquari returned malformed JSON.", cause)
    }

    private fun classifyApiError(response: AquariRawResponse): AquariApiException {
        val root = runCatching { parseJson(response.body).jsonObject }.getOrNull()
        val code = root?.string("code") ?: root?.string("error")
        val message = root?.string("message")
            ?: root?.string("detail")
            ?: "Aquari API request failed with HTTP ${response.status}."
        val requestId = root?.string("requestId") ?: headerFirst(response.headers, "x-request-id")
        val details = root?.detailsMap("details") ?: emptyMap()

        if (response.status == 429) {
            return AquariRateLimitException(
                response.status, code, details, requestId, message,
                parseRetryAfterMs(response.headers),
            )
        }

        if (response.status == 403 && code == "QuotaExceeded") {
            val quota = root?.obj("quota") ?: root
            return AquariQuotaException(
                response.status,
                code,
                details,
                requestId,
                message,
                resource = quota?.string("resource"),
                scopeType = quota?.string("scopeType"),
                scopeId = quota?.string("scopeId"),
                current = quota?.long("current"),
                requested = quota?.long("requested"),
                limit = quota?.long("limit"),
                allowance = quota?.long("allowance"),
                grace = quota?.long("grace"),
                periodFrom = quota?.string("periodFrom"),
                periodTo = quota?.string("periodTo"),
                enforcement = quota?.string("enforcement"),
            )
        }

        return when (response.status) {
            400, 422 -> AquariValidationException(response.status, code, details, requestId, message)
            401 -> AquariAuthenticationException(response.status, code, details, requestId, message)
            403 -> AquariAuthorizationException(response.status, code, details, requestId, message)
            404 -> AquariNotFoundException(response.status, code, details, requestId, message)
            409 -> AquariConflictException(response.status, code, details, requestId, message)
            else -> AquariApiException(response.status, code, details, requestId, message)
        }
    }
}

private fun isRetryableRequest(method: String, mode: AquariRetryMode): Boolean = when (mode) {
    AquariRetryMode.Never -> false
    AquariRetryMode.Idempotent -> true
    AquariRetryMode.Auto -> method in setOf("GET", "HEAD", "OPTIONS")
}

private fun isRetryableStatus(status: Int): Boolean = status in setOf(429, 502, 503, 504)

private fun jitteredBackoff(attempt: Int): Long {
    val base = 250L * (1L shl min(attempt, 8))
    return (base * (0.5 + Random.nextDouble() * 0.5)).toLong()
}

internal fun parseRetryAfterMs(headers: Map<String, List<String>>, nowMillis: Long = System.currentTimeMillis()): Long? {
    val value = headerFirst(headers, "retry-after") ?: return null
    val normalized = value.trim()
    if (Regex("^[0-9]+$").matches(normalized)) {
        val seconds = normalized.toLongOrNull() ?: return Long.MAX_VALUE
        return if (seconds > Long.MAX_VALUE / 1000L) Long.MAX_VALUE else seconds * 1000L
    }
    val currentYear = Instant.ofEpochMilli(nowMillis).atZone(ZoneOffset.UTC).year
    val obsolete = DateTimeFormatterBuilder().parseCaseInsensitive()
        .appendPattern("EEEE, dd-MMM-")
        .appendValueReduced(ChronoField.YEAR, 2, 2, currentYear - 49)
        .appendPattern(" HH:mm:ss zzz")
        .toFormatter(Locale.US).withResolverStyle(ResolverStyle.STRICT)
    val ascii = DateTimeFormatterBuilder().parseCaseInsensitive().appendPattern("EEE MMM d HH:mm:ss uuuu").toFormatter(Locale.US)
        .withResolverStyle(ResolverStyle.STRICT)
    val instant = runCatching {
        ZonedDateTime.parse(normalized, DateTimeFormatter.RFC_1123_DATE_TIME.withResolverStyle(ResolverStyle.STRICT)).toInstant()
    }.getOrNull() ?: runCatching {
        ZonedDateTime.parse(normalized, obsolete).toInstant()
    }.getOrNull() ?: runCatching {
        LocalDateTime.parse(normalized.replace(Regex(" +"), " "), ascii).toInstant(ZoneOffset.UTC)
    }.getOrNull() ?: return null
    return maxOf(0L, instant.toEpochMilli() - nowMillis)
}

private fun headerFirst(headers: Map<String, List<String>>, name: String): String? =
    headers.entries.firstOrNull { it.key.equals(name, ignoreCase = true) }?.value?.firstOrNull()

internal fun JsonObject.string(name: String): String? =
    (this[name] as? JsonPrimitive)?.contentOrNull

internal fun JsonObject.long(name: String): Long? =
    (this[name] as? JsonPrimitive)?.longOrNull

internal fun JsonObject.bool(name: String): Boolean? =
    (this[name] as? JsonPrimitive)?.booleanOrNull

internal fun JsonObject.obj(name: String): JsonObject? = this[name] as? JsonObject
internal fun JsonObject.array(name: String): JsonArray? = this[name] as? JsonArray

private fun JsonObject.detailsMap(name: String): Map<String, List<String>>? {
    val obj = this[name] as? JsonObject ?: return null
    return obj.mapValues { (_, value) ->
        when (value) {
            is JsonArray -> value.mapNotNull { (it as? JsonPrimitive)?.contentOrNull }
            is JsonPrimitive -> listOfNotNull(value.contentOrNull)
            else -> emptyList()
        }
    }
}
