package one.aquari.sdk

/**
 * Reports an Aquari exception.
 */
open class AquariException(message: String, cause: Throwable? = null) : RuntimeException(message, cause)

/**
 * Reports an Aquari configuration exception.
 */
class AquariConfigurationException(message: String, cause: Throwable? = null) :
    AquariException(message, cause)

/**
 * Reports an Aquari transport exception.
 */
open class AquariTransportException(
    message: String,
    cause: Throwable? = null,
    val cancelled: Boolean = false,
) : AquariException(message, cause)

/**
 * Reports an Aquari timeout exception.
 */
class AquariTimeoutException(val timeoutMs: Long, cause: Throwable? = null) :
    AquariTransportException("Aquari request timed out after ${timeoutMs}ms.", cause)

/**
 * Reports an Aquari api exception.
 */
open class AquariApiException(
    val status: Int,
    val code: String?,
    val details: Map<String, List<String>>,
    val requestId: String?,
    message: String,
) : AquariException(message)

/**
 * Reports an Aquari validation exception.
 */
class AquariValidationException(
    status: Int,
    code: String?,
    details: Map<String, List<String>>,
    requestId: String?,
    message: String,
) : AquariApiException(status, code, details, requestId, message)

/**
 * Reports an Aquari authentication exception.
 */
class AquariAuthenticationException(
    status: Int,
    code: String?,
    details: Map<String, List<String>>,
    requestId: String?,
    message: String,
) : AquariApiException(status, code, details, requestId, message)

/**
 * Reports an Aquari authorization exception.
 */
class AquariAuthorizationException(
    status: Int,
    code: String?,
    details: Map<String, List<String>>,
    requestId: String?,
    message: String,
) : AquariApiException(status, code, details, requestId, message)

/**
 * Reports an Aquari not found exception.
 */
class AquariNotFoundException(
    status: Int,
    code: String?,
    details: Map<String, List<String>>,
    requestId: String?,
    message: String,
) : AquariApiException(status, code, details, requestId, message)

/**
 * Reports an Aquari conflict exception.
 */
class AquariConflictException(
    status: Int,
    code: String?,
    details: Map<String, List<String>>,
    requestId: String?,
    message: String,
) : AquariApiException(status, code, details, requestId, message)

/**
 * Reports an Aquari rate limit exception.
 */
class AquariRateLimitException(
    status: Int,
    code: String?,
    details: Map<String, List<String>>,
    requestId: String?,
    message: String,
    val retryAfterMs: Long?,
) : AquariApiException(status, code, details, requestId, message)

/**
 * Reports an Aquari quota exception.
 */
class AquariQuotaException(
    status: Int,
    code: String?,
    details: Map<String, List<String>>,
    requestId: String?,
    message: String,
    val resource: String?,
    val scopeType: String?,
    val scopeId: String?,
    val current: Long?,
    val requested: Long?,
    val limit: Long?,
    val allowance: Long?,
    val grace: Long?,
    val periodFrom: String?,
    val periodTo: String?,
    val enforcement: String?,
) : AquariApiException(status, code, details, requestId, message)

/**
 * Reports an Aquari oauth exception.
 */
class AquariOAuthException(
    val oauthCode: String,
    message: String,
    val errorDescription: String? = null,
    val errorUri: String? = null,
    cause: Throwable? = null,
) : AquariException(message, cause)
