package one.aquari.sdk

import kotlinx.coroutines.suspendCancellableCoroutine
import okhttp3.Call
import okhttp3.Callback
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import java.io.IOException
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * Represents one low-level HTTP request before the Aquari transport sends it.
 */
data class AquariRawRequest(
    val method: String,
    val url: String,
    val headers: Map<String, String> = emptyMap(),
    val body: String? = null,
    val contentType: String? = null,
)

/**
 * Represents one low-level HTTP response returned to the Aquari transport.
 */
data class AquariRawResponse(
    val status: Int,
    val headers: Map<String, List<String>>,
    val body: String,
)

/**
 * Defines the low-level HTTP execution boundary used by the Kotlin Aquari transport.
 */
fun interface AquariHttpExecutor {
    /**
     * Executes one low-level HTTP request for the Aquari transport and returns the raw response.
     */
    suspend fun execute(request: AquariRawRequest): AquariRawResponse
}

/**
 * Executes low-level Aquari HTTP requests with OkHttp and coroutine cancellation.
 */
class OkHttpAquariExecutor private constructor(
    private val client: OkHttpClient,
) : AquariHttpExecutor {
    constructor() : this(OkHttpClient())
    /**
     * Executes one low-level HTTP request for the Aquari transport and returns the raw response.
     */
    override suspend fun execute(request: AquariRawRequest): AquariRawResponse {
        val builder = Request.Builder().url(request.url)
        request.headers.forEach(builder::addHeader)

        val requestBody = request.body?.toRequestBody(
            request.contentType?.toMediaType(),
        )

        builder.method(request.method, requestBody)
        val call = client.newCall(builder.build())

        return call.awaitResponse()
    }
}

private suspend fun Call.awaitResponse(): AquariRawResponse =
    suspendCancellableCoroutine { continuation ->
        continuation.invokeOnCancellation { cancel() }
        enqueue(object : Callback {
            override fun onFailure(call: Call, e: IOException) {
                if (continuation.isActive) continuation.resumeWithException(e)
            }

            override fun onResponse(call: Call, response: Response) {
                response.use {
                    if (continuation.isActive) {
                        continuation.resume(
                            AquariRawResponse(
                                status = response.code,
                                headers = response.headers.toMultimap(),
                                body = response.body.string(),
                            ),
                        )
                    }
                }
            }
        })
    }
