package one.aquari.sdk

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import java.time.Instant

class RetryAfterTest {
    @Test
    fun `seconds never overflow and malformed values are absent`() {
        assertEquals(12000L, parseRetryAfterMs(mapOf("Retry-After" to listOf("12"))))
        assertEquals(0L, parseRetryAfterMs(mapOf("Retry-After" to listOf("0"))))
        assertEquals(Long.MAX_VALUE, parseRetryAfterMs(mapOf("Retry-After" to listOf("9223372036854775807"))))
        for (value in listOf("-1", "+1", "0x10", "1.5", "", "not-a-date")) {
            assertNull(parseRetryAfterMs(mapOf("Retry-After" to listOf(value))))
        }
        val now = Instant.parse("2026-10-05T00:00:00Z").toEpochMilli()
        for (value in listOf("mon, 05 oct 2026 00:00:12 gmt", "Mon, 05 Oct 2026 00:00:12 GMT", "Monday, 05-Oct-26 00:00:12 GMT", "Mon Oct  5 00:00:12 2026")) {
            assertEquals(12000L, parseRetryAfterMs(mapOf("Retry-After" to listOf(value)), now))
        }
        assertEquals(Long.MAX_VALUE, parseRetryAfterMs(mapOf("Retry-After" to listOf("9".repeat(400)))))
    }
}
